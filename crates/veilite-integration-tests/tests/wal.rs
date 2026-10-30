#[path = "common/cipher.rs"]
mod cipher;
#[path = "common/cli.rs"]
mod cli_support;
#[path = "common/files.rs"]
mod files;

use cipher::FixtureCipher;
use std::{fs, io, num::NonZeroU32, path::PathBuf, sync::Arc};
use veilite_core::{CipherConfig, SliceSource, SqlCipherReader};
use veilite_turso::{
    OpenError, open_readonly, open_readonly_with_wal,
    snapshot::{VisitError, WalInput},
    turso,
};

#[derive(Clone, Copy)]
struct Case {
    profile: &'static str,
    cipher: FixtureCipher,
    main: &'static [u8],
    history: &'static [u8],
    shrink: &'static [u8],
    expected: &'static [u8],
    shrunk: &'static [u8],
}

macro_rules! case {
    ($profile:literal, $cipher:ident) => {
        Case {
            profile: $profile,
            cipher: FixtureCipher::$cipher,
            main: include_bytes!(concat!("fixtures/wal/", $profile, "/main.db")),
            history: include_bytes!(concat!("fixtures/wal/", $profile, "/history.wal")),
            shrink: include_bytes!(concat!("fixtures/wal/", $profile, "/shrink.wal")),
            expected: include_bytes!(concat!("fixtures/wal/", $profile, "/expected.db")),
            shrunk: include_bytes!(concat!("fixtures/wal/", $profile, "/shrunk.db")),
        }
    };
}
const CASES: [Case; 3] = [
    case!("3", SqlCipher3),
    case!("4", SqlCipher4),
    case!("custom", Custom),
];
const KEY: &[u8] = b"wal-fixture";

impl Case {
    fn config(self) -> CipherConfig {
        self.cipher.config()
    }

    fn commit_ends(self) -> Vec<usize> {
        let size = self.config().page_size() + 24;
        (32..self.history.len())
            .step_by(size)
            .filter(|&offset| be32(self.history, offset + 4) != 0)
            .map(|offset| offset + size)
            .collect()
    }
}

struct Input {
    dir: tempfile::TempDir,
    db: PathBuf,
    wal: PathBuf,
}

impl Input {
    fn new(case: Case, wal: &[u8]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("input.db");
        let wal_path = dir.path().join("input.db-wal");
        fs::write(&db, case.main).unwrap();
        fs::write(&wal_path, wal).unwrap();
        Self {
            dir,
            db,
            wal: wal_path,
        }
    }
    fn preserved(&self, case: Case, wal: &[u8]) {
        files::assert_preserved(&self.db, case.main, Some(wal));
    }

    fn cli(&self, case: Case, command: &str) -> std::process::Output {
        let key = self.dir.path().join("key");
        fs::write(&key, KEY).unwrap();
        let mut cli = std::process::Command::new(env!("CARGO_BIN_EXE_veilite-test-cli"));
        cli.arg(command)
            .args(case.cipher.cli_options())
            .arg("--wal")
            .arg("--passphrase-file")
            .arg(key)
            .arg(&self.db);
        if command == "export" {
            cli.arg(self.dir.path().join("output.db"));
        }
        cli.stdin(std::process::Stdio::null()).output().unwrap()
    }
}

#[track_caller]
fn scalar(conn: &Arc<turso::Connection>, sql: &str) -> i64 {
    let mut result = None;
    conn.prepare(sql)
        .unwrap_or_else(|error| panic!("{sql}: prepare failed: {error}"))
        .run_with_row_callback(|row| {
            assert!(
                result.is_none(),
                "{sql}: expected exactly one row, got multiple"
            );
            assert_eq!(row.len(), 1, "{sql}: expected exactly one column");
            result = Some(row.get::<i64>(0)?);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{sql}: query failed: {error}"));
    result.unwrap_or_else(|| panic!("{sql}: expected exactly one row, got none"))
}

fn reference(case: Case, encrypted: &[u8]) -> Vec<u8> {
    let reader = SqlCipherReader::open(SliceSource::new(encrypted), case.config(), KEY).unwrap();
    let mut image = vec![0; encrypted.len()];
    for (index, page) in image
        .chunks_exact_mut(case.config().page_size())
        .enumerate()
    {
        reader
            .read_page_into(
                NonZeroU32::new(u32::try_from(index + 1).unwrap()).unwrap(),
                page,
            )
            .unwrap();
    }
    image
}

fn be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

// Test-only mutation helper: preserve the WAL checksum chain so HMAC failures
// cannot be mistaken for a recovery tail that the engine is allowed to ignore.
fn repair_checksums(wal: &mut [u8], page_size: usize) {
    let little = be32(wal, 0) == 0x377f0682;
    let (mut a, mut b) = (be32(wal, 24), be32(wal, 28));
    for offset in (32..wal.len()).step_by(page_size + 24) {
        let body: Vec<_> = wal[offset..offset + 8]
            .iter()
            .chain(&wal[offset + 24..offset + 24 + page_size])
            .copied()
            .collect();
        for pair in body.as_chunks::<8>().0 {
            let decode = |x: &[u8]| {
                if little {
                    u32::from_le_bytes(x.try_into().unwrap())
                } else {
                    u32::from_be_bytes(x.try_into().unwrap())
                }
            };
            a = a.wrapping_add(decode(&pair[..4])).wrapping_add(b);
            b = b.wrapping_add(decode(&pair[4..])).wrapping_add(a);
        }
        wal[offset + 16..offset + 20].copy_from_slice(&a.to_be_bytes());
        wal[offset + 20..offset + 24].copy_from_slice(&b.to_be_bytes());
    }
}

fn damaged_payload(case: Case, page: u32) -> Vec<u8> {
    let end = *case.commit_ends().last().unwrap();
    let mut wal = case.history[..end].to_vec();
    let offset = (32..end)
        .step_by(case.config().page_size() + 24)
        .rfind(|&offset| be32(&wal, offset) == page)
        .unwrap();
    wal[offset + 24 + 30] ^= 1;
    repair_checksums(&mut wal, case.config().page_size());
    wal
}

#[test]
fn queries_and_traverses_reference_snapshots_including_growth_and_shrink() {
    for case in CASES {
        for (wal, expected, count, version) in [
            (case.history, case.expected, 9, 2),
            (case.shrink, case.shrunk, 3, 3),
        ] {
            let input = Input::new(case, wal);
            assert!(matches!(
                open_readonly(&input.db, case.config(), KEY),
                Err(OpenError::Companion(_))
            ));
            let conn = open_readonly_with_wal(&input.db, case.config(), KEY).unwrap();
            assert_eq!(scalar(&conn, "SELECT count(*) FROM items"), count);
            assert_eq!(scalar(&conn, "PRAGMA user_version"), version);
            let mut rows = Vec::new();
            conn.prepare("SELECT id,payload FROM items ORDER BY id")
                .unwrap()
                .run_with_row_callback(|row| {
                    let id = row.get::<i64>(0)?;
                    let turso::Value::Blob(blob) = row.get_value(1) else {
                        panic!("blob expected")
                    };
                    rows.push((id, blob.to_vec()));
                    Ok(())
                })
                .unwrap();
            let expected_rows: Vec<_> = (0..count)
                .map(|id| {
                    (
                        id,
                        match id {
                            0 => b"base".to_vec(),
                            1 => b"changed".to_vec(),
                            _ => vec![0; 1024],
                        },
                    )
                })
                .collect();
            assert_eq!(rows, expected_rows);
            conn.set_query_only(false);
            assert!(conn.execute("DELETE FROM items").is_err());

            let snapshot = WalInput::open(&input.db)
                .unwrap()
                .snapshot(case.config(), KEY)
                .unwrap();
            assert_eq!(
                snapshot.page_count() as usize * snapshot.page_size(),
                expected.len()
            );
            let mut image = Vec::new();
            let mut next = 1;
            snapshot
                .visit_pages(|number, page| {
                    assert_eq!(number.get(), next);
                    next += 1;
                    image.extend_from_slice(page);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                image,
                reference(case, expected),
                "{} version {version}",
                case.profile
            );
            drop(conn);
            input.preserved(case, wal);
        }
    }
}

#[test]
fn uses_last_valid_commit_for_uncommitted_truncated_and_checksum_invalid_tails() {
    for case in CASES {
        let commits = case.commit_ends();
        assert_eq!(commits.len(), 2, "{}: commit count", case.profile);
        let end = commits[1];
        assert!(
            case.history.len() > end,
            "{}: missing uncommitted tail",
            case.profile
        );
        let mut checksum = case.history[..end].to_vec();
        checksum[end - case.config().page_size() - 24 + 16] ^= 1;
        for (scenario, wal, count, version) in [
            ("committed", &case.history[..end], 9, 2),
            ("truncated frame", &case.history[..end - 11], 13, 1),
            ("invalid checksum", checksum.as_slice(), 13, 1),
            ("truncated header", &case.history[..16], 1, 0),
            ("empty WAL", &[][..], 1, 0),
        ] {
            let context = format!("{}: {scenario}", case.profile);
            let input = Input::new(case, wal);
            let conn = open_readonly_with_wal(&input.db, case.config(), KEY)
                .unwrap_or_else(|error| panic!("{context}: open: {error}"));
            assert_eq!(
                scalar(&conn, "SELECT count(*) FROM items"),
                count,
                "{context}: row count"
            );
            assert_eq!(
                scalar(&conn, "PRAGMA user_version"),
                version,
                "{context}: user version"
            );
            WalInput::open(&input.db)
                .unwrap_or_else(|error| panic!("{context}: WAL input: {error}"))
                .snapshot(case.config(), KEY)
                .unwrap_or_else(|error| panic!("{context}: snapshot: {error}"))
                .visit_pages(|_, _| Ok(()))
                .unwrap_or_else(|error| panic!("{context}: page traversal: {error}"));
            drop(conn);
            input.preserved(case, wal);
        }
    }
}

#[test]
fn authenticates_each_open_and_never_falls_back_after_wal_page_authentication_failure() {
    for case in CASES {
        let input = Input::new(case, case.history);
        let conn = open_readonly_with_wal(&input.db, case.config(), KEY).unwrap();
        assert!(matches!(
            open_readonly_with_wal(&input.db, case.config(), b"wrong"),
            Err(OpenError::Decrypt(_))
        ));
        assert!(matches!(
            WalInput::open(&input.db)
                .unwrap()
                .snapshot(case.config(), b"wrong"),
            Err(OpenError::Decrypt(_))
        ));
        drop(conn);
        let wal = damaged_payload(case, 1);
        let damaged = Input::new(case, &wal);
        assert!(open_readonly_with_wal(&damaged.db, case.config(), KEY).is_err());
        assert!(
            WalInput::open(&damaged.db)
                .unwrap()
                .snapshot(case.config(), KEY)
                .is_err()
        );
        damaged.preserved(case, &wal);
    }
}

#[test]
fn callback_and_short_read_failures_stop_page_delivery() {
    let case = CASES[0];
    let input = Input::new(case, case.history);
    let snapshot = WalInput::open(&input.db)
        .unwrap()
        .snapshot(case.config(), KEY)
        .unwrap();
    let mut calls = 0;
    let result = snapshot.visit_pages(|_, _| {
        calls += 1;
        Err(io::Error::other("consumer stopped"))
    });
    assert!(matches!(result, Err(VisitError::Callback(_))));
    assert_eq!(calls, 1);
    input.preserved(case, case.history);
    let snapshot = WalInput::open(&input.db)
        .unwrap()
        .snapshot(case.config(), KEY)
        .unwrap();
    // Deliberately violate the immutable-input contract to exercise a late I/O
    // failure. The uncached visitor must never deliver an empty/partial page.
    fs::OpenOptions::new()
        .write(true)
        .open(&input.wal)
        .unwrap()
        .set_len(0)
        .unwrap();
    calls = 0;
    let result = snapshot.visit_pages(|_, _| {
        calls += 1;
        Ok(())
    });
    assert!(matches!(result, Err(VisitError::Read(_))));
    assert_eq!(calls, 0);
}

#[test]
fn wal_cli_verifies_and_exports_the_same_selected_image() {
    for case in CASES {
        for (wal, expected) in [(case.history, case.expected), (case.shrink, case.shrunk)] {
            let input = Input::new(case, wal);
            for command in ["verify", "export"] {
                let output = input.cli(case, command);
                assert!(output.status.success(), "{output:?}");
                let pages = expected.len() / case.config().page_size();
                let expected_stdout = if command == "verify" {
                    format!("verified {pages} snapshot pages\n")
                } else {
                    format!(
                        "decrypted {pages} snapshot pages to {}\n",
                        input.dir.path().join("output.db").display()
                    )
                };
                assert_eq!(
                    output.stdout,
                    expected_stdout.as_bytes(),
                    "{}: {command}, expected {pages} snapshot pages",
                    case.profile
                );
                assert!(output.stderr.is_empty(), "{output:?}");
            }
            let mut expected = reference(case, expected);
            expected[18] = 1;
            expected[19] = 1;
            assert_eq!(
                fs::read(input.dir.path().join("output.db")).unwrap(),
                expected
            );
            let again = input.cli(case, "export");
            assert_eq!(again.status.code(), Some(1));
            assert_eq!(
                fs::read(input.dir.path().join("output.db")).unwrap(),
                expected
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(input.dir.path().join("output.db"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o077,
                    0
                );
            }
            input.preserved(case, wal);
        }
    }
}

#[test]
fn wal_cli_rejects_unused_page_corruption_and_removes_partial_export() {
    for case in CASES {
        let last = u32::try_from(case.expected.len() / case.config().page_size()).unwrap();
        let wal = damaged_payload(case, last);
        let input = Input::new(case, &wal);
        let conn = open_readonly_with_wal(&input.db, case.config(), KEY).unwrap();
        assert_eq!(scalar(&conn, "SELECT count(*) FROM items"), 9);
        drop(conn);
        for command in ["verify", "export"] {
            let output = input.cli(case, command);
            let context = format!("{}: {command}, damaged page {last}", case.profile);
            assert_eq!(output.status.code(), Some(1), "{context}: {output:?}");
            assert!(output.stdout.is_empty(), "{context}: {output:?}");
            let stderr = std::str::from_utf8(&output.stderr)
                .unwrap_or_else(|error| panic!("{context}: invalid stderr: {error}"));
            // Turso reports page authentication failures as PageCodecError,
            // without preserving the underlying DecryptError text.
            let expected_error = format!("Page codec failed for page={last}");
            assert!(
                stderr.lines().any(|line| line.ends_with(&expected_error)),
                "{context}: {stderr}"
            );
            assert!(
                !input.dir.path().join("output.db").exists(),
                "{context}: partial export remains"
            );
        }
        input.preserved(case, &wal);
    }
}

#[test]
fn preflight_requires_regular_wal_and_rejects_journals() {
    let case = CASES[0];
    let input = Input::new(case, case.history);
    fs::remove_file(&input.wal).unwrap();
    assert!(WalInput::open(&input.db).is_err());
    fs::create_dir(&input.wal).unwrap();
    assert!(matches!(
        WalInput::open(&input.db),
        Err(OpenError::WalInput(_))
    ));
    fs::remove_dir(&input.wal).unwrap();
    fs::write(&input.wal, case.history).unwrap();
    let journal = input.dir.path().join("input.db-journal");
    fs::write(&journal, []).unwrap();
    assert!(matches!(
        WalInput::open(&input.db),
        Err(OpenError::Companion(_))
    ));
}

#[test]
fn selected_image_cannot_exceed_all_available_physical_pages() {
    for case in CASES {
        let input = Input::new(case, &[]);
        let page_size = case.config().page_size();
        // The final page is free in this fixture, so schema opening succeeds.
        // The authenticated header still requires that page in a full traversal.
        fs::write(&input.db, &case.expected[..case.expected.len() - page_size]).unwrap();
        assert!(matches!(
            WalInput::open(&input.db)
                .unwrap()
                .snapshot(case.config(), KEY),
            Err(OpenError::SnapshotSize { .. })
        ));
    }
}

#[cfg(unix)]
#[test]
fn symlink_companions_cannot_select_a_different_wal() {
    use std::os::unix::fs::symlink;
    let case = CASES[0];
    let input = Input::new(case, case.history);
    let alias = input.dir.path().join("alias.db");
    let alias_wal = input.dir.path().join("alias.db-wal");
    symlink(&input.db, &alias).unwrap();
    assert!(WalInput::open(&alias).is_ok());
    fs::write(&alias_wal, case.shrink).unwrap();
    assert!(matches!(
        WalInput::open(&alias),
        Err(OpenError::WalInput(_))
    ));
    fs::remove_file(&alias_wal).unwrap();
    symlink(&input.wal, &alias_wal).unwrap();
    assert!(WalInput::open(&alias).is_ok());
    fs::remove_file(&alias_wal).unwrap();
    symlink(input.dir.path().join("absent"), &alias_wal).unwrap();
    assert!(WalInput::open(&alias).is_err());
    fs::remove_file(&alias_wal).unwrap();
    for name in ["alias.db-journal", "input.db-journal"] {
        let journal = input.dir.path().join(name);
        symlink(input.dir.path().join("absent"), &journal).unwrap();
        assert!(matches!(
            WalInput::open(&alias),
            Err(OpenError::Companion(_))
        ));
        fs::remove_file(journal).unwrap();
    }
}

#[test]
fn hardlinked_main_files_with_different_wal_paths_do_not_share_cached_state() {
    let case = CASES[0];
    let input = Input::new(case, case.history);
    let alias = input.dir.path().join("hardlink.db");
    fs::hard_link(&input.db, &alias).unwrap();
    fs::write(input.dir.path().join("hardlink.db-wal"), case.shrink).unwrap();
    let conn = open_readonly_with_wal(&input.db, case.config(), KEY).unwrap();
    // Depending on the platform's registry identity, the second open either
    // rejects incompatible codec identity or opens its own correctly selected WAL.
    match open_readonly_with_wal(&alias, case.config(), KEY) {
        Ok(other) => assert_eq!(scalar(&other, "PRAGMA user_version"), 3),
        Err(OpenError::Turso(turso::LimboError::InvalidArgument(message)))
            if message == "page codec identity does not match the existing database" => {}
        Err(error) => panic!("unexpected hardlink open failure: {error}"),
    }
    assert_eq!(scalar(&conn, "PRAGMA user_version"), 2);
}
