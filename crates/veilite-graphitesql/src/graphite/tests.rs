use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const SQLCIPHER3_PASSPHRASE: &[u8] = b"veilite-sqlcipher3-test-key";
const SQLCIPHER4_PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";

#[derive(Clone, Copy)]
struct FixtureCase {
    name: &'static str,
    profile: CompatibilityProfile,
    passphrase: &'static [u8],
}

const FIXTURE_CASES: [FixtureCase; 2] = [
    FixtureCase {
        name: "sqlcipher3",
        profile: CompatibilityProfile::SqlCipher3,
        passphrase: SQLCIPHER3_PASSPHRASE,
    },
    FixtureCase {
        name: "sqlcipher4",
        profile: CompatibilityProfile::SqlCipher4,
        passphrase: SQLCIPHER4_PASSPHRASE,
    },
];

impl FixtureCase {
    fn path(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(self.name)
            .join("encrypted.db")
    }
}

#[test]
fn queries_supported_fixtures() {
    for case in FIXTURE_CASES {
        let connection = open_readonly(case.path(), case.profile, case.passphrase)
            .unwrap_or_else(|error| panic!("{} failed to open: {error}", case.name));

        let people = connection
            .query("SELECT id, name, note, score, active FROM people ORDER BY id")
            .unwrap_or_else(|error| panic!("{} people query failed: {error}", case.name));
        assert_eq!(people.columns, ["id", "name", "note", "score", "active"]);
        assert_eq!(
            people.rows,
            [
                vec![
                    Value::Integer(1),
                    Value::Text(b"Alice".to_vec()),
                    Value::Text(b"plain ASCII".to_vec()),
                    Value::Real(98.5),
                    Value::Integer(1),
                ],
                vec![
                    Value::Integer(2),
                    Value::Text("홍길동".as_bytes().to_vec()),
                    Value::Text("한국어, emoji 🔐, and 'quotes'".as_bytes().to_vec()),
                    Value::Real(-12.25),
                    Value::Integer(1),
                ],
                vec![
                    Value::Integer(3),
                    Value::Text(b"Null Tester".to_vec()),
                    Value::Null,
                    Value::Real(0.0),
                    Value::Integer(0),
                ],
            ],
            "{}",
            case.name
        );

        let binary_samples = connection
            .query("SELECT name, payload FROM binary_samples ORDER BY name")
            .unwrap_or_else(|error| panic!("{} blob query failed: {error}", case.name));
        assert_eq!(
            binary_samples.rows,
            [
                vec![
                    Value::Text(b"all-byte-edges".to_vec()),
                    Value::Blob(vec![
                        0x00, 0x01, 0x02, 0x03, 0x7f, 0x80, 0xfc, 0xfd, 0xfe, 0xff
                    ]),
                ],
                vec![
                    Value::Text(b"large-zero-blob".to_vec()),
                    Value::Blob(vec![0; 10_000]),
                ],
            ],
            "{}",
            case.name
        );
    }
}

#[test]
fn connection_rejects_writes() {
    let case = FIXTURE_CASES[1];
    let connection = open_readonly(case.path(), case.profile, case.passphrase).unwrap();

    let error = connection
        .query("UPDATE people SET name = 'Mallory' WHERE id = 1")
        .unwrap_err();
    assert!(matches!(error, GraphiteAdapterError::Query { .. }));
}

#[test]
fn file_adapter_is_strictly_read_only() {
    let case = FIXTURE_CASES[1];
    let path = case.path();
    let path_str = path.to_str().unwrap();
    let vfs = SqlCipherVfs::new(&path, case.profile, case.passphrase).unwrap();
    let mut file = Vfs::open(&vfs, path_str, OpenFlags::READ_ONLY).unwrap();
    let wal_path = companion_path_string(path_str, WAL_SUFFIX);

    assert!(Vfs::exists(&vfs, path_str).unwrap());
    assert!(!Vfs::exists(&vfs, &wal_path).unwrap());
    assert_eq!(file.size().unwrap(), fs::metadata(&path).unwrap().len());
    assert!(file.sync().is_ok());
    assert!(matches!(
        file.write_all_at(b"no", 0),
        Err(GraphiteError::Error(message)) if message == READ_ONLY_ERROR
    ));
    assert!(matches!(
        file.truncate(0),
        Err(GraphiteError::Error(message)) if message == READ_ONLY_ERROR
    ));
    assert!(matches!(
        Vfs::delete(&vfs, path_str),
        Err(GraphiteError::Error(message)) if message == READ_ONLY_ERROR
    ));
    assert!(matches!(
        Vfs::open(&vfs, path_str, OpenFlags::READ_WRITE),
        Err(GraphiteError::Error(message)) if message == READ_ONLY_ERROR
    ));
}

#[test]
fn rejects_companion_files_before_opening_the_database() {
    let directory = TemporaryDirectory::new();
    let database_path = directory.path().join("encrypted.db");
    let wal_path = companion_path(&database_path, WAL_SUFFIX);
    let journal_path = companion_path(&database_path, JOURNAL_SUFFIX);

    File::create(&wal_path).unwrap();
    assert!(matches!(
        open_readonly(
            &database_path,
            CompatibilityProfile::SqlCipher4,
            SQLCIPHER4_PASSPHRASE,
        ),
        Err(GraphiteAdapterError::Companion(CompanionError::UnsupportedWal { path }))
            if path == wal_path
    ));

    fs::remove_file(&wal_path).unwrap();
    File::create(&journal_path).unwrap();
    assert!(matches!(
        open_readonly(
            &database_path,
            CompatibilityProfile::SqlCipher4,
            SQLCIPHER4_PASSPHRASE,
        ),
        Err(GraphiteAdapterError::Companion(CompanionError::UnsupportedJournal { path }))
            if path == journal_path
    ));
}

static NEXT_TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Self {
        let id = NEXT_TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "veilite-graphite-tests-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
