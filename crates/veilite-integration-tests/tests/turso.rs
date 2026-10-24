mod common;

use common::{FIXTURE_CASES, SQLCIPHER3_CASE};
use std::{num::NonZeroUsize, path::Path, sync::Arc};
use veilite_core::DecryptError;
use veilite_turso::{OpenError, open_readonly, turso};

fn strings(conn: &Arc<turso::Connection>, sql: &str) -> turso::Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    conn.prepare(sql)?.run_with_row_callback(|row| {
        rows.push(
            (0..row.len())
                .map(|i| row.get::<String>(i))
                .collect::<turso::Result<Vec<_>>>()?,
        );
        Ok(())
    })?;
    Ok(rows)
}

fn unchanged(path: &Path, bytes: &[u8]) {
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    for suffix in ["-wal", "-journal", "-shm"] {
        assert!(!Path::new(&format!("{}{suffix}", path.display())).exists());
    }
}

#[test]
fn queries_presets_and_custom_with_bindings_indexes_and_overflow() {
    for case in FIXTURE_CASES {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted.db");
        std::fs::write(&path, case.encrypted).unwrap();
        let conn = open_readonly(&path, case.config(), case.passphrase)
            .unwrap_or_else(|error| panic!("{} failed to open: {error}", case.name));
        assert_eq!(strings(&conn,
            "SELECT CAST(id AS TEXT),name,coalesce(note,'NULL'),CAST(score AS TEXT),CAST(active AS TEXT) FROM people ORDER BY id").unwrap(),
            vec![vec!["1","Alice","plain ASCII","98.5","1"], vec!["2","홍길동","한국어, emoji 🔐, and 'quotes'","-12.25","1"], vec!["3","Null Tester","NULL","0.0","0"]]);
        let mut statement = conn
            .prepare("SELECT id FROM people INDEXED BY people_name_idx WHERE name=?1")
            .unwrap();
        statement
            .bind_at(NonZeroUsize::MIN, turso::Value::Text("홍길동".into()))
            .unwrap();
        let mut ids = Vec::new();
        statement
            .run_with_row_callback(|row| {
                ids.push(row.get::<i64>(0)?);
                Ok(())
            })
            .unwrap();
        assert_eq!(ids, [2]);
        statement.reset().unwrap();
        statement
            .bind_at(NonZeroUsize::MIN, turso::Value::Text("absent".into()))
            .unwrap();
        statement
            .run_with_row_callback(|_| panic!("missing key returned a row"))
            .unwrap();
        assert_eq!(
            strings(
                &conn,
                "SELECT CAST(count(*) AS TEXT) FROM people p JOIN audit_log a ON a.person_id=p.id"
            )
            .unwrap(),
            vec![vec!["3"]]
        );

        let pattern = (0..2000).map(|i| format!("{i:04}:")).collect::<String>();
        let mut blobs = Vec::new();
        conn.prepare("SELECT payload FROM binary_samples ORDER BY name")
            .unwrap()
            .run_with_row_callback(|row| {
                let turso::Value::Blob(blob) = row.get_value(0) else {
                    panic!("expected BLOB")
                };
                blobs.push(blob.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            blobs,
            vec![
                vec![0, 1, 2, 3, 127, 128, 252, 253, 254, 255],
                pattern.into_bytes()
            ]
        );
        conn.prepare("SELECT note, score, active FROM people WHERE id=3")
            .unwrap()
            .run_with_row_callback(|row| {
                assert!(matches!(row.get_value(0), turso::Value::Null));
                assert!(matches!(
                    row.get_value(1),
                    turso::Value::Numeric(turso::Numeric::Float(_))
                ));
                assert!(matches!(
                    row.get_value(2),
                    turso::Value::Numeric(turso::Numeric::Integer(0))
                ));
                Ok(())
            })
            .unwrap();

        assert!(conn.prepare_execute_batch("DELETE FROM people").is_err());
        // The main file remains protected even if trusted callers disable the
        // connection-level query_only convenience setting.
        conn.set_query_only(false);
        assert!(
            conn.prepare_execute_batch("CREATE TABLE forbidden(x)")
                .is_err()
        );
        drop(statement);
        drop(conn);
        unchanged(&path, case.encrypted);
    }
}

#[test]
fn authenticates_every_open_even_with_a_warm_database() {
    for case in FIXTURE_CASES {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted.db");
        std::fs::write(&path, case.encrypted).unwrap();
        let first = open_readonly(&path, case.config(), case.passphrase).unwrap();
        strings(&first, "SELECT name FROM people").unwrap();
        let error = open_readonly(&path, case.config(), b"wrong").err().unwrap();
        assert!(matches!(
            error,
            OpenError::Decrypt(DecryptError::AuthenticationFailed { page_no: 1 })
        ));
        let second = open_readonly(&path, case.config(), case.passphrase).unwrap();
        assert_eq!(
            strings(&first, "SELECT name FROM people ORDER BY id").unwrap(),
            strings(&second, "SELECT name FROM people ORDER BY id").unwrap()
        );
        let wrong_config = veilite_core::CipherConfig::new(
            case.page_size,
            1,
            veilite_core::HashAlgorithm::Sha256,
            veilite_core::HashAlgorithm::Sha256,
        )
        .unwrap();
        assert!(open_readonly(&path, wrong_config, case.passphrase).is_err());
        drop(first);
        drop(second);
        unchanged(&path, case.encrypted);
    }
}

#[test]
fn rejects_corrupt_index_and_overflow_without_returning_the_damaged_row() {
    for case in FIXTURE_CASES {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean.db");
        std::fs::write(&clean, case.encrypted).unwrap();
        let conn = open_readonly(&clean, case.config(), case.passphrase).unwrap();
        let index_page: usize = strings(
            &conn,
            "SELECT CAST(rootpage AS TEXT) FROM sqlite_schema WHERE name='people_name_idx'",
        )
        .unwrap()[0][0]
            .parse()
            .unwrap();
        let last_page = case.encrypted.len() / case.page_size;
        for page in [index_page, last_page] {
            let mut bytes = case.encrypted.to_vec();
            bytes[(page - 1) * case.page_size + 16] ^= 1;
            let path = dir.path().join(format!("corrupt-{page}.db"));
            std::fs::write(&path, &bytes).unwrap();
            let conn = open_readonly(&path, case.config(), case.passphrase).unwrap();
            let sql = if page == index_page {
                "SELECT name FROM people INDEXED BY people_name_idx ORDER BY name"
            } else {
                "SELECT payload FROM binary_samples WHERE name='large-pattern-blob'"
            };
            let mut returned = 0;
            let error = conn
                .prepare(sql)
                .unwrap()
                .run_with_row_callback(|_| {
                    returned += 1;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(returned, 0);
            assert!(
                matches!(error, turso::LimboError::CompletionError(turso::CompletionError::PageCodecError { page_idx }) if page_idx == page),
                "{error:?}"
            );
            drop(conn);
            unchanged(&path, &bytes);
        }
    }
}

#[test]
fn refuses_companions_invalid_lengths_and_missing_files() {
    let case = SQLCIPHER3_CASE;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.db");
    assert!(open_readonly(&path, case.config(), case.passphrase).is_err());
    assert!(!path.exists());
    for bytes in [
        &[][..],
        &case.encrypted[..15],
        &case.encrypted[..case.encrypted.len() - 1],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            open_readonly(&path, case.config(), case.passphrase),
            Err(OpenError::Source(_))
        ));
        unchanged(&path, bytes);
    }
    std::fs::write(&path, case.encrypted).unwrap();
    for suffix in ["-wal", "-journal"] {
        let companion = dir.path().join(format!("encrypted.db{suffix}"));
        std::fs::write(&companion, b"companion sentinel").unwrap();
        assert!(matches!(
            open_readonly(&path, case.config(), case.passphrase),
            Err(OpenError::Companion(_))
        ));
        assert_eq!(std::fs::read(&companion).unwrap(), b"companion sentinel");
        std::fs::remove_file(companion).unwrap();
    }
    assert!(matches!(
        open_readonly(&path, case.config(), b""),
        Err(OpenError::Decrypt(DecryptError::EmptyPassphrase))
    ));
    unchanged(&path, case.encrypted);
}

#[cfg(unix)]
#[test]
fn checks_companions_of_symlink_targets_and_dangling_companions() {
    use std::os::unix::fs::symlink;
    let case = SQLCIPHER3_CASE;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.db");
    let alias = dir.path().join("alias.db");
    std::fs::write(&target, case.encrypted).unwrap();
    symlink(&target, &alias).unwrap();
    symlink(dir.path().join("missing"), dir.path().join("target.db-wal")).unwrap();
    assert!(matches!(
        open_readonly(&alias, case.config(), case.passphrase),
        Err(OpenError::Companion(_))
    ));
}

#[test]
fn restores_logical_rows_against_reference_engine_expectations() {
    let bytes = include_bytes!("fixtures/turso/rows.db");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rows.db");
    std::fs::write(&path, bytes).unwrap();
    let conn = open_readonly(&path, SQLCIPHER3_CASE.config(), b"veilite-turso-fixture").unwrap();
    for (sql, expected) in [
        (
            "SELECT CAST(a IS NULL AS TEXT),b FROM nullable",
            vec![vec!["1", "x"]],
        ),
        (
            "SELECT label,CAST(id AS TEXT) FROM alias_later",
            vec![vec!["x", "42"]],
        ),
        (
            "SELECT a,CAST(b AS TEXT) FROM defaults",
            vec![vec!["x", "7"]],
        ),
        ("SELECT a,b FROM reordered", vec![vec!["A", "B"]]),
    ] {
        assert_eq!(strings(&conn, sql).unwrap(), expected);
    }
    drop(conn);
    unchanged(&path, bytes);
}

#[test]
fn rejects_stored_generated_columns() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = include_bytes!("fixtures/turso/stored.db");
    let path = dir.path().join("stored.db");
    std::fs::write(&path, bytes).unwrap();
    let error = open_readonly(&path, SQLCIPHER3_CASE.config(), b"veilite-turso-fixture")
        .err()
        .expect("unsupported STORED generated column");
    assert!(
        matches!(error, OpenError::Turso(_)) && error.to_string().contains("Stored generated"),
        "{error}"
    );
    unchanged(&path, bytes);
}
