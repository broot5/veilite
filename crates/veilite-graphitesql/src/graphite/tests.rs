use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use veilite_core::CipherPreset;

const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

#[test]
fn file_adapter_is_strictly_read_only() {
    let directory = TemporaryDirectory::new();
    let path = directory.path().join("encrypted.db");
    fs::write(
        &path,
        vec![0; CipherConfig::from(CipherPreset::SqlCipher4).page_size()],
    )
    .unwrap();
    let path_utf8 = path.to_str().unwrap();
    let vfs = SqlCipherVfs::new(&path, CipherPreset::SqlCipher4.into(), TEST_PASSPHRASE).unwrap();
    let mut file = Vfs::open(&vfs, path_utf8, OpenFlags::READ_ONLY).unwrap();
    let wal_path = companion_path_string(path_utf8, WAL_SUFFIX);

    assert!(Vfs::exists(&vfs, path_utf8).unwrap());
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
        Vfs::delete(&vfs, path_utf8),
        Err(GraphiteError::Error(message)) if message == READ_ONLY_ERROR
    ));
    assert!(matches!(
        Vfs::open(&vfs, path_utf8, OpenFlags::READ_WRITE),
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
            CipherPreset::SqlCipher4.into(),
            TEST_PASSPHRASE,
        ),
        Err(GraphiteAdapterError::Companion(CompanionError::UnsupportedWal { path }))
            if path == wal_path
    ));

    fs::remove_file(&wal_path).unwrap();
    File::create(&journal_path).unwrap();
    assert!(matches!(
        open_readonly(
            &database_path,
            CipherPreset::SqlCipher4.into(),
            TEST_PASSPHRASE,
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
