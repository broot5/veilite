use std::{fs, io, path::Path};

#[track_caller]
pub fn assert_preserved(path: &Path, main: &[u8], wal: Option<&[u8]>) {
    assert_eq!(
        fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
        main,
        "{}: main file changed",
        path.display()
    );
    for suffix in ["-wal", "-journal", "-shm", "-tshm"] {
        let mut companion = path.as_os_str().to_os_string();
        companion.push(suffix);
        let companion = Path::new(&companion);
        if let ("-wal", Some(expected)) = (suffix, wal) {
            assert_eq!(
                fs::read(companion)
                    .unwrap_or_else(|error| panic!("{}: {error}", companion.display())),
                expected,
                "{}: WAL changed",
                companion.display()
            );
        } else {
            let metadata = fs::symlink_metadata(companion);
            assert!(
                matches!(&metadata, Err(error) if error.kind() == io::ErrorKind::NotFound),
                "{}: expected absent companion, got {metadata:?}",
                companion.display()
            );
        }
    }
}
