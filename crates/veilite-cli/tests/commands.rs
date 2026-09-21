use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veilite"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn exposes_snapshot_commands() {
    let help = cli(&["--help"]);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    let help = String::from_utf8(help.stdout).unwrap();
    for command in ["inspect", "verify", "export"] {
        assert!(help.contains(command));
        let output = cli(&[command, "--help"]);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn companion_preflight_precedes_passphrase_and_database_access() {
    let temp = TemporaryDirectory::new();
    // Main DB and passphrase intentionally do not exist. Companion rejection
    // must happen first, while inspect still requires a valid main file.
    let input = temp.0.join("missing.db");
    let passphrase = temp.0.join("missing.key");
    let destination = temp.0.join("output.db");
    for suffix in ["-wal", "-journal"] {
        let companion = temp.0.join(format!("missing.db{suffix}"));
        fs::write(&companion, b"companion").unwrap();
        for command in ["verify", "export"] {
            let mut args = vec![
                command,
                "--preset",
                "4",
                "--passphrase-file",
                passphrase.to_str().unwrap(),
                input.to_str().unwrap(),
            ];
            if command == "export" {
                args.push(destination.to_str().unwrap());
            }
            let output = cli(&args);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("companion file is unsupported"), "{error}");
            assert!(error.contains(suffix), "{error}");
            assert!(!destination.exists());
        }
        // Inspect reports companions without requesting a passphrase.
        fs::write(&input, vec![0; 4096]).unwrap();
        let output = cli(&["inspect", "--preset", "4", input.to_str().unwrap()]);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        let expected = if suffix == "-wal" {
            "WAL: present"
        } else {
            "journal: present"
        };
        assert!(text.contains(expected));
        fs::remove_file(&input).unwrap();
        fs::remove_file(&companion).unwrap();
    }
}

#[test]
fn invalid_configuration_is_reported_before_file_access() {
    let output = cli(&[
        "verify",
        "--custom",
        "--page-size",
        "1000",
        "--kdf-iterations",
        "1",
        "--kdf-algorithm",
        "sha256",
        "--hmac-algorithm",
        "sha256",
        "missing.db",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("page size")
    );
    let output = cli(&["verify", "missing.db"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("veilite-cli-commands-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
