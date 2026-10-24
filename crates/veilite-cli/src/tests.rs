use std::sync::atomic::{AtomicU64, Ordering};

use clap::{CommandFactory, error::ErrorKind};

use super::*;

#[test]
fn verifies_cli_definition() {
    CliArgs::command().debug_assert();
}

fn parse_cipher_config(args: &[&str]) -> Result<CipherConfig, Box<dyn Error>> {
    let parsed = CliArgs::try_parse_from(args)?;
    match parsed.command {
        Command::Export(args) => args.cipher.config(),
        Command::Inspect(args) => args.cipher.config(),
        Command::Verify(args) => args.cipher.config(),
    }
}

#[test]
fn accepts_preset_configuration_for_every_command() {
    for args in [
        vec![
            "veilite",
            "export",
            "--preset",
            "4",
            "encrypted.db",
            "plaintext.db",
        ],
        vec!["veilite", "inspect", "--preset", "4", "encrypted.db"],
        vec!["veilite", "verify", "--preset", "4", "encrypted.db"],
    ] {
        assert_eq!(
            parse_cipher_config(&args).unwrap(),
            CipherConfig::from(CipherPreset::SqlCipher4)
        );
    }
}

#[test]
fn accepts_complete_custom_configuration_for_every_command() {
    let expected =
        CipherConfig::new(2048, 100_000, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap();
    let custom = [
        "--custom",
        "--page-size",
        "2048",
        "--kdf-iterations",
        "100000",
        "--kdf-algorithm",
        "sha256",
        "--hmac-algorithm",
        "sha256",
    ];

    for mut args in [
        vec!["veilite", "export"],
        vec!["veilite", "inspect"],
        vec!["veilite", "verify"],
    ] {
        args.extend(custom);
        match args[1] {
            "export" => args.extend(["encrypted.db", "plaintext.db"]),
            _ => args.push("encrypted.db"),
        }

        assert_eq!(parse_cipher_config(&args).unwrap(), expected);
    }
}

#[test]
fn rejects_missing_partial_and_mixed_cipher_configuration() {
    for args in [
        vec!["veilite", "inspect", "encrypted.db"],
        vec![
            "veilite",
            "inspect",
            "--custom",
            "--page-size",
            "2048",
            "encrypted.db",
        ],
        vec![
            "veilite",
            "inspect",
            "--preset",
            "4",
            "--page-size",
            "2048",
            "--kdf-iterations",
            "100000",
            "--kdf-algorithm",
            "sha256",
            "--hmac-algorithm",
            "sha256",
            "encrypted.db",
        ],
    ] {
        assert!(CliArgs::try_parse_from(args).is_err());
    }
}

#[test]
fn reports_preset_and_custom_configuration_as_conflicting() {
    let error = CliArgs::try_parse_from([
        "veilite",
        "inspect",
        "--preset",
        "4",
        "--kdf-iterations",
        "100000",
        "encrypted.db",
    ])
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn validates_inspect_file_sizes() {
    for page_size in [1024_u64, 4096] {
        assert!(validate_encrypted_file_size(page_size, page_size).is_ok());
        assert!(validate_encrypted_file_size(page_size * 2, page_size).is_ok());

        for file_size in [0, page_size - 1, page_size + 1] {
            let error = validate_encrypted_file_size(file_size, page_size).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    assert!(validate_encrypted_file_size(1_u64 << 32, 4096).is_ok());
}

#[test]
fn keeps_only_the_first_passphrase_file_line() {
    for (contents, expected) in [
        (b"passphrase".to_vec(), b"passphrase".as_slice()),
        (b"passphrase\nignored".to_vec(), b"passphrase".as_slice()),
        (b"passphrase\r\nignored".to_vec(), b"passphrase".as_slice()),
        (b"passphrase\r".to_vec(), b"passphrase".as_slice()),
        (
            b"\xff\0 \rinside\nignored".to_vec(),
            b"\xff\0 \rinside".as_slice(),
        ),
        (b"\nignored".to_vec(), b"".as_slice()),
        (Vec::new(), b"".as_slice()),
    ] {
        let directory = TemporaryDirectory::new();
        let path = directory.path().join("passphrase");
        fs::write(&path, contents).unwrap();
        let passphrase = read_passphrase_file(&path).unwrap();

        assert_eq!(passphrase.as_slice(), expected);
    }
}

#[test]
fn reads_long_passphrases_across_buffer_boundaries() {
    for length in [4095, 4096, 4097, 8192] {
        let expected = vec![b'x'; length];
        let mut contents = expected.clone();
        contents.extend_from_slice(b"\r\nignored");
        let passphrase = read_passphrase_line(contents.as_slice()).unwrap();
        assert_eq!(passphrase.as_slice(), expected);
    }
}

#[test]
fn stops_reading_after_first_line_and_propagates_earlier_errors() {
    struct FailingTail {
        first: Option<&'static [u8]>,
    }

    impl Read for FailingTail {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            match self.first.take() {
                Some(mut bytes) => bytes.read(output),
                None => Err(io::Error::other("tail must not be read")),
            }
        }
    }

    let passphrase = read_passphrase_line(FailingTail {
        first: Some(b"secret\n"),
    })
    .unwrap();
    assert_eq!(passphrase.as_slice(), b"secret");
    let error = read_passphrase_line(FailingTail {
        first: Some(b"unfinished"),
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
}

#[test]
fn preserves_existing_outputs() {
    let directory = TemporaryDirectory::new();
    let input_path = directory.path().join("encrypted.db");
    let existing_output_path = directory.path().join("existing.db");
    let config = CipherConfig::from(CipherPreset::SqlCipher4);
    fs::write(&input_path, vec![0; config.page_size()]).unwrap();
    fs::write(&existing_output_path, b"keep this").unwrap();
    let reader = SqlCipherReader::open(
        FileSource::open(&input_path).unwrap(),
        config,
        b"test-passphrase",
    )
    .unwrap();

    let error = write_decrypted_database(&existing_output_path, &reader).unwrap_err();
    assert!(error.to_string().contains("failed to create export"));
    assert!(error.to_string().contains("existing.db"));
    assert_eq!(fs::read(&existing_output_path).unwrap(), b"keep this");
}

#[test]
fn reports_when_a_partial_export_cannot_be_removed() {
    let directory = TemporaryDirectory::new();
    let residual_path = directory.path().join("partial.db");
    fs::create_dir(&residual_path).unwrap();
    let export_error: Box<dyn Error> =
        io::Error::new(io::ErrorKind::InvalidData, "page authentication failed").into();

    let error = cleanup_failed_export(&residual_path, export_error);
    let message = error.to_string();

    assert!(residual_path.is_dir());
    assert!(message.contains("page authentication failed"));
    assert!(message.contains("partial.db"));
    assert!(message.contains("the file may contain decrypted data"));
}

#[test]
fn identifies_broken_pipe_errors() {
    let broken_pipe = io::Error::new(io::ErrorKind::BrokenPipe, "downstream closed");
    let other = io::Error::other("different failure");

    assert!(is_broken_pipe(&broken_pipe));
    assert!(!is_broken_pipe(&other));
}

static NEXT_TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Self {
        let id = NEXT_TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("veilite-cli-tests-{}-{id}", std::process::id()));
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
