#[path = "common/cli.rs"]
mod cli_support;
mod common;

use common::{FIXTURE_CASES, FixtureCase, FixtureCipher};
use std::num::NonZeroU32;
use veilite_core::{SliceSource, SqlCipherReader};

// Exercise the production CLI source through the integration-only binary target.
// Full SQLCipher fixtures stay in this unpublished crate's test suite.
struct CliFixture {
    directory: tempfile::TempDir,
    case: FixtureCase,
}

impl CliFixture {
    fn new(case: FixtureCase) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("veilite-integration-cli-")
            .tempdir()
            .unwrap_or_else(|error| panic!("{} temp directory: {error}", case.name));
        std::fs::write(directory.path().join("input.db"), case.encrypted)
            .unwrap_or_else(|error| panic!("{} input setup: {error}", case.name));
        std::fs::write(directory.path().join("passphrase"), case.passphrase)
            .unwrap_or_else(|error| panic!("{} passphrase setup: {error}", case.name));
        Self { directory, case }
    }

    fn run(&self, command: &str) -> std::process::Output {
        let mut cli = std::process::Command::new(env!("CARGO_BIN_EXE_veilite-test-cli"));
        cli.arg(command).args(self.case.cipher.cli_options());
        cli.arg("--passphrase-file")
            .arg(self.directory.path().join("passphrase"));
        cli.arg(self.directory.path().join("input.db"));
        if command == "export" {
            cli.arg(self.directory.path().join("output.db"));
        }
        cli.stdin(std::process::Stdio::null())
            .output()
            .unwrap_or_else(|error| panic!("{} {command} launch: {error}", self.case.name))
    }

    #[track_caller]
    fn assert_authentication_failure(&self, command: &str, page: u32) {
        let context = format!(
            "{} {command}, expected failure at page {page}",
            self.case.name
        );
        let output = self.run(command);
        assert_eq!(output.status.code(), Some(1), "{context}: {output:?}");
        assert!(output.stdout.is_empty(), "{context}: {output:?}");
        let error = String::from_utf8(output.stderr)
            .unwrap_or_else(|error| panic!("{context}: invalid stderr: {error}"));
        assert!(
            error.contains(&format!("page {page}:")),
            "{context}: {error}"
        );
        assert!(error.contains("authentication"), "{context}: {error}");
        assert!(
            !self.directory.path().join("output.db").exists(),
            "{context}: export was not removed"
        );
    }
}

#[test]
fn cli_verifies_and_exports_every_page() {
    for case in FIXTURE_CASES {
        let fixture = CliFixture::new(case);
        let reader = SqlCipherReader::open(
            SliceSource::new(case.encrypted),
            case.config(),
            case.passphrase,
        )
        .unwrap_or_else(|error| panic!("{} reader failed to open: {error}", case.name));
        assert!(
            reader.page_count() > 1,
            "{} needs multiple pages",
            case.name
        );
        for command in ["verify", "export"] {
            let output = fixture.run(command);
            assert!(
                output.status.success(),
                "{} {command}: {:?}",
                case.name,
                output
            );
            assert!(
                output.stderr.is_empty(),
                "{} {command}: {output:?}",
                case.name
            );
            let expected = if command == "verify" {
                format!("verified {} pages\n", reader.page_count())
            } else {
                format!(
                    "decrypted {} pages to {}\n",
                    reader.page_count(),
                    fixture.directory.path().join("output.db").display()
                )
            };
            assert_eq!(
                output.stdout,
                expected.as_bytes(),
                "{} {command} stdout",
                case.name
            );
        }
        let exported = std::fs::read(fixture.directory.path().join("output.db"))
            .unwrap_or_else(|error| panic!("{} read export: {error}", case.name));
        assert_eq!(
            exported.len(),
            case.encrypted.len(),
            "{} export length",
            case.name
        );
        let mut expected = vec![0; case.page_size];
        for (index, actual) in exported.chunks_exact(case.page_size).enumerate() {
            let page_no = NonZeroU32::new(u32::try_from(index + 1).unwrap()).unwrap();
            reader
                .read_page_into(page_no, &mut expected)
                .unwrap_or_else(|error| {
                    panic!("{} export reference page {page_no}: {error}", case.name)
                });
            assert_eq!(actual, expected, "{} page {page_no}", case.name);
        }
    }
}

#[test]
fn cli_rejects_wrong_passphrases() {
    for case in FIXTURE_CASES {
        let fixture = CliFixture::new(case);
        std::fs::write(
            fixture.directory.path().join("passphrase"),
            b"wrong passphrase",
        )
        .unwrap_or_else(|error| panic!("{} passphrase setup: {error}", case.name));
        for command in ["verify", "export"] {
            fixture.assert_authentication_failure(command, 1);
        }
    }
}

#[test]
fn cli_rejects_late_corruption_and_removes_partial_exports() {
    for case in FIXTURE_CASES {
        let fixture = CliFixture::new(case);
        let last_page = u32::try_from(case.encrypted.len() / case.page_size).unwrap();
        assert!(last_page > 1, "{} needs multiple pages", case.name);
        let mut corrupted = case.encrypted.to_vec();
        corrupted[(last_page as usize - 1) * case.page_size + 16] ^= 1;
        // Prove the preceding pages are readable, so export reaches the
        // failure only after writing plaintext to its destination.
        let reader =
            SqlCipherReader::open(SliceSource::new(&corrupted), case.config(), case.passphrase)
                .unwrap_or_else(|error| panic!("{} corrupted reader setup: {error}", case.name));
        let mut page = vec![0; case.page_size];
        for number in 1..last_page {
            reader
                .read_page_into(NonZeroU32::new(number).unwrap(), &mut page)
                .unwrap_or_else(|error| panic!("{} preceding page {number}: {error}", case.name));
        }
        std::fs::write(fixture.directory.path().join("input.db"), corrupted)
            .unwrap_or_else(|error| panic!("{} corrupted input setup: {error}", case.name));
        for command in ["verify", "export"] {
            fixture.assert_authentication_failure(command, last_page);
        }
    }
}
