use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use veilite::{CompatibilityProfile, Decryptor};
use zeroize::Zeroize;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    version,
    about = "Decrypt a supported SQLCipher database into a SQLite file",
    after_help = "Environment:\n  VEILITE_PASSPHRASE  Passphrase for the encrypted database"
)]
struct CliArgs {
    /// SQLCipher on-disk compatibility profile
    #[arg(long, value_enum, value_name = "PROFILE")]
    compatibility: CompatibilityArg,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,

    /// Destination SQLite file; must not already exist
    #[arg(value_name = "DECRYPTED_SQLITE")]
    output_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CompatibilityArg {
    #[value(name = "3")]
    V3,
    #[value(name = "4")]
    V4,
}

impl CompatibilityArg {
    const fn profile(self) -> CompatibilityProfile {
        match self {
            Self::V3 => CompatibilityProfile::SqlCipher3,
            Self::V4 => CompatibilityProfile::SqlCipher4,
        }
    }
}

fn validate_encrypted_file_size(file_size: usize, page_size: usize) -> io::Result<()> {
    if file_size < page_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encrypted database is shorter than one page for the selected compatibility profile: {file_size} bytes"
            ),
        ));
    }
    if !file_size.is_multiple_of(page_size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encrypted database size {file_size} is not a multiple of the selected page size {page_size}"
            ),
        ));
    }
    Ok(())
}

fn write_new_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse();
    let profile = args.compatibility.profile();
    let encrypted = fs::read(&args.input_path)?;
    let page_size = profile.page_size();
    validate_encrypted_file_size(encrypted.len(), page_size)?;

    let mut passphrase = std::env::var("VEILITE_PASSPHRASE").map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "VEILITE_PASSPHRASE is not set")
    })?;
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&encrypted[..16]);
    let decryptor = Decryptor::new(profile, passphrase.as_bytes(), &salt);
    passphrase.zeroize();
    salt.zeroize();
    let decryptor = decryptor?;

    let plaintext = decryptor.decrypt_database(&encrypted)?;
    write_new_private_file(&args.output_path, plaintext.as_slice())?;

    println!(
        "decrypted {} pages to {}",
        encrypted.len() / page_size,
        args.output_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, error::ErrorKind};

    use super::*;

    #[test]
    fn parses_supported_compatibility_profiles() {
        for (value, compatibility) in [("3", CompatibilityArg::V3), ("4", CompatibilityArg::V4)] {
            assert_eq!(
                CliArgs::try_parse_from([
                    "veilite",
                    "--compatibility",
                    value,
                    "encrypted.db",
                    "decrypted.sqlite3",
                ])
                .unwrap(),
                CliArgs {
                    compatibility,
                    input_path: "encrypted.db".into(),
                    output_path: "decrypted.sqlite3".into(),
                }
            );
        }
    }

    #[test]
    fn rejects_unsupported_compatibility() {
        let error = CliArgs::try_parse_from([
            "veilite",
            "--compatibility",
            "2",
            "encrypted.db",
            "decrypted.sqlite3",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn requires_explicit_compatibility() {
        let error =
            CliArgs::try_parse_from(["veilite", "encrypted.db", "decrypted.sqlite3"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn help_describes_arguments_and_passphrase_environment_variable() {
        let help = CliArgs::try_parse_from(["veilite", "--help"])
            .unwrap_err()
            .to_string();

        assert!(help.contains("--compatibility <PROFILE>"));
        assert!(help.contains("SQLCipher encrypted main database"));
        assert!(help.contains("Destination SQLite file; must not already exist"));
        assert!(help.contains("VEILITE_PASSPHRASE"));
    }

    #[test]
    fn verifies_cli_definition() {
        CliArgs::command().debug_assert();
    }

    #[test]
    fn validates_encrypted_file_sizes() {
        for page_size in [1024, 4096] {
            assert!(validate_encrypted_file_size(page_size, page_size).is_ok());
            assert!(validate_encrypted_file_size(page_size * 2, page_size).is_ok());

            for file_size in [0, page_size - 1, page_size + 1] {
                let error = validate_encrypted_file_size(file_size, page_size).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }
}
