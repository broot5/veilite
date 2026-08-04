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
    #[arg(long, value_enum, value_name = "VERSION")]
    compatibility: CompatibilityArg,

    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,

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
    if encrypted.len() < page_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encrypted database is shorter than one page for the selected compatibility profile: {} bytes",
                encrypted.len()
            ),
        )
        .into());
    }

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

        assert!(error.to_string().contains("possible values: 3, 4"));
    }

    #[test]
    fn requires_explicit_compatibility() {
        let error =
            CliArgs::try_parse_from(["veilite", "encrypted.db", "decrypted.sqlite3"]).unwrap_err();

        assert!(error.to_string().contains("--compatibility <VERSION>"));
    }

    #[test]
    fn help_mentions_passphrase_environment_variable() {
        let help = CliArgs::try_parse_from(["veilite", "--help"])
            .unwrap_err()
            .to_string();

        assert!(help.contains("VEILITE_PASSPHRASE"));
    }
}
