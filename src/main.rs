use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use veilite::{Decryptor, SQLCIPHER4_PAGE_SIZE};
use zeroize::Zeroize;

fn usage(program: &str) -> String {
    format!("usage: VEILITE_PASSPHRASE=<passphrase> {program} <encrypted.db> <decrypted.sqlite3>")
}

fn parse_paths() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "veilite".to_owned());
    let input = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage(&program)))?;
    let output = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage(&program)))?;
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage(&program)).into());
    }
    Ok((input.into(), output.into()))
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
    let (input_path, output_path) = parse_paths()?;
    let encrypted = fs::read(&input_path)?;
    if encrypted.len() < SQLCIPHER4_PAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encrypted database is shorter than one SQLCipher 4 page: {} bytes",
                encrypted.len()
            ),
        )
        .into());
    }

    let mut passphrase = env::var("VEILITE_PASSPHRASE").map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "VEILITE_PASSPHRASE is not set")
    })?;
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&encrypted[..16]);
    let decryptor = Decryptor::new_sqlcipher4(passphrase.as_bytes(), &salt);
    passphrase.zeroize();
    salt.zeroize();

    let plaintext = decryptor.decrypt_database(&encrypted)?;
    write_new_private_file(&output_path, plaintext.as_slice())?;

    println!(
        "decrypted {} pages to {}",
        encrypted.len() / SQLCIPHER4_PAGE_SIZE,
        output_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
