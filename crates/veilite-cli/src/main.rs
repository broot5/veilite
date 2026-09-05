use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use bstr::BStr;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use veilite_core::{CipherConfig, CipherPreset, FileSource, HashAlgorithm, SqlCipherReader};
use veilite_graphitesql::{QueryResult, Value, check_companion_files, open_readonly};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(version, about = "Read immutable SQLCipher main database snapshots")]
struct CliArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Export an encrypted database as a plaintext SQLite image
    ///
    /// Input must be an immutable main database snapshot. Sibling -wal and
    /// -journal files are rejected.
    Export(ExportArgs),

    /// Show encrypted database and cipher configuration information
    ///
    /// Reports sibling -wal and -journal files without opening the database or
    /// reading a passphrase.
    Inspect(InspectArgs),

    /// Execute a read-only SQL query
    ///
    /// Input must be an immutable main database snapshot. Sibling -wal and
    /// -journal files are rejected.
    Query(QueryArgs),

    /// Authenticate every encrypted database page
    ///
    /// Input must be an immutable main database snapshot. Sibling -wal and
    /// -journal files are rejected.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[command(flatten)]
    cipher: CipherArgs,

    #[command(flatten)]
    passphrase: PassphraseArgs,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,

    /// Destination SQLite file; must not already exist
    #[arg(value_name = "DECRYPTED_SQLITE")]
    output_path: PathBuf,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[command(flatten)]
    cipher: CipherArgs,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,
}

#[derive(Debug, Args)]
struct QueryArgs {
    #[command(flatten)]
    cipher: CipherArgs,

    #[command(flatten)]
    passphrase: PassphraseArgs,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,

    /// Read-only SQL statement to execute
    #[arg(value_name = "SQL")]
    sql: String,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[command(flatten)]
    cipher: CipherArgs,

    #[command(flatten)]
    passphrase: PassphraseArgs,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,
}

#[derive(Debug, Args)]
struct PassphraseArgs {
    /// Read the passphrase from the first line of FILE instead of prompting
    #[arg(long, value_name = "FILE", help_heading = "Passphrase input")]
    passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("cipher_mode")
            .required(true)
            .multiple(false)
            .args(["preset", "custom"])
    ),
    group(
        ArgGroup::new("custom_configuration")
            .multiple(true)
            .args([
                "page_size",
                "kdf_iterations",
                "kdf_algorithm",
                "hmac_algorithm",
            ])
            .requires("custom")
    )
)]
struct CipherArgs {
    /// Complete SQLCipher 3 or 4 default on-disk configuration
    #[arg(
        long,
        value_enum,
        value_name = "PRESET",
        help_heading = "Cipher configuration",
        conflicts_with = "custom_configuration"
    )]
    preset: Option<CipherPresetArg>,

    /// Supply a complete custom cipher configuration
    #[arg(
        long,
        help_heading = "Cipher configuration",
        requires_all = [
            "page_size",
            "kdf_iterations",
            "kdf_algorithm",
            "hmac_algorithm"
        ]
    )]
    custom: bool,

    /// Cipher page size for a custom configuration
    #[arg(long, value_name = "BYTES", help_heading = "Cipher configuration")]
    page_size: Option<usize>,

    /// Encryption key derivation iteration count
    #[arg(long, value_name = "COUNT", help_heading = "Cipher configuration")]
    kdf_iterations: Option<u32>,

    /// PBKDF2-HMAC algorithm for encryption and HMAC key derivation
    #[arg(
        long,
        value_enum,
        value_name = "ALGORITHM",
        help_heading = "Cipher configuration"
    )]
    kdf_algorithm: Option<HashAlgorithmArg>,

    /// HMAC algorithm for page authentication
    #[arg(
        long,
        value_enum,
        value_name = "ALGORITHM",
        help_heading = "Cipher configuration"
    )]
    hmac_algorithm: Option<HashAlgorithmArg>,
}

impl CipherArgs {
    fn config(&self) -> Result<CipherConfig, Box<dyn Error>> {
        match (self.preset, self.custom) {
            (Some(preset), false) => Ok(preset.preset().into()),
            (None, true) => {
                let (
                    Some(page_size),
                    Some(kdf_iterations),
                    Some(kdf_algorithm),
                    Some(hmac_algorithm),
                ) = (
                    self.page_size,
                    self.kdf_iterations,
                    self.kdf_algorithm,
                    self.hmac_algorithm,
                )
                else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "provide all four cipher options with --custom",
                    )
                    .into());
                };

                CipherConfig::new(
                    page_size,
                    kdf_iterations,
                    kdf_algorithm.into(),
                    hmac_algorithm.into(),
                )
                .map_err(Into::into)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select exactly one of --preset <3|4> or --custom",
            )
            .into()),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CipherPresetArg {
    #[value(name = "3")]
    V3,
    #[value(name = "4")]
    V4,
}

impl CipherPresetArg {
    const fn preset(self) -> CipherPreset {
        match self {
            Self::V3 => CipherPreset::SqlCipher3,
            Self::V4 => CipherPreset::SqlCipher4,
        }
    }

    const fn number(self) -> u8 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HashAlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

impl From<HashAlgorithmArg> for HashAlgorithm {
    fn from(algorithm: HashAlgorithmArg) -> Self {
        match algorithm {
            HashAlgorithmArg::Sha1 => Self::Sha1,
            HashAlgorithmArg::Sha256 => Self::Sha256,
            HashAlgorithmArg::Sha512 => Self::Sha512,
        }
    }
}

fn validate_encrypted_file_size(file_size: u64, page_size: u64) -> io::Result<()> {
    if file_size < page_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encrypted database is shorter than one page for the selected cipher configuration: {file_size} bytes"
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

fn run() -> Result<(), Box<dyn Error>> {
    match CliArgs::parse().command {
        Command::Export(args) => export(args),
        Command::Inspect(args) => inspect(args),
        Command::Query(args) => query(args),
        Command::Verify(args) => verify(args),
    }
}

fn export(args: ExportArgs) -> Result<(), Box<dyn Error>> {
    let config = args.cipher.config()?;
    check_companion_files(&args.input_path)?;
    let passphrase = read_passphrase(&args.passphrase)?;
    let source = open_encrypted_database(&args.input_path)?;
    let reader = SqlCipherReader::open(source, config, passphrase.as_slice())?;
    drop(passphrase);

    write_decrypted_database(&args.output_path, &reader)?;

    writeln!(
        io::stdout().lock(),
        "decrypted {} pages to {}",
        reader.page_count(),
        args.output_path.display()
    )?;
    Ok(())
}

fn write_decrypted_database(
    path: &Path,
    reader: &SqlCipherReader<FileSource>,
) -> Result<(), Box<dyn Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .map_err(|source| path_io_error("failed to create export", path, source))?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut plaintext_page = Zeroizing::new(vec![0; reader.page_size()]);
        for page_no in 1..=reader.page_count() {
            let page_no = nonzero_page_number(page_no)?;
            reader.read_page_into(page_no, &mut plaintext_page)?;
            file.write_all(&plaintext_page)
                .map_err(|source| path_io_error("failed to write export", path, source))?;
        }
        file.sync_all()
            .map_err(|source| path_io_error("failed to sync export", path, source))?;
        Ok(())
    })();

    if let Err(error) = result {
        drop(file);
        return Err(cleanup_failed_export(path, error));
    }
    Ok(())
}

fn cleanup_failed_export(path: &Path, export_error: Box<dyn Error>) -> Box<dyn Error> {
    match fs::remove_file(path) {
        Ok(()) => export_error,
        Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => export_error,
        Err(cleanup_error) => io::Error::new(
            cleanup_error.kind(),
            format!(
                "export failed: {export_error}; failed to remove partial plaintext file {path:?}: \
                 {cleanup_error}; the file may contain decrypted data"
            ),
        )
        .into(),
    }
}

fn path_io_error(action: &str, path: &Path, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{action} {path:?}: {source}"))
}

fn open_encrypted_database(path: &Path) -> io::Result<FileSource> {
    FileSource::open(path)
        .map_err(|source| path_io_error("failed to open encrypted database", path, source))
}

fn inspect(args: InspectArgs) -> Result<(), Box<dyn Error>> {
    let config = args.cipher.config()?;
    let metadata = fs::metadata(&args.input_path).map_err(|source| {
        path_io_error(
            "failed to inspect encrypted database",
            &args.input_path,
            source,
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("database path is not a file: {}", args.input_path.display()),
        )
        .into());
    }

    let file_size = metadata.len();
    let page_size = config.page_size() as u64;
    validate_encrypted_file_size(file_size, page_size)?;

    let wal_path = companion_path(&args.input_path, "-wal");
    let journal_path = companion_path(&args.input_path, "-journal");
    let stdout = io::stdout();
    let mut output = stdout.lock();

    writeln!(output, "path: {}", args.input_path.display())?;
    match args.cipher.preset {
        Some(preset) => {
            writeln!(output, "configuration: preset")?;
            writeln!(output, "preset: {}", preset.number())?;
        }
        None => writeln!(output, "configuration: custom")?,
    }
    writeln!(output, "file size: {file_size} bytes")?;
    writeln!(output, "page size: {page_size} bytes")?;
    writeln!(output, "KDF iterations: {}", config.kdf_iterations())?;
    writeln!(
        output,
        "KDF algorithm: {}",
        hash_algorithm_name(config.kdf_algorithm())
    )?;
    writeln!(
        output,
        "HMAC algorithm: {}",
        hash_algorithm_name(config.hmac_algorithm())
    )?;
    writeln!(output, "reserve size: {} bytes", config.reserve_size())?;
    writeln!(output, "page count: {}", file_size / page_size)?;
    writeln!(output, "WAL: {}", presence(&wal_path)?)?;
    writeln!(output, "journal: {}", presence(&journal_path)?)?;
    Ok(())
}

fn query(args: QueryArgs) -> Result<(), Box<dyn Error>> {
    let config = args.cipher.config()?;
    check_companion_files(&args.input_path)?;
    let passphrase = read_passphrase(&args.passphrase)?;
    let connection = open_readonly(&args.input_path, config, passphrase.as_slice())?;
    drop(passphrase);
    let result = connection.query(&args.sql)?;

    let stdout = io::stdout();
    write_query_result(stdout.lock(), &result)?;
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    let config = args.cipher.config()?;
    check_companion_files(&args.input_path)?;
    let passphrase = read_passphrase(&args.passphrase)?;
    let source = open_encrypted_database(&args.input_path)?;
    let reader = SqlCipherReader::open(source, config, passphrase.as_slice())?;
    drop(passphrase);
    let mut plaintext_page = Zeroizing::new(vec![0; reader.page_size()]);

    for page_no in 1..=reader.page_count() {
        let page_no = nonzero_page_number(page_no)?;
        reader.read_page_into(page_no, &mut plaintext_page)?;
    }

    writeln!(
        io::stdout().lock(),
        "verified {} pages",
        reader.page_count()
    )?;
    Ok(())
}

const fn hash_algorithm_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
    }
}

fn nonzero_page_number(page_no: u32) -> io::Result<NonZeroU32> {
    NonZeroU32::new(page_no)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "database page number is zero"))
}

fn read_passphrase(args: &PassphraseArgs) -> io::Result<Zeroizing<Vec<u8>>> {
    match &args.passphrase_file {
        Some(path) => read_passphrase_file(path),
        None => rpassword::prompt_password("Passphrase: ")
            .map(String::into_bytes)
            .map(Zeroizing::new),
    }
}

fn read_passphrase_file(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let bytes = fs::read(path)
        .map_err(|source| path_io_error("failed to read passphrase file", path, source))?;
    let mut passphrase = Zeroizing::new(bytes);

    truncate_to_first_line(&mut passphrase);

    Ok(passphrase)
}

fn truncate_to_first_line(passphrase: &mut Vec<u8>) {
    if let Some(line_end) = passphrase.iter().position(|byte| *byte == b'\n') {
        passphrase[line_end..].zeroize();
        passphrase.truncate(line_end);
    }
    if passphrase.last() == Some(&b'\r') {
        passphrase.pop();
    }
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    companion.into()
}

fn presence(path: &Path) -> io::Result<&'static str> {
    path.try_exists()
        .map_err(|source| path_io_error("failed to inspect companion file", path, source))
        .map(|exists| if exists { "present" } else { "absent" })
}

fn write_query_result(mut output: impl Write, result: &QueryResult) -> io::Result<()> {
    write_cells(&mut output, &result.columns, |column, output| {
        write!(output, "{column:?}")
    })?;

    for row in &result.rows {
        write_cells(&mut output, row, write_value)?;
    }
    Ok(())
}

fn write_cells<T>(
    output: &mut impl Write,
    cells: &[T],
    mut write_cell: impl FnMut(&T, &mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            output.write_all(b"|")?;
        }
        write_cell(cell, output)?;
    }
    output.write_all(b"\n")
}

fn write_value(value: &Value, output: &mut dyn Write) -> io::Result<()> {
    match value {
        Value::Null => output.write_all(b"NULL"),
        Value::Integer(value) => write!(output, "{value}"),
        Value::Real(value) => write!(output, "{value}"),
        Value::Text(value) => write!(output, "{:?}", BStr::new(value.as_bytes())),
        Value::Blob(value) => {
            output.write_all(b"X'")?;
            for byte in value {
                write!(output, "{byte:02x}")?;
            }
            output.write_all(b"'")
        }
    }
}

fn main() {
    if let Err(error) = run() {
        if is_broken_pipe(error.as_ref()) {
            return;
        }
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn is_broken_pipe(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
}

#[cfg(test)]
mod tests;
