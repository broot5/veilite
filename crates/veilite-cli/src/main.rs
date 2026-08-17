use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use veilite_core::{CompatibilityProfile, FileSource, SqlCipherReader};
use veilite_graphitesql::{QueryResult, Value, check_companion_files, open_readonly};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(version, about = "Read supported SQLCipher databases")]
struct CliArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decrypt a database into a SQLite file
    Export(ExportArgs),

    /// Show encrypted database and compatibility profile information
    Inspect(InspectArgs),

    /// Execute a read-only SQL query
    Query(QueryArgs),

    /// Authenticate every encrypted database page
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// SQLCipher on-disk compatibility profile
    #[arg(long, value_enum, value_name = "PROFILE")]
    compatibility: CompatibilityArg,

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
    /// SQLCipher on-disk compatibility profile
    #[arg(long, value_enum, value_name = "PROFILE")]
    compatibility: CompatibilityArg,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,
}

#[derive(Debug, Args)]
struct QueryArgs {
    /// SQLCipher on-disk compatibility profile
    #[arg(long, value_enum, value_name = "PROFILE")]
    compatibility: CompatibilityArg,

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
    /// SQLCipher on-disk compatibility profile
    #[arg(long, value_enum, value_name = "PROFILE")]
    compatibility: CompatibilityArg,

    #[command(flatten)]
    passphrase: PassphraseArgs,

    /// SQLCipher encrypted main database
    #[arg(value_name = "ENCRYPTED_DB")]
    input_path: PathBuf,
}

#[derive(Debug, Args)]
struct PassphraseArgs {
    /// Read the passphrase from the first line of FILE instead of prompting
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
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

    const fn number(self) -> u8 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
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

fn run() -> Result<(), Box<dyn Error>> {
    match CliArgs::parse().command {
        Command::Export(args) => export(args),
        Command::Inspect(args) => inspect(args),
        Command::Query(args) => query(args),
        Command::Verify(args) => verify(args),
    }
}

fn export(args: ExportArgs) -> Result<(), Box<dyn Error>> {
    check_companion_files(&args.input_path)?;
    let passphrase = read_passphrase(&args.passphrase)?;
    let source = FileSource::open(&args.input_path)?;
    let reader =
        SqlCipherReader::open(source, args.compatibility.profile(), passphrase.as_slice())?;
    drop(passphrase);

    write_decrypted_database(&args.output_path, &reader)?;

    println!(
        "decrypted {} pages to {}",
        reader.page_count(),
        args.output_path.display()
    );
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

    let mut file = options.open(path)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut plaintext_page = Zeroizing::new(vec![0; reader.page_size()]);
        for page_no in 1..=reader.page_count() {
            let page_no = nonzero_page_number(page_no)?;
            reader.read_page_into(page_no, &mut plaintext_page)?;
            file.write_all(&plaintext_page)?;
        }
        file.sync_all()?;
        Ok(())
    })();

    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn inspect(args: InspectArgs) -> Result<(), Box<dyn Error>> {
    let metadata = fs::metadata(&args.input_path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("database path is not a file: {}", args.input_path.display()),
        )
        .into());
    }

    let file_size = usize::try_from(metadata.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted database size does not fit in usize",
        )
    })?;
    let page_size = args.compatibility.profile().page_size();
    validate_encrypted_file_size(file_size, page_size)?;

    let wal_path = companion_path(&args.input_path, "-wal");
    let journal_path = companion_path(&args.input_path, "-journal");

    println!("path: {}", args.input_path.display());
    println!("compatibility: {}", args.compatibility.number());
    println!("file size: {file_size} bytes");
    println!("page size: {page_size} bytes");
    println!("page count: {}", file_size / page_size);
    println!("WAL: {}", presence(&wal_path)?);
    println!("journal: {}", presence(&journal_path)?);
    Ok(())
}

fn query(args: QueryArgs) -> Result<(), Box<dyn Error>> {
    let passphrase = read_passphrase(&args.passphrase)?;
    let connection = open_readonly(
        &args.input_path,
        args.compatibility.profile(),
        passphrase.as_slice(),
    )?;
    drop(passphrase);
    let result = connection.query(&args.sql)?;

    let stdout = io::stdout();
    write_query_result(stdout.lock(), &result)?;
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    check_companion_files(&args.input_path)?;
    let passphrase = read_passphrase(&args.passphrase)?;
    let source = FileSource::open(&args.input_path)?;
    let reader =
        SqlCipherReader::open(source, args.compatibility.profile(), passphrase.as_slice())?;
    drop(passphrase);
    let mut plaintext_page = Zeroizing::new(vec![0; reader.page_size()]);

    for page_no in 1..=reader.page_count() {
        let page_no = nonzero_page_number(page_no)?;
        reader.read_page_into(page_no, &mut plaintext_page)?;
    }

    println!("verified {} pages", reader.page_count());
    Ok(())
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
    let bytes = fs::read(path).map_err(|source| {
        io::Error::new(
            source.kind(),
            format!(
                "failed to read passphrase file {}: {source}",
                path.display()
            ),
        )
    })?;
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
        .map(|exists| if exists { "present" } else { "absent" })
}

fn write_query_result(mut output: impl Write, result: &QueryResult) -> io::Result<()> {
    write_cells(&mut output, &result.columns, |column, output| {
        output.write_all(column.as_bytes())
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
        Value::Text(value) => output.write_all(value),
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
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verifies_cli_definition() {
        CliArgs::command().debug_assert();
    }

    #[test]
    fn validates_inspect_file_sizes() {
        for page_size in [1024, 4096] {
            assert!(validate_encrypted_file_size(page_size, page_size).is_ok());
            assert!(validate_encrypted_file_size(page_size * 2, page_size).is_ok());

            for file_size in [0, page_size - 1, page_size + 1] {
                let error = validate_encrypted_file_size(file_size, page_size).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    }

    #[test]
    fn keeps_only_the_first_passphrase_file_line() {
        for (mut contents, expected) in [
            (b"passphrase".to_vec(), b"passphrase".as_slice()),
            (b"passphrase\nignored".to_vec(), b"passphrase".as_slice()),
            (b"passphrase\r\nignored".to_vec(), b"passphrase".as_slice()),
            (Vec::new(), b"".as_slice()),
        ] {
            truncate_to_first_line(&mut contents);

            assert_eq!(contents, expected);
        }
    }

    #[test]
    fn writes_query_results() {
        let result = QueryResult {
            columns: vec![
                "null".into(),
                "integer".into(),
                "real".into(),
                "text".into(),
                "blob".into(),
            ],
            rows: vec![vec![
                Value::Null,
                Value::Integer(-42),
                Value::Real(3.5),
                Value::Text(b"hello".to_vec()),
                Value::Blob(vec![0x00, 0xab, 0xff]),
            ]],
        };
        let mut output = Vec::new();

        write_query_result(&mut output, &result).unwrap();

        assert_eq!(
            output,
            b"null|integer|real|text|blob\nNULL|-42|3.5|hello|X'00abff'\n"
        );
    }
}
