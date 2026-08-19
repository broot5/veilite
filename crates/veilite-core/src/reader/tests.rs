use std::cell::RefCell;
use std::io;
use std::num::NonZeroU32;
use std::path::PathBuf;

use super::*;
use crate::decryptor::PageDecryptor;
use crate::{CipherPreset, FileSource, SliceSource};

const SQLCIPHER3_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/sqlcipher3/encrypted.db");
const SQLCIPHER3_PASSPHRASE: &[u8] = b"veilite-sqlcipher3-test-key";
const SQLCIPHER4_FIXTURE: &[u8] = include_bytes!("../../../../fixtures/sqlcipher4/encrypted.db");
const SQLCIPHER4_PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";
const SQLCIPHER_CUSTOM_FIXTURE: &[u8] =
    include_bytes!("../../../../fixtures/sqlcipher-custom/encrypted.db");
const SQLCIPHER_CUSTOM_PASSPHRASE: &[u8] = b"veilite-sqlcipher-custom-test-key";

#[derive(Clone, Copy)]
enum FixtureCipher {
    SqlCipher3,
    SqlCipher4,
    Custom,
}

impl FixtureCipher {
    fn config(self) -> CipherConfig {
        match self {
            Self::SqlCipher3 => CipherPreset::SqlCipher3.into(),
            Self::SqlCipher4 => CipherPreset::SqlCipher4.into(),
            Self::Custom => CipherConfig::new(
                2048,
                100_000,
                crate::HashAlgorithm::Sha256,
                crate::HashAlgorithm::Sha256,
            )
            .expect("custom fixture configuration is valid"),
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureCase {
    name: &'static str,
    cipher: FixtureCipher,
    fixture: &'static [u8],
    passphrase: &'static [u8],
}

const FIXTURE_CASES: [FixtureCase; 3] = [
    FixtureCase {
        name: "sqlcipher3",
        cipher: FixtureCipher::SqlCipher3,
        fixture: SQLCIPHER3_FIXTURE,
        passphrase: SQLCIPHER3_PASSPHRASE,
    },
    FixtureCase {
        name: "sqlcipher4",
        cipher: FixtureCipher::SqlCipher4,
        fixture: SQLCIPHER4_FIXTURE,
        passphrase: SQLCIPHER4_PASSPHRASE,
    },
    FixtureCase {
        name: "sqlcipher-custom",
        cipher: FixtureCipher::Custom,
        fixture: SQLCIPHER_CUSTOM_FIXTURE,
        passphrase: SQLCIPHER_CUSTOM_PASSPHRASE,
    },
];

impl FixtureCase {
    fn cipher_config(self) -> CipherConfig {
        self.cipher.config()
    }

    fn reader(self) -> SqlCipherReader<SliceSource<'static>> {
        SqlCipherReader::open(
            SliceSource::new(self.fixture),
            self.cipher_config(),
            self.passphrase,
        )
        .unwrap_or_else(|error| panic!("{} reader failed to open: {error}", self.name))
    }

    fn plaintext(self) -> Zeroizing<Vec<u8>> {
        let salt = self.fixture[..16].try_into().unwrap();
        let decryptor = PageDecryptor::new(self.cipher_config(), self.passphrase, salt).unwrap();
        let page_size = decryptor.page_size();
        let mut plaintext = Zeroizing::new(vec![0; self.fixture.len()]);

        for (index, encrypted_page) in self.fixture.chunks_exact(page_size).enumerate() {
            let page_no =
                NonZeroU32::new(u32::try_from(index + 1).expect("fixture page number fits"))
                    .expect("fixture page numbers start at one");
            let start = index * page_size;
            decryptor
                .decrypt_page_into(
                    page_no,
                    encrypted_page,
                    &mut plaintext[start..start + page_size],
                )
                .unwrap();
        }

        plaintext
    }
}

#[test]
fn opens_supported_fixture_metadata() {
    for case in FIXTURE_CASES {
        let reader = case.reader();

        assert_eq!(reader.file_size(), case.fixture.len() as u64);
        let page_size = case.cipher_config().page_size();
        assert_eq!(reader.page_size(), page_size);
        assert_eq!(
            reader.page_count(),
            u32::try_from(case.fixture.len() / page_size).expect("fixture page count fits in u32")
        );
    }
}

#[test]
fn defers_passphrase_authentication_until_the_first_page_read() {
    for case in FIXTURE_CASES {
        let reader = SqlCipherReader::open(
            SliceSource::new(case.fixture),
            case.cipher_config(),
            b"wrong passphrase",
        )
        .expect("opening a reader should only derive keys");
        let mut output = vec![0xaa; reader.page_size()];

        let error = reader
            .read_page_into(NonZeroU32::new(1).unwrap(), &mut output)
            .unwrap_err();

        assert!(matches!(
            error,
            ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 1 })
        ));
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn reads_single_pages() {
    for case in FIXTURE_CASES {
        let reader = case.reader();
        let expected = case.plaintext();
        let page_size = reader.page_size();

        for page_no in [1, reader.page_count()] {
            let mut output = vec![0; page_size];
            reader
                .read_page_into(NonZeroU32::new(page_no).unwrap(), &mut output)
                .unwrap();
            let start = (page_no as usize - 1) * page_size;

            assert_eq!(output, expected[start..start + page_size], "{}", case.name);
        }
    }
}

#[test]
fn reads_ranges_within_and_across_pages() {
    for case in FIXTURE_CASES {
        let reader = case.reader();
        let expected = case.plaintext();
        let page_size = reader.page_size();
        let ranges = [
            (0, 100),
            (page_size / 2, 200),
            (page_size - 31, 97),
            (page_size * 2 - 7, page_size + 23),
            (expected.len() - 1, 1),
        ];

        for (offset, length) in ranges {
            let mut output = vec![0; length];
            reader.read_exact_at(offset as u64, &mut output).unwrap();

            assert_eq!(output, expected[offset..offset + length], "{}", case.name);
        }
    }
}

#[test]
fn rejects_invalid_file_sizes_before_key_derivation() {
    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let page_size = CipherConfig::from(preset).page_size();
        assert!(matches!(open_error(&[], preset), ReaderError::EmptyFile));

        let too_small = vec![0; page_size - 1];
        assert!(matches!(
            open_error(&too_small, preset),
            ReaderError::FileTooSmall {
                file_size,
                page_size: actual_page_size,
            } if file_size == (page_size - 1) as u64 && actual_page_size == page_size
        ));

        let incomplete = vec![0; page_size + 1];
        assert!(matches!(
            open_error(&incomplete, preset),
            ReaderError::InvalidFileSize {
                file_size,
                page_size: actual_page_size,
            } if file_size == (page_size + 1) as u64 && actual_page_size == page_size
        ));
    }
}

fn open_error(bytes: &[u8], preset: CipherPreset) -> ReaderError<io::Error> {
    match SqlCipherReader::open(
        SliceSource::new(bytes),
        CipherConfig::from(preset),
        b"passphrase",
    ) {
        Ok(_) => panic!("invalid encrypted database should be rejected"),
        Err(error) => error,
    }
}

struct LengthOnlySource {
    length: u64,
}

impl ReadAt for LengthOnlySource {
    type Error = io::Error;

    fn read_exact_at(&self, _offset: u64, _output: &mut [u8]) -> io::Result<()> {
        unreachable!("oversized database should be rejected before reading the source")
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.length)
    }
}

#[test]
fn rejects_more_pages_than_u32_can_address() {
    let page_count = u64::from(u32::MAX) + 1;

    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let config = CipherConfig::from(preset);
        let source = LengthOnlySource {
            length: page_count * config.page_size() as u64,
        };
        let Err(error) = SqlCipherReader::open(source, config, b"passphrase") else {
            panic!("oversized database should be rejected");
        };

        assert!(matches!(
            error,
            ReaderError::TooManyPages {
                page_count: actual_page_count,
            } if actual_page_count == page_count
        ));
    }
}

#[test]
fn rejects_out_of_range_pages_and_reads() {
    for case in FIXTURE_CASES {
        let reader = case.reader();
        let mut page = vec![0xaa; reader.page_size()];
        let page_no = reader.page_count() + 1;
        let error = reader
            .read_page_into(NonZeroU32::new(page_no).unwrap(), &mut page)
            .unwrap_err();
        assert!(matches!(
            error,
            ReaderError::PageOutOfRange {
                page_no: actual_page_no,
                page_count
            } if actual_page_no == page_no && page_count == reader.page_count()
        ));
        assert!(page.iter().all(|byte| *byte == 0));

        let mut output = [0xaa; 2];
        let error = reader
            .read_exact_at(reader.file_size() - 1, &mut output)
            .unwrap_err();
        assert!(matches!(error, ReaderError::UnexpectedEof { .. }));
        assert_eq!(output, [0; 2]);

        let error = reader.read_exact_at(u64::MAX, &mut output).unwrap_err();
        assert!(matches!(error, ReaderError::OffsetOverflow { .. }));
        assert_eq!(output, [0; 2]);

        reader.read_exact_at(u64::MAX, &mut []).unwrap();
    }
}

#[test]
fn clears_partial_plaintext_when_a_later_page_fails_authentication() {
    for case in FIXTURE_CASES {
        let page_size = case.cipher_config().page_size();
        let mut tampered = case.fixture.to_vec();
        tampered[page_size + 16] ^= 1;
        let reader = SqlCipherReader::open(
            SliceSource::new(&tampered),
            case.cipher_config(),
            case.passphrase,
        )
        .unwrap();
        let mut output = vec![0xaa; 64];

        let error = reader
            .read_exact_at((page_size - 32) as u64, &mut output)
            .unwrap_err();

        assert!(matches!(
            error,
            ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 2 })
        ));
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

struct MisreportedLengthSource<'a> {
    bytes: &'a [u8],
    reported_length: u64,
}

impl ReadAt for MisreportedLengthSource<'_> {
    type Error = io::Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        SliceSource::new(self.bytes).read_exact_at(offset, output)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.reported_length)
    }
}

#[test]
fn rejects_short_source_reads_and_clears_output() {
    let case = FIXTURE_CASES[1];
    let source = MisreportedLengthSource {
        bytes: &case.fixture[..case.fixture.len() - 1],
        reported_length: case.fixture.len() as u64,
    };
    let reader = SqlCipherReader::open(source, case.cipher_config(), case.passphrase).unwrap();
    let mut output = vec![0xaa; reader.page_size()];

    let error = reader
        .read_page_into(NonZeroU32::new(reader.page_count()).unwrap(), &mut output)
        .unwrap_err();

    assert!(matches!(
        error,
        ReaderError::Source(source_error)
            if source_error.kind() == io::ErrorKind::UnexpectedEof
    ));
    assert!(output.iter().all(|byte| *byte == 0));
}

struct RecordingSource<'a> {
    bytes: &'a [u8],
    reads: RefCell<Vec<(u64, usize)>>,
}

impl ReadAt for RecordingSource<'_> {
    type Error = io::Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        self.reads.borrow_mut().push((offset, output.len()));
        SliceSource::new(self.bytes).read_exact_at(offset, output)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }
}

#[test]
fn reads_only_the_physical_pages_needed_for_a_range() {
    let case = FIXTURE_CASES[1];
    let source = RecordingSource {
        bytes: case.fixture,
        reads: RefCell::new(Vec::new()),
    };
    let reader = SqlCipherReader::open(source, case.cipher_config(), case.passphrase).unwrap();
    let page_size = reader.page_size();
    let mut output = vec![0; 64];

    reader
        .read_exact_at((page_size - 32) as u64, &mut output)
        .unwrap();

    assert_eq!(
        reader.source.reads.into_inner(),
        vec![(0, 16), (0, page_size), (page_size as u64, page_size)]
    );
}

#[test]
fn reads_ranges_from_file_source() {
    let case = FIXTURE_CASES[1];
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sqlcipher4/encrypted.db");
    let reader = SqlCipherReader::open(
        FileSource::open(fixture_path).unwrap(),
        case.cipher_config(),
        case.passphrase,
    )
    .unwrap();
    let expected = case.plaintext();
    let offset = reader.page_size() - 17;
    let mut output = vec![0; 100];

    reader.read_exact_at(offset as u64, &mut output).unwrap();

    assert_eq!(output, expected[offset..offset + output.len()]);
}
