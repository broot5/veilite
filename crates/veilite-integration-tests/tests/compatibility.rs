use std::num::NonZeroU32;
use std::path::PathBuf;

use veilite_core::{
    CipherConfig, CipherPreset, DecryptError, FileSource, HashAlgorithm, ReaderError, SliceSource,
    SqlCipherReader,
};
use veilite_graphitesql::{GraphiteAdapterError, Value, open_readonly};

const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy)]
enum FixtureCipher {
    SqlCipher3,
    SqlCipher4,
    Custom,
}

#[derive(Clone, Copy)]
struct FixtureCase {
    name: &'static str,
    cipher: FixtureCipher,
    encrypted: &'static [u8],
    passphrase: &'static [u8],
    page_size: usize,
    reserve_size: usize,
}

impl FixtureCase {
    fn config(self) -> CipherConfig {
        match self.cipher {
            FixtureCipher::SqlCipher3 => CipherPreset::SqlCipher3.into(),
            FixtureCipher::SqlCipher4 => CipherPreset::SqlCipher4.into(),
            FixtureCipher::Custom => {
                CipherConfig::new(2048, 100_000, HashAlgorithm::Sha256, HashAlgorithm::Sha256)
                    .expect("custom fixture configuration is valid")
            }
        }
    }

    fn path(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(self.name)
            .join("encrypted.db")
    }

    fn reader(self) -> SqlCipherReader<SliceSource<'static>> {
        SqlCipherReader::open(
            SliceSource::new(self.encrypted),
            self.config(),
            self.passphrase,
        )
        .unwrap_or_else(|error| panic!("{} reader failed to open: {error}", self.name))
    }
}

const SQLCIPHER3_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher3",
    cipher: FixtureCipher::SqlCipher3,
    encrypted: include_bytes!("../../../fixtures/sqlcipher3/encrypted.db"),
    passphrase: b"veilite-sqlcipher3-test-key",
    page_size: 1024,
    reserve_size: 48,
};

const SQLCIPHER4_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher4",
    cipher: FixtureCipher::SqlCipher4,
    encrypted: include_bytes!("../../../fixtures/sqlcipher4/encrypted.db"),
    passphrase: b"veilite-sqlcipher4-test-key",
    page_size: 4096,
    reserve_size: 80,
};

const SQLCIPHER_CUSTOM_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher-custom",
    cipher: FixtureCipher::Custom,
    encrypted: include_bytes!("../../../fixtures/sqlcipher-custom/encrypted.db"),
    passphrase: b"veilite-sqlcipher-custom-test-key",
    page_size: 2048,
    reserve_size: 48,
};

const FIXTURE_CASES: [FixtureCase; 3] = [SQLCIPHER3_CASE, SQLCIPHER4_CASE, SQLCIPHER_CUSTOM_CASE];

#[test]
fn authenticates_and_restores_supported_fixtures() {
    for case in FIXTURE_CASES {
        let reader = case.reader();
        let expected_page_count = case.encrypted.len() / case.page_size;

        assert_eq!(reader.page_size(), case.page_size, "{}", case.name);
        assert_eq!(
            reader.file_size(),
            u64::try_from(case.encrypted.len()).expect("fixture length fits in u64"),
            "{}",
            case.name
        );
        assert_eq!(
            reader.page_count(),
            u32::try_from(expected_page_count).expect("fixture page count fits in u32"),
            "{}",
            case.name
        );

        let mut page = vec![0; case.page_size];
        for page_no in 1..=reader.page_count() {
            reader
                .read_page_into(NonZeroU32::new(page_no).unwrap(), &mut page)
                .unwrap_or_else(|error| panic!("{} page {page_no}: {error}", case.name));

            assert!(
                page[case.page_size - case.reserve_size..]
                    .iter()
                    .all(|byte| *byte == 0),
                "{} page {page_no}",
                case.name
            );
        }

        reader
            .read_page_into(NonZeroU32::new(1).unwrap(), &mut page)
            .unwrap();
        assert_eq!(&page[..16], SQLITE_HEADER_MAGIC, "{}", case.name);
        assert_eq!(
            u16::from_be_bytes([page[16], page[17]]),
            u16::try_from(case.page_size).expect("fixture page size fits in u16"),
            "{}",
            case.name
        );
        assert_eq!(usize::from(page[20]), case.reserve_size, "{}", case.name);
        assert_eq!(
            u32::from_be_bytes(page[60..64].try_into().unwrap()),
            42,
            "{}",
            case.name
        );
        assert_eq!(
            u32::from_be_bytes(page[68..72].try_into().unwrap()),
            0x5645_4c49,
            "{}",
            case.name
        );
    }
}

#[test]
fn reads_matching_ranges_from_slice_and_file_sources() {
    for case in FIXTURE_CASES {
        let slice_reader = case.reader();
        let file_reader = SqlCipherReader::open(
            FileSource::open(case.path()).unwrap(),
            case.config(),
            case.passphrase,
        )
        .unwrap();
        let mut expected = Vec::with_capacity(case.encrypted.len());
        let mut page = vec![0; case.page_size];
        for page_no in 1..=slice_reader.page_count() {
            slice_reader
                .read_page_into(NonZeroU32::new(page_no).unwrap(), &mut page)
                .unwrap();
            expected.extend_from_slice(&page);
        }
        let ranges = [
            (0, 100),
            (case.page_size / 2, 200),
            (case.page_size - 31, 97),
            (case.page_size * 2 - 7, case.page_size + 23),
            (case.encrypted.len() - 1, 1),
        ];

        for (offset, length) in ranges {
            let mut from_slice = vec![0; length];
            let mut from_file = vec![0; length];
            let offset_u64 = u64::try_from(offset).expect("fixture offset fits in u64");
            slice_reader
                .read_exact_at(offset_u64, &mut from_slice)
                .unwrap();
            file_reader
                .read_exact_at(offset_u64, &mut from_file)
                .unwrap();

            assert_eq!(
                from_slice,
                expected[offset..offset + length],
                "{}",
                case.name
            );
            assert_eq!(from_file, from_slice, "{} at {offset}", case.name);
        }
    }
}

#[test]
fn defers_passphrase_authentication_until_a_page_is_read() {
    for case in FIXTURE_CASES {
        let reader = SqlCipherReader::open(
            SliceSource::new(case.encrypted),
            case.config(),
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
fn rejects_page_tampering_and_relocation_without_exposing_plaintext() {
    for case in FIXTURE_CASES {
        let iv_start = case.page_size - case.reserve_size;
        let hmac_start = iv_start + AES_BLOCK_SIZE;

        for index in [16, iv_start, hmac_start] {
            let mut tampered = case.encrypted.to_vec();
            tampered[index] ^= 1;
            let reader =
                SqlCipherReader::open(SliceSource::new(&tampered), case.config(), case.passphrase)
                    .unwrap();
            let mut output = vec![0xaa; case.page_size];

            let error = reader
                .read_page_into(NonZeroU32::new(1).unwrap(), &mut output)
                .unwrap_err();

            assert!(matches!(
                error,
                ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 1 })
            ));
            assert!(output.iter().all(|byte| *byte == 0));
        }

        let mut relocated = case.encrypted.to_vec();
        let second_page = relocated[case.page_size..2 * case.page_size].to_vec();
        relocated[2 * case.page_size..3 * case.page_size].copy_from_slice(&second_page);
        let reader =
            SqlCipherReader::open(SliceSource::new(&relocated), case.config(), case.passphrase)
                .unwrap();
        let mut output = vec![0xaa; case.page_size];

        let error = reader
            .read_page_into(NonZeroU32::new(3).unwrap(), &mut output)
            .unwrap_err();

        assert!(matches!(
            error,
            ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 3 })
        ));
        assert!(output.iter().all(|byte| *byte == 0));

        let mut tampered = case.encrypted.to_vec();
        tampered[case.page_size + 16] ^= 1;
        let reader =
            SqlCipherReader::open(SliceSource::new(&tampered), case.config(), case.passphrase)
                .unwrap();
        let mut output = vec![0xaa; 64];

        let error = reader
            .read_exact_at(
                u64::try_from(case.page_size - 32).expect("page offset fits in u64"),
                &mut output,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 2 })
        ));
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn ignores_sqlcipher3_unauthenticated_filler() {
    let case = SQLCIPHER3_CASE;
    let original_reader = case.reader();
    let mut tampered = case.encrypted.to_vec();

    for page in tampered.chunks_exact_mut(case.page_size) {
        let filler_start = page.len() - 12;
        page[filler_start] ^= 1;
        page[page.len() - 1] ^= 1;
    }

    let tampered_reader =
        SqlCipherReader::open(SliceSource::new(&tampered), case.config(), case.passphrase).unwrap();
    let mut expected = vec![0; case.page_size];
    let mut actual = vec![0; case.page_size];

    for page_no in 1..=original_reader.page_count() {
        let page_no = NonZeroU32::new(page_no).unwrap();
        original_reader
            .read_page_into(page_no, &mut expected)
            .unwrap();
        tampered_reader
            .read_page_into(page_no, &mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn queries_supported_fixtures_and_rejects_writes() {
    for case in FIXTURE_CASES {
        let connection = open_readonly(case.path(), case.config(), case.passphrase)
            .unwrap_or_else(|error| panic!("{} failed to open: {error}", case.name));

        let people = connection
            .query("SELECT id, name, note, score, active FROM people ORDER BY id")
            .unwrap_or_else(|error| panic!("{} people query failed: {error}", case.name));
        assert_eq!(people.columns, ["id", "name", "note", "score", "active"]);
        assert_eq!(
            people.rows,
            [
                vec![
                    Value::Integer(1),
                    Value::Text(b"Alice".to_vec()),
                    Value::Text(b"plain ASCII".to_vec()),
                    Value::Real(98.5),
                    Value::Integer(1),
                ],
                vec![
                    Value::Integer(2),
                    Value::Text("홍길동".as_bytes().to_vec()),
                    Value::Text("한국어, emoji 🔐, and 'quotes'".as_bytes().to_vec()),
                    Value::Real(-12.25),
                    Value::Integer(1),
                ],
                vec![
                    Value::Integer(3),
                    Value::Text(b"Null Tester".to_vec()),
                    Value::Null,
                    Value::Real(0.0),
                    Value::Integer(0),
                ],
            ],
            "{}",
            case.name
        );

        let binary_samples = connection
            .query("SELECT name, payload FROM binary_samples ORDER BY name")
            .unwrap_or_else(|error| panic!("{} blob query failed: {error}", case.name));
        assert_eq!(
            binary_samples.rows,
            [
                vec![
                    Value::Text(b"all-byte-edges".to_vec()),
                    Value::Blob(vec![
                        0x00, 0x01, 0x02, 0x03, 0x7f, 0x80, 0xfc, 0xfd, 0xfe, 0xff,
                    ]),
                ],
                vec![
                    Value::Text(b"large-zero-blob".to_vec()),
                    Value::Blob(vec![0; 10_000]),
                ],
            ],
            "{}",
            case.name
        );

        let error = connection
            .query("UPDATE people SET name = 'Mallory' WHERE id = 1")
            .unwrap_err();
        assert!(matches!(error, GraphiteAdapterError::Query { .. }));
    }
}
