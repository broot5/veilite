mod common;

use common::{FIXTURE_CASES, FixtureCase, FixtureCipher, SQLCIPHER3_CASE};
use std::{num::NonZeroU32, path::PathBuf};
use veilite_core::{DecryptError, FileSource, ReaderError, SliceSource, SqlCipherReader};

const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;

impl FixtureCase {
    fn path(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(self.name)
            .join("encrypted.db")
    }

    fn reserve_size(self) -> usize {
        match self.cipher {
            FixtureCipher::SqlCipher3 | FixtureCipher::Custom => 48,
            FixtureCipher::SqlCipher4 => 80,
        }
    }
}

#[test]
fn page_source_and_sqlite_reader_preserve_authentication_failures() {
    for case in FIXTURE_CASES {
        let context = case.name;
        let pages = SqlCipherReader::open(
            SliceSource::new(case.encrypted),
            case.config(),
            b"wrong passphrase",
        )
        .unwrap();
        let mut output = vec![0xaa; case.page_size];
        let error = sqlite_reader::PageSource::read_page_into(&pages, NonZeroU32::MIN, &mut output)
            .unwrap_err();
        assert!(
            matches!(
                error,
                ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 1 })
            ),
            "{context}: {error:?}"
        );
        assert!(
            output.iter().all(|byte| *byte == 0),
            "{context}: output not cleared"
        );
        assert!(
            matches!(
                sqlite_reader::Reader::open(pages),
                Err(sqlite_reader::ReaderError::Source(ReaderError::Decrypt(
                    DecryptError::AuthenticationFailed { page_no: 1 }
                )))
            ),
            "{context}: SQLite reader did not preserve page 1 authentication failure"
        );

        let reader = sqlite_reader::Reader::open(case.reader()).unwrap();
        let index_page = reader
            .index("people_name_idx")
            .unwrap()
            .schema_object()
            .root_page;
        let last_page = u32::try_from(case.encrypted.len() / case.page_size).unwrap();
        // The final page belongs to the large BLOB's overflow chain. Reading
        // earlier rows succeeds, but no partial large row may escape.
        for page in [index_page, last_page] {
            let context = format!("{} corrupted page {page}", case.name);
            let mut bytes = case.encrypted.to_vec();
            bytes[(page as usize - 1) * case.page_size + 16] ^= 1;
            let pages =
                SqlCipherReader::open(SliceSource::new(&bytes), case.config(), case.passphrase)
                    .unwrap();
            output.fill(0xaa);
            sqlite_reader::PageSource::read_page_into(
                &pages,
                NonZeroU32::new(page).unwrap(),
                &mut output,
            )
            .unwrap_err();
            assert!(
                output.iter().all(|byte| *byte == 0),
                "{context}: output not cleared"
            );
            let reader = sqlite_reader::Reader::open(pages).unwrap();
            let error = if page == index_page {
                let index = reader.index("people_name_idx").unwrap();
                let mut entries = index.entries();
                let error = entries.next().unwrap().unwrap_err();
                assert!(
                    entries.next().is_none(),
                    "{context}: index iterator not terminated"
                );
                error
            } else {
                let table = reader.table("binary_samples").unwrap();
                let mut rows = table.rows();
                assert!(
                    rows.next().unwrap().is_ok(),
                    "{context}: preceding row failed"
                );
                let error = rows.next().unwrap().unwrap_err();
                assert!(
                    rows.next().is_none(),
                    "{context}: row iterator not terminated"
                );
                error
            };
            assert!(
                matches!(error,
                    sqlite_reader::ReaderError::Source(ReaderError::Decrypt(
                        DecryptError::AuthenticationFailed { page_no }
                    )) if page_no == page
                ),
                "{context}: {error:?}"
            );
        }
    }
}

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
                page[case.page_size - case.reserve_size()..]
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
        assert_eq!(usize::from(page[20]), case.reserve_size(), "{}", case.name);
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
        let context = case.name;
        let slice_reader = case.reader();
        let file_reader = SqlCipherReader::open(
            FileSource::open(case.path())
                .unwrap_or_else(|error| panic!("{context} file source: {error}")),
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
            (0, case.page_size),
            (case.page_size, case.page_size),
            (case.encrypted.len() - case.page_size, case.page_size),
            (1, case.page_size),
            (0, 100),
            (case.page_size / 2, 200),
            (case.page_size - 31, 97),
            (case.page_size * 2 - 7, case.page_size + 23),
            (case.encrypted.len() - 1, 1),
        ];

        for (offset, length) in ranges {
            let context = format!("{} offset {offset}, length {length}", case.name);
            let mut from_slice = vec![0; length];
            let mut from_file = vec![0; length];
            let offset_u64 = u64::try_from(offset).expect("fixture offset fits in u64");
            slice_reader
                .read_exact_at(offset_u64, &mut from_slice)
                .unwrap_or_else(|error| panic!("{context} slice read: {error}"));
            file_reader
                .read_exact_at(offset_u64, &mut from_file)
                .unwrap_or_else(|error| panic!("{context} file read: {error}"));

            assert_eq!(from_slice, expected[offset..offset + length], "{context}");
            assert_eq!(from_file, from_slice, "{context}");
        }
    }
}

#[test]
fn rejects_page_tampering_and_relocation_without_exposing_plaintext() {
    for case in FIXTURE_CASES {
        let context = case.name;
        let iv_start = case.page_size - case.reserve_size();
        let hmac_start = iv_start + AES_BLOCK_SIZE;

        for index in [16, iv_start, hmac_start] {
            let context = format!("{} tampered byte {index}, page 1", case.name);
            let mut tampered = case.encrypted.to_vec();
            tampered[index] ^= 1;
            let reader =
                SqlCipherReader::open(SliceSource::new(&tampered), case.config(), case.passphrase)
                    .unwrap();
            let mut output = vec![0xaa; case.page_size];

            let error = reader.read_exact_at(0, &mut output).unwrap_err();

            assert!(
                matches!(
                    error,
                    ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 1 })
                ),
                "{context}: {error:?}"
            );
            assert!(
                output.iter().all(|byte| *byte == 0),
                "{context}: output not cleared"
            );
        }

        let mut relocated = case.encrypted.to_vec();
        let second_page = relocated[case.page_size..2 * case.page_size].to_vec();
        relocated[2 * case.page_size..3 * case.page_size].copy_from_slice(&second_page);
        let reader =
            SqlCipherReader::open(SliceSource::new(&relocated), case.config(), case.passphrase)
                .unwrap();
        let mut output = vec![0xaa; case.page_size];

        let error = reader
            .read_exact_at(u64::try_from(2 * case.page_size).unwrap(), &mut output)
            .unwrap_err();

        assert!(
            matches!(
                error,
                ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 3 })
            ),
            "{context}: {error:?}"
        );
        assert!(
            output.iter().all(|byte| *byte == 0),
            "{context}: output not cleared"
        );

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

        assert!(
            matches!(
                error,
                ReaderError::Decrypt(DecryptError::AuthenticationFailed { page_no: 2 })
            ),
            "{context}: {error:?}"
        );
        assert!(
            output.iter().all(|byte| *byte == 0),
            "{context}: output not cleared"
        );
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
        assert_eq!(actual, expected, "{} filler, page {page_no}", case.name);
    }
}
