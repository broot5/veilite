use std::num::NonZeroU32;
use std::sync::OnceLock;

use super::*;

const SQLCIPHER3_FIXTURE: &[u8] = include_bytes!("../../fixtures/sqlcipher3/encrypted.db");
const SQLCIPHER3_PASSPHRASE: &[u8] = b"veilite-sqlcipher3-test-key";
const SQLCIPHER4_FIXTURE: &[u8] = include_bytes!("../../fixtures/sqlcipher4/encrypted.db");
const SQLCIPHER4_PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";

#[derive(Clone, Copy)]
struct FixtureCase {
    profile: CompatibilityProfile,
    fixture: &'static [u8],
    page_size: usize,
    reserve_size: usize,
}

const FIXTURE_CASES: [FixtureCase; 2] = [
    FixtureCase {
        profile: CompatibilityProfile::SqlCipher3,
        fixture: SQLCIPHER3_FIXTURE,
        page_size: 1024,
        reserve_size: 48,
    },
    FixtureCase {
        profile: CompatibilityProfile::SqlCipher4,
        fixture: SQLCIPHER4_FIXTURE,
        page_size: 4096,
        reserve_size: 80,
    },
];

impl FixtureCase {
    fn decryptor(self) -> &'static Decryptor {
        match self.profile {
            CompatibilityProfile::SqlCipher3 => sqlcipher3_decryptor(),
            CompatibilityProfile::SqlCipher4 => sqlcipher4_decryptor(),
        }
    }
}

fn sqlcipher3_decryptor() -> &'static Decryptor {
    static DECRYPTOR: OnceLock<Decryptor> = OnceLock::new();
    DECRYPTOR.get_or_init(|| {
        let salt: &[u8; 16] = SQLCIPHER3_FIXTURE[..16]
            .try_into()
            .expect("fixture has a salt");
        Decryptor::new(
            CompatibilityProfile::SqlCipher3,
            SQLCIPHER3_PASSPHRASE,
            salt,
        )
        .expect("fixture passphrase is non-empty")
    })
}

fn sqlcipher4_decryptor() -> &'static Decryptor {
    static DECRYPTOR: OnceLock<Decryptor> = OnceLock::new();
    DECRYPTOR.get_or_init(|| {
        let salt: &[u8; 16] = SQLCIPHER4_FIXTURE[..16]
            .try_into()
            .expect("fixture has a salt");
        Decryptor::new(
            CompatibilityProfile::SqlCipher4,
            SQLCIPHER4_PASSPHRASE,
            salt,
        )
        .expect("fixture passphrase is non-empty")
    })
}

fn first_page_with_changed_header_byte(
    case: FixtureCase,
    header_offset: usize,
    original: u8,
    replacement: u8,
) -> Vec<u8> {
    assert!((16..32).contains(&header_offset));

    let decryptor = case.decryptor();
    let page_size = case.page_size;
    let mut page = case.fixture[..page_size].to_vec();
    let ciphertext_end = page_size - case.reserve_size;
    let iv_end = ciphertext_end + AES_BLOCK_SIZE;
    let hmac_end = iv_end + decryptor.params.hmac_algorithm.output_len();
    page[ciphertext_end + header_offset - 16] ^= original ^ replacement;

    match decryptor.params.hmac_algorithm {
        HashAlgorithm::Sha1 => {
            let tag = hmac::Hmac::<Sha1>::new_from_slice(&decryptor.keys.hmac_key)
                .unwrap()
                .chain_update(&page[16..ciphertext_end])
                .chain_update(&page[ciphertext_end..iv_end])
                .chain_update(1_u32.to_le_bytes())
                .finalize()
                .into_bytes();
            page[iv_end..hmac_end].copy_from_slice(&tag);
        }
        HashAlgorithm::Sha512 => {
            let tag = hmac::Hmac::<Sha512>::new_from_slice(&decryptor.keys.hmac_key)
                .unwrap()
                .chain_update(&page[16..ciphertext_end])
                .chain_update(&page[ciphertext_end..iv_end])
                .chain_update(1_u32.to_le_bytes())
                .finalize()
                .into_bytes();
            page[iv_end..hmac_end].copy_from_slice(&tag);
        }
    }
    page
}

#[test]
fn decrypts_supported_fixtures() {
    for case in FIXTURE_CASES {
        let plaintext = case
            .decryptor()
            .decrypt_database(case.fixture)
            .unwrap_or_else(|error| panic!("{:?}: {error}", case.profile));
        let page_size = case.page_size;
        let reserve_size = case.reserve_size;

        assert_eq!(case.decryptor().page_size(), page_size);
        assert_eq!(case.profile.page_size(), page_size);
        assert_eq!(plaintext.len(), case.fixture.len());
        assert_eq!(&plaintext[..16], SQLITE_HEADER_MAGIC);
        assert_eq!(
            u16::from_be_bytes([plaintext[16], plaintext[17]]),
            page_size as u16
        );
        assert_eq!(usize::from(plaintext[20]), reserve_size);
        assert_eq!(
            u32::from_be_bytes(plaintext[60..64].try_into().unwrap()),
            42
        );
        assert_eq!(
            u32::from_be_bytes(plaintext[68..72].try_into().unwrap()),
            0x5645_4c49
        );
        assert!(plaintext.chunks_exact(page_size).all(|page| {
            page[page_size - reserve_size..]
                .iter()
                .all(|byte| *byte == 0)
        }));
    }
}

#[test]
fn ignores_unauthenticated_sqlcipher3_filler() {
    let expected = sqlcipher3_decryptor()
        .decrypt_database(SQLCIPHER3_FIXTURE)
        .expect("fixture should decrypt");
    let mut tampered = SQLCIPHER3_FIXTURE.to_vec();

    for page in tampered.chunks_exact_mut(FIXTURE_CASES[0].page_size) {
        let filler_start = page.len() - 12;
        page[filler_start] ^= 1;
        page[page.len() - 1] ^= 1;
    }

    let actual = sqlcipher3_decryptor()
        .decrypt_database(&tampered)
        .expect("unauthenticated filler should be ignored");

    assert_eq!(actual.as_slice(), expected.as_slice());
}

#[test]
fn rejects_wrong_passphrase() {
    for case in FIXTURE_CASES {
        let salt: &[u8; 16] = case.fixture[..16].try_into().unwrap();
        let wrong = Decryptor::new(case.profile, b"wrong passphrase", salt).unwrap();

        assert_eq!(
            wrong.decrypt_database(case.fixture).unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 1 }
        );
    }
}

#[test]
fn rejects_tampering_in_ciphertext_iv_and_hmac() {
    for case in FIXTURE_CASES {
        let iv_start = case.page_size - case.reserve_size;
        let hmac_start = iv_start + AES_BLOCK_SIZE;

        for index in [16, iv_start, hmac_start] {
            let mut tampered = case.fixture.to_vec();
            tampered[index] ^= 1;
            assert_eq!(
                case.decryptor().decrypt_database(&tampered).unwrap_err(),
                DecryptError::AuthenticationFailed { page_no: 1 }
            );
        }
    }
}

#[test]
fn page_number_is_authenticated() {
    for case in FIXTURE_CASES {
        let page_size = case.page_size;
        let second_page = &case.fixture[page_size..2 * page_size];
        let mut output = vec![0_u8; page_size];

        assert_eq!(
            case.decryptor()
                .decrypt_page_into(NonZeroU32::new(3).unwrap(), second_page, &mut output)
                .unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 3 }
        );
    }
}

#[test]
fn validates_page_buffer_sizes() {
    for case in FIXTURE_CASES {
        let page_size = case.page_size;
        let mut output = vec![0_u8; page_size];
        assert_eq!(
            case.decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &case.fixture[..page_size - 1],
                    &mut output,
                )
                .unwrap_err(),
            DecryptError::InvalidEncryptedPageLength {
                expected: page_size,
                actual: page_size - 1,
            }
        );

        let mut short_output = vec![0_u8; page_size - 1];
        assert_eq!(
            case.decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &case.fixture[..page_size],
                    &mut short_output,
                )
                .unwrap_err(),
            DecryptError::InvalidOutputPageLength {
                expected: page_size,
                actual: page_size - 1,
            }
        );
    }
}

#[test]
fn clears_reserved_output_bytes() {
    for case in FIXTURE_CASES {
        let page_size = case.page_size;
        let reserve_size = case.reserve_size;
        let mut output = vec![0xaa; page_size];
        case.decryptor()
            .decrypt_page_into(
                NonZeroU32::new(1).unwrap(),
                &case.fixture[..page_size],
                &mut output,
            )
            .unwrap();

        assert!(
            output[page_size - reserve_size..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }
}

#[test]
fn rejects_empty_and_incomplete_databases() {
    for case in FIXTURE_CASES {
        assert_eq!(
            case.decryptor().decrypt_database(&[]).unwrap_err(),
            DecryptError::EmptyDatabase
        );
        assert_eq!(
            case.decryptor()
                .decrypt_database(&case.fixture[..case.fixture.len() - 1])
                .unwrap_err(),
            DecryptError::IncompletePage {
                file_size: case.fixture.len() - 1,
                page_size: case.page_size,
            }
        );
    }
}

#[test]
fn rejects_empty_passphrase() {
    for case in FIXTURE_CASES {
        let salt: &[u8; 16] = case.fixture[..16].try_into().unwrap();

        assert!(matches!(
            Decryptor::new(case.profile, b"", salt),
            Err(DecryptError::EmptyPassphrase)
        ));
    }
}

#[test]
fn validates_decrypted_sqlite_header() {
    for (case, other) in [
        (FIXTURE_CASES[0], FIXTURE_CASES[1]),
        (FIXTURE_CASES[1], FIXTURE_CASES[0]),
    ] {
        let encoded_page_size = (case.page_size as u16).to_be_bytes();
        let other_encoded_page_size = (other.page_size as u16).to_be_bytes();
        let cases = [
            (
                first_page_with_changed_header_byte(
                    case,
                    16,
                    encoded_page_size[0],
                    other_encoded_page_size[0],
                ),
                DecryptError::InvalidSqlitePageSize {
                    expected: case.page_size,
                    actual: other.page_size,
                },
            ),
            (
                first_page_with_changed_header_byte(
                    case,
                    20,
                    case.reserve_size as u8,
                    other.reserve_size as u8,
                ),
                DecryptError::InvalidSqliteReserveSize {
                    expected: case.reserve_size,
                    actual: other.reserve_size,
                },
            ),
        ];

        for (page, expected_error) in cases {
            let mut output = vec![0xaa; case.page_size];
            let error = case
                .decryptor()
                .decrypt_page_into(NonZeroU32::new(1).unwrap(), &page, &mut output)
                .unwrap_err();

            assert_eq!(error, expected_error);
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}
