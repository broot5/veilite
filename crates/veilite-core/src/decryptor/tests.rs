use std::num::NonZeroU32;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::*;
use crate::test_support::{
    FIXTURE_CASES, FixtureCase, FixtureCipher, PRESET_FIXTURE_CASES, SQLCIPHER_CUSTOM_CASE,
    SQLCIPHER3_CASE, SQLCIPHER4_CASE,
};

impl FixtureCase {
    fn page_decryptor(self) -> &'static PageDecryptor {
        match self.cipher {
            FixtureCipher::SqlCipher3 => sqlcipher3_page_decryptor(),
            FixtureCipher::SqlCipher4 => sqlcipher4_page_decryptor(),
            FixtureCipher::Custom => sqlcipher_custom_page_decryptor(),
        }
    }
}

fn sqlcipher_custom_page_decryptor() -> &'static PageDecryptor {
    static DECRYPTOR: OnceLock<PageDecryptor> = OnceLock::new();
    DECRYPTOR.get_or_init(|| fixture_page_decryptor(SQLCIPHER_CUSTOM_CASE))
}

fn sqlcipher3_page_decryptor() -> &'static PageDecryptor {
    static DECRYPTOR: OnceLock<PageDecryptor> = OnceLock::new();
    DECRYPTOR.get_or_init(|| fixture_page_decryptor(SQLCIPHER3_CASE))
}

fn sqlcipher4_page_decryptor() -> &'static PageDecryptor {
    static DECRYPTOR: OnceLock<PageDecryptor> = OnceLock::new();
    DECRYPTOR.get_or_init(|| fixture_page_decryptor(SQLCIPHER4_CASE))
}

fn fixture_page_decryptor(case: FixtureCase) -> PageDecryptor {
    let salt: &[u8; 16] = case.fixture[..16].try_into().expect("fixture has a salt");
    PageDecryptor::new(case.config(), case.passphrase, salt)
        .expect("fixture passphrase is non-empty")
}

fn decrypt_fixture_pages(
    decryptor: &PageDecryptor,
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let page_size = decryptor.page_size();
    let mut plaintext = Zeroizing::new(vec![0; encrypted.len()]);

    for (index, encrypted_page) in encrypted.chunks_exact(page_size).enumerate() {
        let page_no = NonZeroU32::new(u32::try_from(index + 1).expect("fixture page number fits"))
            .expect("fixture page numbers start at one");
        let start = index * page_size;
        decryptor.decrypt_page_into(
            page_no,
            encrypted_page,
            &mut plaintext[start..start + page_size],
        )?;
    }

    Ok(plaintext)
}

fn first_page_with_changed_header_byte(
    case: FixtureCase,
    header_offset: usize,
    original: u8,
    replacement: u8,
) -> Vec<u8> {
    assert!((16..32).contains(&header_offset));

    let decryptor = case.page_decryptor();
    let page_size = case.page_size;
    let mut page = case.fixture[..page_size].to_vec();
    let ciphertext_end = page_size - case.reserve_size;
    let iv_end = ciphertext_end + AES_BLOCK_SIZE;
    let hmac_end = iv_end + decryptor.config.hmac_algorithm().output_len();
    page[ciphertext_end + header_offset - 16] ^= original ^ replacement;

    match decryptor.config.hmac_algorithm() {
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
        HashAlgorithm::Sha256 => {
            let tag = hmac::Hmac::<Sha256>::new_from_slice(&decryptor.keys.hmac_key)
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
        let plaintext = decrypt_fixture_pages(case.page_decryptor(), case.fixture)
            .unwrap_or_else(|error| panic!("{:?}: {error}", case.cipher));
        let page_size = case.page_size;
        let reserve_size = case.reserve_size;

        assert_eq!(case.config().page_size(), page_size);
        assert_eq!(&plaintext[..16], SQLITE_HEADER_MAGIC);
        assert_eq!(
            u16::from_be_bytes([plaintext[16], plaintext[17]]),
            u16::try_from(page_size).expect("fixture page size fits in u16")
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
    let expected = decrypt_fixture_pages(sqlcipher3_page_decryptor(), SQLCIPHER3_CASE.fixture)
        .expect("fixture should decrypt");
    let mut tampered = SQLCIPHER3_CASE.fixture.to_vec();

    for page in tampered.chunks_exact_mut(SQLCIPHER3_CASE.page_size) {
        let filler_start = page.len() - 12;
        page[filler_start] ^= 1;
        page[page.len() - 1] ^= 1;
    }

    let actual = decrypt_fixture_pages(sqlcipher3_page_decryptor(), &tampered)
        .expect("unauthenticated filler should be ignored");

    assert_eq!(actual.as_slice(), expected.as_slice());
}

#[test]
fn rejects_tampering_in_ciphertext_iv_and_hmac() {
    for case in FIXTURE_CASES {
        let iv_start = case.page_size - case.reserve_size;
        let hmac_start = iv_start + AES_BLOCK_SIZE;

        for index in [16, iv_start, hmac_start] {
            let mut tampered = case.fixture[..case.page_size].to_vec();
            tampered[index] ^= 1;
            let mut output = vec![0; case.page_size];
            assert_eq!(
                case.page_decryptor()
                    .decrypt_page_into(NonZeroU32::new(1).unwrap(), &tampered, &mut output)
                    .unwrap_err(),
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
            case.page_decryptor()
                .decrypt_page_into(NonZeroU32::new(3).unwrap(), second_page, &mut output)
                .unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 3 }
        );
    }
}

#[test]
fn rejects_invalid_page_buffer_lengths() {
    for case in PRESET_FIXTURE_CASES {
        let page_size = case.page_size;
        let mut output = vec![0_u8; page_size];
        assert_eq!(
            case.page_decryptor()
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
            case.page_decryptor()
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
fn rejects_empty_passphrase() {
    for case in PRESET_FIXTURE_CASES {
        let salt: &[u8; 16] = case.fixture[..16].try_into().unwrap();

        assert!(matches!(
            PageDecryptor::new(case.config(), b"", salt),
            Err(DecryptError::EmptyPassphrase)
        ));
    }
}

#[test]
fn derives_a_sha256_key_from_a_known_answer() {
    let mut actual = [0; 32];
    PageDecryptor::derive_key_into(HashAlgorithm::Sha256, b"password", b"salt", 1, &mut actual);
    let expected = [
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8,
        0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    ];

    assert_eq!(actual, expected);
}

#[test]
fn verifies_a_sha256_page_hmac_from_a_known_answer() {
    let config = CipherConfig::new(1024, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap();
    let salt = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let decryptor = PageDecryptor::new(config, b"password", &salt).unwrap();
    let iv: [u8; 16] = std::array::from_fn(|index| u8::try_from(index + 16).unwrap());
    let stored_hmac = [
        0xed, 0xc3, 0x46, 0x9a, 0xd1, 0x18, 0x1f, 0x7c, 0x31, 0x14, 0xfe, 0x0d, 0x19, 0x30, 0x34,
        0xf2, 0xca, 0x32, 0x88, 0x8d, 0x87, 0xb8, 0x7e, 0x47, 0x31, 0xa7, 0x43, 0x08, 0xf6, 0x74,
        0x8e, 0xdb,
    ];

    decryptor
        .verify_page_hmac(b"ciphertext", &iv, 7, &stored_hmac)
        .unwrap();
}

#[test]
fn uses_the_kdf_algorithm_for_both_keys_independently_of_the_hmac_algorithm() {
    let salt = [0x42; 16];
    let sha1_hmac = PageDecryptor::new(
        CipherConfig::new(1024, 2, HashAlgorithm::Sha256, HashAlgorithm::Sha1).unwrap(),
        b"passphrase",
        &salt,
    )
    .unwrap();
    let sha512_hmac = PageDecryptor::new(
        CipherConfig::new(1024, 2, HashAlgorithm::Sha256, HashAlgorithm::Sha512).unwrap(),
        b"passphrase",
        &salt,
    )
    .unwrap();
    let sha1_kdf = PageDecryptor::new(
        CipherConfig::new(1024, 2, HashAlgorithm::Sha1, HashAlgorithm::Sha256).unwrap(),
        b"passphrase",
        &salt,
    )
    .unwrap();

    assert_eq!(
        sha1_hmac.keys.encryption_key,
        sha512_hmac.keys.encryption_key
    );
    assert_eq!(sha1_hmac.keys.hmac_key, sha512_hmac.keys.hmac_key);
    assert_ne!(sha1_hmac.keys.encryption_key, sha1_kdf.keys.encryption_key);
    assert_ne!(sha1_hmac.keys.hmac_key, sha1_kdf.keys.hmac_key);
}

#[test]
fn decodes_sqlite_page_size_header_encoding() {
    for (encoded, expected) in [
        ([0x00, 0x01], 65_536),
        ([0x04, 0x00], 1024),
        ([0x10, 0x00], 4096),
    ] {
        assert_eq!(decode_sqlite_page_size(encoded), expected);
    }
}

#[test]
fn rejects_mismatched_sqlite_header_fields() {
    for (case, other) in [
        (PRESET_FIXTURE_CASES[0], PRESET_FIXTURE_CASES[1]),
        (PRESET_FIXTURE_CASES[1], PRESET_FIXTURE_CASES[0]),
    ] {
        let encoded_page_size = u16::try_from(case.page_size)
            .expect("fixture page size fits in u16")
            .to_be_bytes();
        let other_encoded_page_size = u16::try_from(other.page_size)
            .expect("fixture page size fits in u16")
            .to_be_bytes();
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
                    u8::try_from(case.reserve_size).expect("fixture reserve size fits in u8"),
                    u8::try_from(other.reserve_size).expect("fixture reserve size fits in u8"),
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
                .page_decryptor()
                .decrypt_page_into(NonZeroU32::new(1).unwrap(), &page, &mut output)
                .unwrap_err();

            assert_eq!(error, expected_error);
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}
