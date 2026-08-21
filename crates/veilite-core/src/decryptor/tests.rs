use std::num::NonZeroU32;

use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{KeyInit, Mac};

use super::*;

#[test]
fn rejects_empty_passphrase() {
    for config in [
        CipherConfig::from(crate::CipherPreset::SqlCipher3),
        CipherConfig::from(crate::CipherPreset::SqlCipher4),
    ] {
        assert!(matches!(
            PageDecryptor::new(config, b"", &[0x42; 16]),
            Err(DecryptError::EmptyPassphrase)
        ));
    }
}

#[test]
fn rejects_all_zero_physical_pages() {
    for config in [
        CipherConfig::from(crate::CipherPreset::SqlCipher3),
        CipherConfig::from(crate::CipherPreset::SqlCipher4),
    ] {
        let decryptor = PageDecryptor::new(config, b"passphrase", &[0x42; 16]).unwrap();
        let mut page = vec![0; config.page_size()];

        let error = decryptor
            .decrypt_page_in_place(NonZeroU32::new(1).unwrap(), &mut page)
            .unwrap_err();

        assert_eq!(error, DecryptError::AuthenticationFailed { page_no: 1 });
        assert!(page.iter().all(|byte| *byte == 0));
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
fn rejects_authenticated_pages_with_mismatched_sqlite_header_fields() {
    let config = CipherConfig::new(1024, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap();
    let decryptor = PageDecryptor::new(config, b"passphrase", &[0x42; 16]).unwrap();
    let cases = [
        (
            authenticated_first_page(
                &decryptor,
                [0x10, 0x00],
                u8::try_from(config.reserve_size()).expect("reserve size fits in u8"),
            ),
            DecryptError::InvalidSqlitePageSize {
                expected: 1024,
                actual: 4096,
            },
        ),
        (
            authenticated_first_page(&decryptor, [0x04, 0x00], 80),
            DecryptError::InvalidSqliteReserveSize {
                expected: config.reserve_size(),
                actual: 80,
            },
        ),
    ];

    for (mut page, expected_error) in cases {
        let error = decryptor
            .decrypt_page_in_place(NonZeroU32::new(1).unwrap(), &mut page)
            .unwrap_err();

        assert_eq!(error, expected_error);
        assert!(page.iter().all(|byte| *byte == 0));
    }
}

fn authenticated_first_page(
    decryptor: &PageDecryptor,
    sqlite_page_size: [u8; 2],
    sqlite_reserve_size: u8,
) -> Vec<u8> {
    let config = decryptor.config;
    let ciphertext_end = config.usable_end();
    let iv_end = ciphertext_end + AES_BLOCK_SIZE;
    let hmac_end = iv_end + HashAlgorithm::Sha256.output_len();
    let iv = [0x24; AES_BLOCK_SIZE];
    let mut page = vec![0; config.page_size()];
    page[16..18].copy_from_slice(&sqlite_page_size);
    page[20] = sqlite_reserve_size;
    page[ciphertext_end..iv_end].copy_from_slice(&iv);

    let plaintext_len = ciphertext_end - 16;
    cbc::Encryptor::<aes::Aes256>::new((&decryptor.keys.encryption_key).into(), (&iv).into())
        .encrypt_padded::<NoPadding>(&mut page[16..ciphertext_end], plaintext_len)
        .expect("validated first-page plaintext is AES block-aligned");

    let tag = hmac::Hmac::<sha2::Sha256>::new_from_slice(&decryptor.keys.hmac_key)
        .expect("HMAC accepts keys of any length")
        .chain_update(&page[16..ciphertext_end])
        .chain_update(iv)
        .chain_update(1_u32.to_le_bytes())
        .finalize()
        .into_bytes();
    page[iv_end..hmac_end].copy_from_slice(&tag);
    page
}
