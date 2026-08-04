use std::fmt;
use std::num::NonZeroU32;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;
pub const SQLCIPHER4_PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
struct CipherParams {
    page_size: usize,
    kdf_iter: u32,
    reserve_size: usize,
    iv_size: usize,
    hmac_size: usize,
}

impl CipherParams {
    const SQLCIPHER4: Self = Self {
        page_size: SQLCIPHER4_PAGE_SIZE,
        kdf_iter: 256_000,
        reserve_size: 80,
        iv_size: 16,
        hmac_size: 64,
    };
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
}

pub struct Decryptor {
    params: CipherParams,
    keys: KeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    EmptyDatabase,
    InvalidInputPageSize { expected: usize, actual: usize },
    InvalidOutputPageSize { expected: usize, actual: usize },
    AuthenticationFailed { page_no: u32 },
    InvalidCiphertextLength { page_no: u32 },
    IncompletePage { file_size: usize, page_size: usize },
    TooManyPages { page_count: usize },
    CryptoInitializationFailed,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatabase => write!(f, "the encrypted database is empty"),
            Self::InvalidInputPageSize { expected, actual } => write!(
                f,
                "invalid encrypted page size: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidOutputPageSize { expected, actual } => write!(
                f,
                "invalid output page size: expected {expected} bytes, got {actual}"
            ),
            Self::AuthenticationFailed { page_no } => write!(
                f,
                "authentication failed for page {page_no}: wrong passphrase or corrupted data"
            ),
            Self::InvalidCiphertextLength { page_no } => {
                write!(f, "ciphertext on page {page_no} is not AES block-aligned")
            }
            Self::IncompletePage {
                file_size,
                page_size,
            } => write!(
                f,
                "database size {file_size} is not a multiple of page size {page_size}"
            ),
            Self::TooManyPages { page_count } => {
                write!(f, "database has too many pages: {page_count}")
            }
            Self::CryptoInitializationFailed => {
                write!(f, "failed to initialize a cryptographic primitive")
            }
        }
    }
}

impl std::error::Error for DecryptError {}

impl Decryptor {
    pub fn new_sqlcipher4(passphrase: &[u8], salt: &[u8; 16]) -> Self {
        let params = CipherParams::SQLCIPHER4;
        let encryption_key = pbkdf2_hmac_array::<Sha512, 32>(passphrase, salt, params.kdf_iter);
        let hmac_salt: [u8; 16] = std::array::from_fn(|index| salt[index] ^ 0x3a);
        let hmac_key = pbkdf2_hmac_array::<Sha512, 32>(&encryption_key, &hmac_salt, 2);

        Self {
            params,
            keys: KeyMaterial {
                encryption_key,
                hmac_key,
            },
        }
    }

    pub fn page_size(&self) -> usize {
        self.params.page_size
    }

    pub fn decrypt_page_into(
        &self,
        page_no: NonZeroU32,
        encrypted_page: &[u8],
        output: &mut [u8],
    ) -> Result<(), DecryptError> {
        let expected = self.params.page_size;
        if encrypted_page.len() != expected {
            return Err(DecryptError::InvalidInputPageSize {
                expected,
                actual: encrypted_page.len(),
            });
        }
        if output.len() != expected {
            return Err(DecryptError::InvalidOutputPageSize {
                expected,
                actual: output.len(),
            });
        }

        output.fill(0);

        let page_no_u32 = page_no.get();
        let offset = if page_no_u32 == 1 { 16 } else { 0 };
        let ciphertext_len = self.params.page_size - offset - self.params.reserve_size;
        if !ciphertext_len.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(DecryptError::InvalidCiphertextLength {
                page_no: page_no_u32,
            });
        }

        let ciphertext_end = offset + ciphertext_len;
        let iv_end = ciphertext_end + self.params.iv_size;
        let hmac_end = iv_end + self.params.hmac_size;

        let ciphertext = &encrypted_page[offset..ciphertext_end];
        let iv = &encrypted_page[ciphertext_end..iv_end];
        let stored_hmac = &encrypted_page[iv_end..hmac_end];

        let mac = hmac::Hmac::<Sha512>::new_from_slice(&self.keys.hmac_key)
            .map_err(|_| DecryptError::CryptoInitializationFailed)?
            .chain_update(ciphertext)
            .chain_update(iv)
            .chain_update(page_no_u32.to_le_bytes());

        mac.verify_slice(stored_hmac)
            .map_err(|_| DecryptError::AuthenticationFailed {
                page_no: page_no_u32,
            })?;

        let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.keys.encryption_key, iv)
            .map_err(|_| DecryptError::CryptoInitializationFailed)?;

        if cipher
            .decrypt_padded_b2b::<NoPadding>(ciphertext, &mut output[offset..ciphertext_end])
            .is_err()
        {
            output.zeroize();
            return Err(DecryptError::InvalidCiphertextLength {
                page_no: page_no_u32,
            });
        }

        if page_no_u32 == 1 {
            output[..SQLITE_HEADER.len()].copy_from_slice(SQLITE_HEADER);
        }

        Ok(())
    }

    pub fn decrypt_database(&self, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
        if encrypted.is_empty() {
            return Err(DecryptError::EmptyDatabase);
        }

        let page_size = self.params.page_size;
        if !encrypted.len().is_multiple_of(page_size) {
            return Err(DecryptError::IncompletePage {
                file_size: encrypted.len(),
                page_size,
            });
        }

        let page_count = encrypted.len() / page_size;
        let max_page_count = (u32::MAX - 1) as usize;
        if page_count > max_page_count {
            return Err(DecryptError::TooManyPages { page_count });
        }

        let mut output = Zeroizing::new(vec![0; encrypted.len()]);
        for (index, encrypted_page) in encrypted.chunks_exact(page_size).enumerate() {
            let page_no_u32 =
                u32::try_from(index + 1).map_err(|_| DecryptError::TooManyPages { page_count })?;
            let page_no =
                NonZeroU32::new(page_no_u32).ok_or(DecryptError::TooManyPages { page_count })?;
            let start = index * page_size;

            self.decrypt_page_into(
                page_no,
                encrypted_page,
                &mut output[start..start + page_size],
            )?;
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::OnceLock;

    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../fixtures/sqlcipher4/encrypted.db");
    const PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";

    fn decryptor() -> &'static Decryptor {
        static DECRYPTOR: OnceLock<Decryptor> = OnceLock::new();
        DECRYPTOR.get_or_init(|| {
            let salt: &[u8; 16] = FIXTURE[..16].try_into().expect("fixture has a salt");
            Decryptor::new_sqlcipher4(PASSPHRASE, salt)
        })
    }

    #[test]
    fn decrypts_complete_fixture() {
        let plaintext = decryptor()
            .decrypt_database(FIXTURE)
            .expect("fixture should decrypt");

        assert_eq!(plaintext.len(), FIXTURE.len());
        assert_eq!(&plaintext[..16], SQLITE_HEADER);
        assert_eq!(u16::from_be_bytes([plaintext[16], plaintext[17]]), 4096);
        assert_eq!(plaintext[20], 80);
        assert_eq!(
            u32::from_be_bytes(plaintext[60..64].try_into().unwrap()),
            42
        );
        assert_eq!(
            u32::from_be_bytes(plaintext[68..72].try_into().unwrap()),
            0x5645_4c49
        );
    }

    #[test]
    fn rejects_wrong_passphrase() {
        let salt: &[u8; 16] = FIXTURE[..16].try_into().unwrap();
        let wrong = Decryptor::new_sqlcipher4(b"wrong passphrase", salt);

        assert_eq!(
            wrong.decrypt_database(FIXTURE).unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 1 }
        );
    }

    #[test]
    fn rejects_tampering_in_ciphertext_iv_and_hmac() {
        for index in [16, 4016, 4032] {
            let mut tampered = FIXTURE.to_vec();
            tampered[index] ^= 1;
            assert_eq!(
                decryptor().decrypt_database(&tampered).unwrap_err(),
                DecryptError::AuthenticationFailed { page_no: 1 }
            );
        }
    }

    #[test]
    fn page_number_is_authenticated() {
        let second_page = &FIXTURE[SQLCIPHER4_PAGE_SIZE..2 * SQLCIPHER4_PAGE_SIZE];
        let mut output = [0_u8; SQLCIPHER4_PAGE_SIZE];

        assert_eq!(
            decryptor()
                .decrypt_page_into(NonZeroU32::new(3).unwrap(), second_page, &mut output)
                .unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 3 }
        );
    }

    #[test]
    fn validates_page_buffer_sizes() {
        let mut output = [0_u8; SQLCIPHER4_PAGE_SIZE];
        assert_eq!(
            decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &FIXTURE[..SQLCIPHER4_PAGE_SIZE - 1],
                    &mut output,
                )
                .unwrap_err(),
            DecryptError::InvalidInputPageSize {
                expected: SQLCIPHER4_PAGE_SIZE,
                actual: SQLCIPHER4_PAGE_SIZE - 1,
            }
        );

        let mut short_output = [0_u8; SQLCIPHER4_PAGE_SIZE - 1];
        assert_eq!(
            decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &FIXTURE[..SQLCIPHER4_PAGE_SIZE],
                    &mut short_output,
                )
                .unwrap_err(),
            DecryptError::InvalidOutputPageSize {
                expected: SQLCIPHER4_PAGE_SIZE,
                actual: SQLCIPHER4_PAGE_SIZE - 1,
            }
        );
    }

    #[test]
    fn clears_reserved_output_bytes() {
        let mut output = [0xaa; SQLCIPHER4_PAGE_SIZE];
        decryptor()
            .decrypt_page_into(
                NonZeroU32::new(1).unwrap(),
                &FIXTURE[..SQLCIPHER4_PAGE_SIZE],
                &mut output,
            )
            .unwrap();

        assert!(
            output[SQLCIPHER4_PAGE_SIZE - 80..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn rejects_empty_and_incomplete_databases() {
        assert_eq!(
            decryptor().decrypt_database(&[]).unwrap_err(),
            DecryptError::EmptyDatabase
        );
        assert_eq!(
            decryptor()
                .decrypt_database(&FIXTURE[..FIXTURE.len() - 1])
                .unwrap_err(),
            DecryptError::IncompletePage {
                file_size: FIXTURE.len() - 1,
                page_size: SQLCIPHER4_PAGE_SIZE,
            }
        );
    }
}
