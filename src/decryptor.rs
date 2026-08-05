use std::fmt;
use std::num::NonZeroU32;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::profile::{CipherParams, CompatibilityProfile, HashAlgorithm};

const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;

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
    EmptyPassphrase,
    EmptyDatabase,
    InvalidEncryptedPageLength { expected: usize, actual: usize },
    InvalidOutputPageLength { expected: usize, actual: usize },
    InvalidSqlitePageSize { expected: usize, actual: usize },
    InvalidSqliteReserveSize { expected: usize, actual: usize },
    AuthenticationFailed { page_no: u32 },
    InvalidCiphertextLength { page_no: u32 },
    IncompletePage { file_size: usize, page_size: usize },
    TooManyPages { page_count: usize },
    CryptoInitializationFailed,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassphrase => write!(f, "the passphrase is empty"),
            Self::EmptyDatabase => write!(f, "the encrypted database is empty"),
            Self::InvalidEncryptedPageLength { expected, actual } => write!(
                f,
                "invalid encrypted page length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidOutputPageLength { expected, actual } => write!(
                f,
                "invalid output page length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidSqlitePageSize { expected, actual } => write!(
                f,
                "invalid SQLite page size in the decrypted header: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidSqliteReserveSize { expected, actual } => write!(
                f,
                "invalid SQLite reserve size in the decrypted header: expected {expected} bytes, got {actual}"
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
    pub fn new(
        profile: CompatibilityProfile,
        passphrase: &[u8],
        salt: &[u8; 16],
    ) -> Result<Self, DecryptError> {
        if passphrase.is_empty() {
            return Err(DecryptError::EmptyPassphrase);
        }

        let params = profile.params();

        let encryption_key = Self::derive_key(
            params.kdf_algorithm,
            passphrase,
            salt,
            params.kdf_iterations,
        );
        let hmac_salt: [u8; 16] = std::array::from_fn(|index| salt[index] ^ 0x3a);

        let hmac_key = Self::derive_key(params.kdf_algorithm, &encryption_key, &hmac_salt, 2);

        Ok(Self {
            params,
            keys: KeyMaterial {
                encryption_key,
                hmac_key,
            },
        })
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
            return Err(DecryptError::InvalidEncryptedPageLength {
                expected,
                actual: encrypted_page.len(),
            });
        }
        if output.len() != expected {
            return Err(DecryptError::InvalidOutputPageLength {
                expected,
                actual: output.len(),
            });
        }

        output.fill(0);

        let page_number = page_no.get();
        let ciphertext_offset = if page_number == 1 { 16 } else { 0 };
        let ciphertext_len = self.params.page_size - ciphertext_offset - self.params.reserve_size;
        if !ciphertext_len.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(DecryptError::InvalidCiphertextLength {
                page_no: page_number,
            });
        }

        let ciphertext_end = ciphertext_offset + ciphertext_len;
        let iv_end = ciphertext_end + AES_BLOCK_SIZE;
        let hmac_end = iv_end + self.params.hmac_algorithm.output_len();

        let ciphertext = &encrypted_page[ciphertext_offset..ciphertext_end];
        let iv = &encrypted_page[ciphertext_end..iv_end];
        let stored_hmac = &encrypted_page[iv_end..hmac_end];

        self.verify_page_hmac(ciphertext, iv, page_number, stored_hmac)?;

        let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.keys.encryption_key, iv)
            .map_err(|_| DecryptError::CryptoInitializationFailed)?;

        if cipher
            .decrypt_padded_b2b::<NoPadding>(
                ciphertext,
                &mut output[ciphertext_offset..ciphertext_end],
            )
            .is_err()
        {
            output.zeroize();
            return Err(DecryptError::InvalidCiphertextLength {
                page_no: page_number,
            });
        }

        if page_number == 1 {
            output[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);

            let encoded_page_size = u16::from_be_bytes([output[16], output[17]]);
            let sqlite_page_size = if encoded_page_size == 1 {
                65_536
            } else {
                usize::from(encoded_page_size)
            };
            if sqlite_page_size != self.params.page_size {
                output.zeroize();
                return Err(DecryptError::InvalidSqlitePageSize {
                    expected: self.params.page_size,
                    actual: sqlite_page_size,
                });
            }

            let sqlite_reserve_size = usize::from(output[20]);
            if sqlite_reserve_size != self.params.reserve_size {
                output.zeroize();
                return Err(DecryptError::InvalidSqliteReserveSize {
                    expected: self.params.reserve_size,
                    actual: sqlite_reserve_size,
                });
            }
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
        let max_page_count = u32::MAX as usize;
        if page_count > max_page_count {
            return Err(DecryptError::TooManyPages { page_count });
        }

        let mut output = Zeroizing::new(vec![0; encrypted.len()]);
        for (index, encrypted_page) in encrypted.chunks_exact(page_size).enumerate() {
            let page_number =
                u32::try_from(index + 1).map_err(|_| DecryptError::TooManyPages { page_count })?;
            let page_number =
                NonZeroU32::new(page_number).ok_or(DecryptError::TooManyPages { page_count })?;
            let start = index * page_size;

            self.decrypt_page_into(
                page_number,
                encrypted_page,
                &mut output[start..start + page_size],
            )?;
        }

        Ok(output)
    }

    fn derive_key(
        algorithm: HashAlgorithm,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> [u8; 32] {
        match algorithm {
            HashAlgorithm::Sha1 => pbkdf2_hmac_array::<Sha1, 32>(password, salt, iterations),
            HashAlgorithm::Sha512 => pbkdf2_hmac_array::<Sha512, 32>(password, salt, iterations),
        }
    }

    fn verify_page_hmac(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        page_number: u32,
        stored_hmac: &[u8],
    ) -> Result<(), DecryptError> {
        match self.params.hmac_algorithm {
            HashAlgorithm::Sha1 => {
                let mac = hmac::Hmac::<Sha1>::new_from_slice(&self.keys.hmac_key)
                    .map_err(|_| DecryptError::CryptoInitializationFailed)?
                    .chain_update(ciphertext)
                    .chain_update(iv)
                    .chain_update(page_number.to_le_bytes());

                mac.verify_slice(stored_hmac)
                    .map_err(|_| DecryptError::AuthenticationFailed {
                        page_no: page_number,
                    })
            }
            HashAlgorithm::Sha512 => {
                let mac = hmac::Hmac::<Sha512>::new_from_slice(&self.keys.hmac_key)
                    .map_err(|_| DecryptError::CryptoInitializationFailed)?
                    .chain_update(ciphertext)
                    .chain_update(iv)
                    .chain_update(page_number.to_le_bytes());

                mac.verify_slice(stored_hmac)
                    .map_err(|_| DecryptError::AuthenticationFailed {
                        page_no: page_number,
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests;
