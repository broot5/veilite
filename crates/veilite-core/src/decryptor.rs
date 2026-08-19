use std::num::NonZeroU32;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{CipherConfig, HashAlgorithm};

const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
}

pub struct PageDecryptor {
    config: CipherConfig,
    keys: KeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecryptError {
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    #[error("invalid encrypted page length: expected {expected} bytes, got {actual}")]
    InvalidEncryptedPageLength { expected: usize, actual: usize },
    #[error("invalid output page length: expected {expected} bytes, got {actual}")]
    InvalidOutputPageLength { expected: usize, actual: usize },
    #[error(
        "invalid SQLite page size in the decrypted header: expected {expected} bytes, got {actual}"
    )]
    InvalidSqlitePageSize { expected: usize, actual: usize },
    #[error(
        "invalid SQLite reserve size in the decrypted header: expected {expected} bytes, got {actual}"
    )]
    InvalidSqliteReserveSize { expected: usize, actual: usize },
    #[error("authentication failed for page {page_no}: wrong passphrase or corrupted data")]
    AuthenticationFailed { page_no: u32 },
    #[error("ciphertext on page {page_no} is not AES block-aligned")]
    InvalidCiphertextLength { page_no: u32 },
}

impl PageDecryptor {
    pub fn new(
        config: CipherConfig,
        passphrase: &[u8],
        salt: &[u8; 16],
    ) -> Result<Self, DecryptError> {
        if passphrase.is_empty() {
            return Err(DecryptError::EmptyPassphrase);
        }

        let mut keys = KeyMaterial {
            encryption_key: [0; 32],
            hmac_key: [0; 32],
        };
        let hmac_salt: [u8; 16] = std::array::from_fn(|index| salt[index] ^ 0x3a);
        let KeyMaterial {
            encryption_key,
            hmac_key,
        } = &mut keys;
        Self::derive_key_into(
            config.kdf_algorithm(),
            passphrase,
            salt,
            config.kdf_iterations(),
            encryption_key,
        );
        Self::derive_key_into(
            config.kdf_algorithm(),
            encryption_key,
            &hmac_salt,
            2,
            hmac_key,
        );

        Ok(Self { config, keys })
    }

    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.config.page_size()
    }

    pub fn decrypt_page_into(
        &self,
        page_no: NonZeroU32,
        encrypted_page: &[u8],
        output: &mut [u8],
    ) -> Result<(), DecryptError> {
        let expected = self.config.page_size();
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
        let ciphertext_len = self.config.usable_end() - ciphertext_offset;
        if !ciphertext_len.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(DecryptError::InvalidCiphertextLength {
                page_no: page_number,
            });
        }

        let ciphertext_end = ciphertext_offset + ciphertext_len;
        let iv_end = ciphertext_end + AES_BLOCK_SIZE;
        let hmac_end = iv_end + self.config.hmac_algorithm().output_len();

        let ciphertext = &encrypted_page[ciphertext_offset..ciphertext_end];
        let iv: &[u8; AES_BLOCK_SIZE] = encrypted_page[ciphertext_end..iv_end]
            .try_into()
            .expect("validated page layout has a 16-byte IV");
        let stored_hmac = &encrypted_page[iv_end..hmac_end];

        self.verify_page_hmac(ciphertext, iv, page_number, stored_hmac)?;

        let cipher =
            cbc::Decryptor::<aes::Aes256>::new((&self.keys.encryption_key).into(), iv.into());

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

            let sqlite_page_size = decode_sqlite_page_size([output[16], output[17]]);
            if sqlite_page_size != self.config.page_size() {
                output.zeroize();
                return Err(DecryptError::InvalidSqlitePageSize {
                    expected: self.config.page_size(),
                    actual: sqlite_page_size,
                });
            }

            let sqlite_reserve_size = usize::from(output[20]);
            if sqlite_reserve_size != self.config.reserve_size() {
                output.zeroize();
                return Err(DecryptError::InvalidSqliteReserveSize {
                    expected: self.config.reserve_size(),
                    actual: sqlite_reserve_size,
                });
            }
        }

        Ok(())
    }

    fn derive_key_into(
        algorithm: HashAlgorithm,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8; 32],
    ) {
        match algorithm {
            HashAlgorithm::Sha1 => pbkdf2_hmac::<Sha1>(password, salt, iterations, output),
            HashAlgorithm::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, iterations, output),
            HashAlgorithm::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, iterations, output),
        }
    }

    fn verify_page_hmac(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        page_number: u32,
        stored_hmac: &[u8],
    ) -> Result<(), DecryptError> {
        match self.config.hmac_algorithm() {
            HashAlgorithm::Sha1 => {
                let mac = hmac::Hmac::<Sha1>::new_from_slice(&self.keys.hmac_key)
                    .expect("HMAC accepts keys of any length")
                    .chain_update(ciphertext)
                    .chain_update(iv)
                    .chain_update(page_number.to_le_bytes());

                mac.verify_slice(stored_hmac)
                    .map_err(|_| DecryptError::AuthenticationFailed {
                        page_no: page_number,
                    })
            }
            HashAlgorithm::Sha256 => {
                let mac = hmac::Hmac::<Sha256>::new_from_slice(&self.keys.hmac_key)
                    .expect("HMAC accepts keys of any length")
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
                    .expect("HMAC accepts keys of any length")
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

#[must_use]
fn decode_sqlite_page_size(encoded: [u8; 2]) -> usize {
    let page_size = u16::from_be_bytes(encoded);
    if page_size == 1 {
        65_536
    } else {
        usize::from(page_size)
    }
}

#[cfg(test)]
mod tests;
