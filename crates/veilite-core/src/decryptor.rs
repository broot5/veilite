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

/// Internal authenticated page decryptor.
///
/// Most callers should use [`crate::SqlCipherReader`], which validates source
/// length and page numbers before invoking the decryptor.
pub struct PageDecryptor {
    config: CipherConfig,
    keys: KeyMaterial,
}

/// Error returned while deriving keys or authenticating and decrypting a page.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecryptError {
    /// An empty passphrase was supplied.
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    /// The authenticated first page declares a different SQLite page size.
    #[error(
        "invalid SQLite page size in the decrypted header: expected {expected} bytes, got {actual}"
    )]
    InvalidSqlitePageSize {
        /// Page size required by the selected cipher configuration.
        expected: usize,
        /// Page size decoded from the authenticated SQLite header.
        actual: usize,
    },
    /// The authenticated first page declares a different SQLite reserve size.
    #[error(
        "invalid SQLite reserve size in the decrypted header: expected {expected} bytes, got {actual}"
    )]
    InvalidSqliteReserveSize {
        /// Reserve size required by the selected cipher configuration.
        expected: usize,
        /// Reserve size decoded from the authenticated SQLite header.
        actual: usize,
    },
    /// Page authentication failed.
    ///
    /// The format cannot distinguish a wrong passphrase or configuration from
    /// corrupted or tampered page bytes.
    #[error("authentication failed for page {page_no}: wrong passphrase or corrupted data")]
    AuthenticationFailed {
        /// One-based physical page number that failed authentication.
        page_no: u32,
    },
}

impl PageDecryptor {
    /// Derives page encryption and HMAC keys from a passphrase and database salt.
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

    /// Returns the configured physical page size in bytes.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.config.page_size()
    }

    /// Authenticates and decrypts one physical page in place.
    ///
    /// The page buffer is cleared if authentication or header validation fails.
    pub fn decrypt_page_in_place(
        &self,
        page_no: NonZeroU32,
        page: &mut [u8],
    ) -> Result<(), DecryptError> {
        debug_assert_eq!(
            page.len(),
            self.config.page_size(),
            "reader must provide exactly one encrypted page"
        );

        let result = self.decrypt_page_in_place_inner(page_no, page);
        if result.is_err() {
            page.zeroize();
        }
        result
    }

    fn decrypt_page_in_place_inner(
        &self,
        page_no: NonZeroU32,
        page: &mut [u8],
    ) -> Result<(), DecryptError> {
        let page_number = page_no.get();
        let ciphertext_offset = if page_number == 1 { 16 } else { 0 };
        let ciphertext_len = self.config.usable_end() - ciphertext_offset;
        let ciphertext_end = ciphertext_offset + ciphertext_len;
        let iv_end = ciphertext_end + AES_BLOCK_SIZE;
        let hmac_end = iv_end + self.config.hmac_algorithm().output_len();

        let iv: [u8; AES_BLOCK_SIZE] = page[ciphertext_end..iv_end]
            .try_into()
            .expect("validated page layout has a 16-byte IV");
        self.verify_page_hmac(
            &page[ciphertext_offset..ciphertext_end],
            &iv,
            page_number,
            &page[iv_end..hmac_end],
        )?;

        let cipher =
            cbc::Decryptor::<aes::Aes256>::new((&self.keys.encryption_key).into(), (&iv).into());
        cipher
            .decrypt_padded::<NoPadding>(&mut page[ciphertext_offset..ciphertext_end])
            .expect("validated page layout is AES block-aligned");

        if page_number == 1 {
            page[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);

            let sqlite_page_size = decode_sqlite_page_size([page[16], page[17]]);
            if sqlite_page_size != self.config.page_size() {
                return Err(DecryptError::InvalidSqlitePageSize {
                    expected: self.config.page_size(),
                    actual: sqlite_page_size,
                });
            }

            let sqlite_reserve_size = usize::from(page[20]);
            if sqlite_reserve_size != self.config.reserve_size() {
                return Err(DecryptError::InvalidSqliteReserveSize {
                    expected: self.config.reserve_size(),
                    actual: sqlite_reserve_size,
                });
            }
        }

        page[self.config.usable_end()..].zeroize();
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
