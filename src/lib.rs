use std::fmt;
use std::num::NonZeroU32;

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const AES_BLOCK_SIZE: usize = 16;
const SQLCIPHER3_PAGE_SIZE: usize = 1024;
pub const SQLCIPHER4_PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityProfile {
    SqlCipher3,
    SqlCipher4,
}

impl CompatibilityProfile {
    fn params(self) -> CipherParams {
        match self {
            Self::SqlCipher3 => CipherParams {
                page_size: SQLCIPHER3_PAGE_SIZE,
                kdf_iterations: 64_000,
                kdf_algorithm: HashAlgorithm::Sha1,
                hmac_algorithm: HashAlgorithm::Sha1,
                reserve_size: 48,
            },
            Self::SqlCipher4 => CipherParams {
                page_size: SQLCIPHER4_PAGE_SIZE,
                kdf_iterations: 256_000,
                kdf_algorithm: HashAlgorithm::Sha512,
                hmac_algorithm: HashAlgorithm::Sha512,
                reserve_size: 80,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum HashAlgorithm {
    Sha1,
    Sha512,
}

impl HashAlgorithm {
    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone, Copy)]
struct CipherParams {
    page_size: usize,
    kdf_iterations: u32,
    kdf_algorithm: HashAlgorithm,
    hmac_algorithm: HashAlgorithm,
    reserve_size: usize,
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
mod tests {
    use std::num::NonZeroU32;
    use std::sync::OnceLock;

    use super::*;

    const SQLCIPHER3_FIXTURE: &[u8] = include_bytes!("../fixtures/sqlcipher3/encrypted.db");
    const SQLCIPHER3_PASSPHRASE: &[u8] = b"veilite-sqlcipher3-test-key";
    const SQLCIPHER4_FIXTURE: &[u8] = include_bytes!("../fixtures/sqlcipher4/encrypted.db");
    const SQLCIPHER4_PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";

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
        header_offset: usize,
        original: u8,
        replacement: u8,
    ) -> Vec<u8> {
        assert!((16..32).contains(&header_offset));

        let mut page = SQLCIPHER4_FIXTURE[..SQLCIPHER4_PAGE_SIZE].to_vec();
        let ciphertext_end = SQLCIPHER4_PAGE_SIZE - 80;
        let iv_end = ciphertext_end + 16;
        page[ciphertext_end + header_offset - 16] ^= original ^ replacement;

        let tag = hmac::Hmac::<Sha512>::new_from_slice(&sqlcipher4_decryptor().keys.hmac_key)
            .unwrap()
            .chain_update(&page[16..ciphertext_end])
            .chain_update(&page[ciphertext_end..iv_end])
            .chain_update(1_u32.to_le_bytes())
            .finalize()
            .into_bytes();
        page[iv_end..].copy_from_slice(&tag);
        page
    }

    #[test]
    fn decrypts_sqlcipher3_fixture() {
        let plaintext = sqlcipher3_decryptor()
            .decrypt_database(SQLCIPHER3_FIXTURE)
            .expect("SQLCipher 3 fixture should decrypt");

        assert_eq!(sqlcipher3_decryptor().page_size(), SQLCIPHER3_PAGE_SIZE);
        assert_eq!(plaintext.len(), SQLCIPHER3_FIXTURE.len());
        assert_eq!(&plaintext[..16], SQLITE_HEADER_MAGIC);
        assert_eq!(
            u16::from_be_bytes([plaintext[16], plaintext[17]]),
            SQLCIPHER3_PAGE_SIZE as u16
        );
        assert_eq!(plaintext[20], 48);
        assert_eq!(
            u32::from_be_bytes(plaintext[60..64].try_into().unwrap()),
            42
        );
        assert_eq!(
            u32::from_be_bytes(plaintext[68..72].try_into().unwrap()),
            0x5645_4c49
        );
        assert!(plaintext.chunks_exact(SQLCIPHER3_PAGE_SIZE).all(|page| {
            page[SQLCIPHER3_PAGE_SIZE - 48..]
                .iter()
                .all(|byte| *byte == 0)
        }));
    }

    #[test]
    fn ignores_unauthenticated_sqlcipher3_filler() {
        let expected = sqlcipher3_decryptor()
            .decrypt_database(SQLCIPHER3_FIXTURE)
            .expect("fixture should decrypt");
        let mut tampered = SQLCIPHER3_FIXTURE.to_vec();

        for page in tampered.chunks_exact_mut(SQLCIPHER3_PAGE_SIZE) {
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
    fn decrypts_sqlcipher4_fixture() {
        let plaintext = sqlcipher4_decryptor()
            .decrypt_database(SQLCIPHER4_FIXTURE)
            .expect("SQLCipher 4 fixture should decrypt");

        assert_eq!(sqlcipher4_decryptor().page_size(), SQLCIPHER4_PAGE_SIZE);
        assert_eq!(plaintext.len(), SQLCIPHER4_FIXTURE.len());
        assert_eq!(&plaintext[..16], SQLITE_HEADER_MAGIC);
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
        let cases: [(CompatibilityProfile, &[u8]); 2] = [
            (CompatibilityProfile::SqlCipher3, SQLCIPHER3_FIXTURE),
            (CompatibilityProfile::SqlCipher4, SQLCIPHER4_FIXTURE),
        ];

        for (profile, fixture) in cases {
            let salt: &[u8; 16] = fixture[..16].try_into().unwrap();
            let wrong = Decryptor::new(profile, b"wrong passphrase", salt).unwrap();

            assert_eq!(
                wrong.decrypt_database(fixture).unwrap_err(),
                DecryptError::AuthenticationFailed { page_no: 1 }
            );
        }
    }

    #[test]
    fn rejects_tampering_in_ciphertext_iv_and_hmac() {
        for index in [16, 4016, 4032] {
            let mut tampered = SQLCIPHER4_FIXTURE.to_vec();
            tampered[index] ^= 1;
            assert_eq!(
                sqlcipher4_decryptor()
                    .decrypt_database(&tampered)
                    .unwrap_err(),
                DecryptError::AuthenticationFailed { page_no: 1 }
            );
        }
    }

    #[test]
    fn page_number_is_authenticated() {
        let second_page = &SQLCIPHER4_FIXTURE[SQLCIPHER4_PAGE_SIZE..2 * SQLCIPHER4_PAGE_SIZE];
        let mut output = [0_u8; SQLCIPHER4_PAGE_SIZE];

        assert_eq!(
            sqlcipher4_decryptor()
                .decrypt_page_into(NonZeroU32::new(3).unwrap(), second_page, &mut output)
                .unwrap_err(),
            DecryptError::AuthenticationFailed { page_no: 3 }
        );
    }

    #[test]
    fn validates_page_buffer_sizes() {
        let mut output = [0_u8; SQLCIPHER4_PAGE_SIZE];
        assert_eq!(
            sqlcipher4_decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &SQLCIPHER4_FIXTURE[..SQLCIPHER4_PAGE_SIZE - 1],
                    &mut output,
                )
                .unwrap_err(),
            DecryptError::InvalidEncryptedPageLength {
                expected: SQLCIPHER4_PAGE_SIZE,
                actual: SQLCIPHER4_PAGE_SIZE - 1,
            }
        );

        let mut short_output = [0_u8; SQLCIPHER4_PAGE_SIZE - 1];
        assert_eq!(
            sqlcipher4_decryptor()
                .decrypt_page_into(
                    NonZeroU32::new(1).unwrap(),
                    &SQLCIPHER4_FIXTURE[..SQLCIPHER4_PAGE_SIZE],
                    &mut short_output,
                )
                .unwrap_err(),
            DecryptError::InvalidOutputPageLength {
                expected: SQLCIPHER4_PAGE_SIZE,
                actual: SQLCIPHER4_PAGE_SIZE - 1,
            }
        );
    }

    #[test]
    fn clears_reserved_output_bytes() {
        let mut output = [0xaa; SQLCIPHER4_PAGE_SIZE];
        sqlcipher4_decryptor()
            .decrypt_page_into(
                NonZeroU32::new(1).unwrap(),
                &SQLCIPHER4_FIXTURE[..SQLCIPHER4_PAGE_SIZE],
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
            sqlcipher4_decryptor().decrypt_database(&[]).unwrap_err(),
            DecryptError::EmptyDatabase
        );
        assert_eq!(
            sqlcipher4_decryptor()
                .decrypt_database(&SQLCIPHER4_FIXTURE[..SQLCIPHER4_FIXTURE.len() - 1])
                .unwrap_err(),
            DecryptError::IncompletePage {
                file_size: SQLCIPHER4_FIXTURE.len() - 1,
                page_size: SQLCIPHER4_PAGE_SIZE,
            }
        );
    }

    #[test]
    fn rejects_empty_passphrase() {
        let salt: &[u8; 16] = SQLCIPHER4_FIXTURE[..16].try_into().unwrap();

        assert!(matches!(
            Decryptor::new(CompatibilityProfile::SqlCipher4, b"", salt),
            Err(DecryptError::EmptyPassphrase)
        ));
    }

    #[test]
    fn validates_decrypted_sqlite_header() {
        let cases = [
            (
                first_page_with_changed_header_byte(16, 0x10, 0x04),
                DecryptError::InvalidSqlitePageSize {
                    expected: SQLCIPHER4_PAGE_SIZE,
                    actual: 1024,
                },
            ),
            (
                first_page_with_changed_header_byte(20, 80, 48),
                DecryptError::InvalidSqliteReserveSize {
                    expected: 80,
                    actual: 48,
                },
            ),
        ];

        for (page, expected_error) in cases {
            let mut output = [0xaa; SQLCIPHER4_PAGE_SIZE];
            let error = sqlcipher4_decryptor()
                .decrypt_page_into(NonZeroU32::new(1).unwrap(), &page, &mut output)
                .unwrap_err();

            assert_eq!(error, expected_error);
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}
