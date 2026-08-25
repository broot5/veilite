use thiserror::Error;

const MIN_PAGE_SIZE: usize = 1024;
const MAX_PAGE_SIZE: usize = 65_536;
const MAX_KDF_ITERATIONS: u32 = i32::MAX as u32;
const AES_BLOCK_SIZE: usize = 16;
const DATABASE_SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const MIN_SQLITE_USABLE_SIZE: usize = 480;

/// A supported SQLCipher default on-disk configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherPreset {
    /// The SQLCipher 3 default compatibility profile.
    SqlCipher3,
    /// The SQLCipher 4 default compatibility profile.
    SqlCipher4,
}

impl From<CipherPreset> for CipherConfig {
    fn from(preset: CipherPreset) -> Self {
        let (page_size, kdf_iterations, kdf_algorithm, hmac_algorithm) = match preset {
            CipherPreset::SqlCipher3 => (1024, 64_000, HashAlgorithm::Sha1, HashAlgorithm::Sha1),
            CipherPreset::SqlCipher4 => {
                (4096, 256_000, HashAlgorithm::Sha512, HashAlgorithm::Sha512)
            }
        };

        Self::new(page_size, kdf_iterations, kdf_algorithm, hmac_algorithm)
            .expect("built-in cipher presets must be valid")
    }
}

/// Hash algorithm used by PBKDF2 or page HMAC authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    #[must_use]
    pub(super) const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// A complete supported SQLCipher on-disk configuration.
///
/// The configuration always uses passphrase-based key derivation, AES-256-CBC,
/// page HMAC authentication, and a zero-length plaintext header. Use
/// [`CipherPreset`] for the built-in SQLCipher 3 and 4 defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherConfig {
    page_size: usize,
    kdf_iterations: u32,
    kdf_algorithm: HashAlgorithm,
    hmac_algorithm: HashAlgorithm,
}

impl CipherConfig {
    /// Creates and validates a complete custom configuration.
    ///
    /// `page_size` must be a power of two from 1,024 through 65,536 bytes, and
    /// `kdf_iterations` must be in `1..=i32::MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`CipherConfigError`] when a value or the resulting page layout
    /// falls outside the supported format boundary.
    pub fn new(
        page_size: usize,
        kdf_iterations: u32,
        kdf_algorithm: HashAlgorithm,
        hmac_algorithm: HashAlgorithm,
    ) -> Result<Self, CipherConfigError> {
        if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(CipherConfigError::InvalidPageSize { page_size });
        }
        if !(1..=MAX_KDF_ITERATIONS).contains(&kdf_iterations) {
            return Err(CipherConfigError::InvalidKdfIterations { kdf_iterations });
        }

        let reserve_size = reserve_size_for(hmac_algorithm);
        let invalid_layout = CipherConfigError::InvalidPageLayout {
            page_size,
            reserve_size,
        };
        let usable_end = page_size.checked_sub(reserve_size).ok_or(invalid_layout)?;
        if usable_end < MIN_SQLITE_USABLE_SIZE {
            return Err(invalid_layout);
        }

        let first_page_ciphertext_len = usable_end - DATABASE_SALT_SIZE;
        if u8::try_from(reserve_size).is_err()
            || !usable_end.is_multiple_of(AES_BLOCK_SIZE)
            || !first_page_ciphertext_len.is_multiple_of(AES_BLOCK_SIZE)
        {
            return Err(invalid_layout);
        }

        Ok(Self {
            page_size,
            kdf_iterations,
            kdf_algorithm,
            hmac_algorithm,
        })
    }

    /// Returns the encrypted database page size in bytes.
    #[must_use]
    pub const fn page_size(self) -> usize {
        self.page_size
    }

    /// Returns the encryption-key PBKDF2 iteration count.
    #[must_use]
    pub const fn kdf_iterations(self) -> u32 {
        self.kdf_iterations
    }

    /// Returns the hash algorithm used by both PBKDF2 derivations.
    #[must_use]
    pub const fn kdf_algorithm(self) -> HashAlgorithm {
        self.kdf_algorithm
    }

    /// Returns the page authentication HMAC algorithm.
    #[must_use]
    pub const fn hmac_algorithm(self) -> HashAlgorithm {
        self.hmac_algorithm
    }

    /// Returns the per-page reserve size calculated from the HMAC algorithm.
    #[must_use]
    pub const fn reserve_size(self) -> usize {
        reserve_size_for(self.hmac_algorithm)
    }

    #[must_use]
    pub(super) const fn usable_end(self) -> usize {
        self.page_size - self.reserve_size()
    }
}

#[must_use]
const fn reserve_size_for(hmac_algorithm: HashAlgorithm) -> usize {
    (IV_SIZE + hmac_algorithm.output_len()).next_multiple_of(AES_BLOCK_SIZE)
}

/// Error returned when a custom cipher configuration is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CipherConfigError {
    /// The page size is outside the supported power-of-two range.
    #[error("invalid cipher page size {page_size}: expected a power of two from 1024 to 65536")]
    InvalidPageSize {
        /// Rejected page size in bytes.
        page_size: usize,
    },
    /// The PBKDF2 iteration count is outside the supported positive range.
    #[error("invalid KDF iteration count {kdf_iterations}: expected a value from 1 to 2147483647")]
    InvalidKdfIterations {
        /// Rejected iteration count.
        kdf_iterations: u32,
    },
    /// The selected values cannot form a supported authenticated page layout.
    #[error(
        "invalid cipher page layout: page size {page_size} bytes with {reserve_size} reserved bytes"
    )]
    InvalidPageLayout {
        /// Requested page size in bytes.
        page_size: usize,
        /// Calculated per-page reserve size in bytes.
        reserve_size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_built_in_presets_to_complete_configs() {
        let cases = [
            (
                CipherPreset::SqlCipher3,
                1024,
                64_000,
                HashAlgorithm::Sha1,
                HashAlgorithm::Sha1,
                48,
            ),
            (
                CipherPreset::SqlCipher4,
                4096,
                256_000,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha512,
                80,
            ),
        ];

        for (preset, page_size, iterations, kdf, hmac, reserve_size) in cases {
            let config = CipherConfig::from(preset);

            assert_eq!(config.page_size(), page_size);
            assert_eq!(config.kdf_iterations(), iterations);
            assert_eq!(config.kdf_algorithm(), kdf);
            assert_eq!(config.hmac_algorithm(), hmac);
            assert_eq!(config.reserve_size(), reserve_size);
            assert_eq!(config.usable_end(), page_size - reserve_size);
        }
    }

    #[test]
    fn validates_supported_configuration_boundaries() {
        for page_size in [1024, 65_536] {
            for kdf_iterations in [1, i32::MAX as u32] {
                for hmac_algorithm in [
                    HashAlgorithm::Sha1,
                    HashAlgorithm::Sha256,
                    HashAlgorithm::Sha512,
                ] {
                    assert!(
                        CipherConfig::new(
                            page_size,
                            kdf_iterations,
                            HashAlgorithm::Sha256,
                            hmac_algorithm,
                        )
                        .is_ok()
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_unsupported_page_sizes_and_iteration_counts() {
        for page_size in [0, 511, 512, 513, 1023, 65_535, 65_537] {
            assert_eq!(
                CipherConfig::new(page_size, 1, HashAlgorithm::Sha1, HashAlgorithm::Sha1,),
                Err(CipherConfigError::InvalidPageSize { page_size })
            );
        }

        for kdf_iterations in [0, i32::MAX as u32 + 1] {
            assert_eq!(
                CipherConfig::new(
                    4096,
                    kdf_iterations,
                    HashAlgorithm::Sha512,
                    HashAlgorithm::Sha512,
                ),
                Err(CipherConfigError::InvalidKdfIterations { kdf_iterations })
            );
        }
    }

    #[test]
    fn calculates_reserve_from_the_page_hmac_algorithm() {
        for (algorithm, reserve_size) in [
            (HashAlgorithm::Sha1, 48),
            (HashAlgorithm::Sha256, 48),
            (HashAlgorithm::Sha512, 80),
        ] {
            let config = CipherConfig::new(2048, 100_000, HashAlgorithm::Sha1, algorithm).unwrap();

            assert_eq!(config.reserve_size(), reserve_size);
            assert_eq!(config.usable_end(), 2048 - reserve_size);
        }
    }
}
