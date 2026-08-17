const SQLCIPHER3_PAGE_SIZE: usize = 1024;
const SQLCIPHER4_PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityProfile {
    SqlCipher3,
    SqlCipher4,
}

impl CompatibilityProfile {
    #[must_use]
    pub const fn page_size(self) -> usize {
        match self {
            Self::SqlCipher3 => SQLCIPHER3_PAGE_SIZE,
            Self::SqlCipher4 => SQLCIPHER4_PAGE_SIZE,
        }
    }

    pub(crate) fn params(self) -> CipherParams {
        match self {
            Self::SqlCipher3 => CipherParams {
                page_size: self.page_size(),
                kdf_iterations: 64_000,
                kdf_algorithm: HashAlgorithm::Sha1,
                hmac_algorithm: HashAlgorithm::Sha1,
                reserve_size: 48,
            },
            Self::SqlCipher4 => CipherParams {
                page_size: self.page_size(),
                kdf_iterations: 256_000,
                kdf_algorithm: HashAlgorithm::Sha512,
                hmac_algorithm: HashAlgorithm::Sha512,
                reserve_size: 80,
            },
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum HashAlgorithm {
    Sha1,
    Sha512,
}

impl HashAlgorithm {
    pub(crate) fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CipherParams {
    pub(crate) page_size: usize,
    pub(crate) kdf_iterations: u32,
    pub(crate) kdf_algorithm: HashAlgorithm,
    pub(crate) hmac_algorithm: HashAlgorithm,
    pub(crate) reserve_size: usize,
}
