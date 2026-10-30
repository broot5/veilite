use veilite_core::{CipherConfig, CipherPreset, HashAlgorithm};

#[derive(Debug, Clone, Copy)]
pub enum FixtureCipher {
    SqlCipher3,
    SqlCipher4,
    Custom,
}

impl FixtureCipher {
    pub fn config(self) -> CipherConfig {
        match self {
            FixtureCipher::SqlCipher3 => CipherPreset::SqlCipher3.into(),
            FixtureCipher::SqlCipher4 => CipherPreset::SqlCipher4.into(),
            FixtureCipher::Custom => {
                CipherConfig::new(2048, 100_000, HashAlgorithm::Sha256, HashAlgorithm::Sha256)
                    .expect("custom fixture configuration is valid")
            }
        }
    }
}
