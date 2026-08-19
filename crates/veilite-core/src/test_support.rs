use crate::{CipherConfig, CipherPreset, HashAlgorithm};

const SQLCIPHER3_FIXTURE: &[u8] = include_bytes!("../../../fixtures/sqlcipher3/encrypted.db");
const SQLCIPHER3_PASSPHRASE: &[u8] = b"veilite-sqlcipher3-test-key";
const SQLCIPHER4_FIXTURE: &[u8] = include_bytes!("../../../fixtures/sqlcipher4/encrypted.db");
const SQLCIPHER4_PASSPHRASE: &[u8] = b"veilite-sqlcipher4-test-key";
const SQLCIPHER_CUSTOM_FIXTURE: &[u8] =
    include_bytes!("../../../fixtures/sqlcipher-custom/encrypted.db");
const SQLCIPHER_CUSTOM_PASSPHRASE: &[u8] = b"veilite-sqlcipher-custom-test-key";

#[derive(Debug, Clone, Copy)]
pub enum FixtureCipher {
    SqlCipher3,
    SqlCipher4,
    Custom,
}

#[derive(Clone, Copy)]
pub struct FixtureCase {
    pub name: &'static str,
    pub cipher: FixtureCipher,
    pub fixture: &'static [u8],
    pub passphrase: &'static [u8],
    pub page_size: usize,
    pub reserve_size: usize,
}

impl FixtureCase {
    pub fn config(self) -> CipherConfig {
        match self.cipher {
            FixtureCipher::SqlCipher3 => CipherPreset::SqlCipher3.into(),
            FixtureCipher::SqlCipher4 => CipherPreset::SqlCipher4.into(),
            FixtureCipher::Custom => {
                CipherConfig::new(2048, 100_000, HashAlgorithm::Sha256, HashAlgorithm::Sha256)
                    .expect("custom fixture configuration is valid")
            }
        }
    }
}

pub const SQLCIPHER3_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher3",
    cipher: FixtureCipher::SqlCipher3,
    fixture: SQLCIPHER3_FIXTURE,
    passphrase: SQLCIPHER3_PASSPHRASE,
    page_size: 1024,
    reserve_size: 48,
};

pub const SQLCIPHER4_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher4",
    cipher: FixtureCipher::SqlCipher4,
    fixture: SQLCIPHER4_FIXTURE,
    passphrase: SQLCIPHER4_PASSPHRASE,
    page_size: 4096,
    reserve_size: 80,
};

pub const SQLCIPHER_CUSTOM_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher-custom",
    cipher: FixtureCipher::Custom,
    fixture: SQLCIPHER_CUSTOM_FIXTURE,
    passphrase: SQLCIPHER_CUSTOM_PASSPHRASE,
    page_size: 2048,
    reserve_size: 48,
};

pub const PRESET_FIXTURE_CASES: [FixtureCase; 2] = [SQLCIPHER3_CASE, SQLCIPHER4_CASE];
pub const FIXTURE_CASES: [FixtureCase; 3] =
    [SQLCIPHER3_CASE, SQLCIPHER4_CASE, SQLCIPHER_CUSTOM_CASE];
