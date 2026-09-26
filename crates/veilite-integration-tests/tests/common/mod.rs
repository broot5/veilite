use veilite_core::{CipherConfig, CipherPreset, HashAlgorithm, SliceSource, SqlCipherReader};

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
    pub encrypted: &'static [u8],
    pub passphrase: &'static [u8],
    pub page_size: usize,
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

    pub fn reader(self) -> SqlCipherReader<SliceSource<'static>> {
        SqlCipherReader::open(
            SliceSource::new(self.encrypted),
            self.config(),
            self.passphrase,
        )
        .unwrap_or_else(|error| panic!("{} reader failed to open: {error}", self.name))
    }
}

pub const SQLCIPHER3_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher3",
    cipher: FixtureCipher::SqlCipher3,
    encrypted: include_bytes!("../../../../fixtures/sqlcipher3/encrypted.db"),
    passphrase: b"veilite-sqlcipher3-test-key",
    page_size: 1024,
};

const SQLCIPHER4_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher4",
    cipher: FixtureCipher::SqlCipher4,
    encrypted: include_bytes!("../../../../fixtures/sqlcipher4/encrypted.db"),
    passphrase: b"veilite-sqlcipher4-test-key",
    page_size: 4096,
};

const SQLCIPHER_CUSTOM_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher-custom",
    cipher: FixtureCipher::Custom,
    encrypted: include_bytes!("../../../../fixtures/sqlcipher-custom/encrypted.db"),
    passphrase: b"veilite-sqlcipher-custom-test-key",
    page_size: 2048,
};

pub const FIXTURE_CASES: [FixtureCase; 3] =
    [SQLCIPHER3_CASE, SQLCIPHER4_CASE, SQLCIPHER_CUSTOM_CASE];
