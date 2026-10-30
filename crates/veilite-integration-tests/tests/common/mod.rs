mod cipher;

pub use cipher::FixtureCipher;
use veilite_core::CipherConfig;

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
        self.cipher.config()
    }
}

pub const SQLCIPHER3_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher3",
    cipher: FixtureCipher::SqlCipher3,
    encrypted: include_bytes!("../fixtures/sqlcipher/3.db"),
    passphrase: b"veilite-sqlcipher3-test-key",
    page_size: 1024,
};

const SQLCIPHER4_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher4",
    cipher: FixtureCipher::SqlCipher4,
    encrypted: include_bytes!("../fixtures/sqlcipher/4.db"),
    passphrase: b"veilite-sqlcipher4-test-key",
    page_size: 4096,
};

const SQLCIPHER_CUSTOM_CASE: FixtureCase = FixtureCase {
    name: "sqlcipher-custom",
    cipher: FixtureCipher::Custom,
    encrypted: include_bytes!("../fixtures/sqlcipher/custom.db"),
    passphrase: b"veilite-sqlcipher-custom-test-key",
    page_size: 2048,
};

pub const FIXTURE_CASES: [FixtureCase; 3] =
    [SQLCIPHER3_CASE, SQLCIPHER4_CASE, SQLCIPHER_CUSTOM_CASE];
