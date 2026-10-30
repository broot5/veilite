use crate::FixtureCipher;

impl FixtureCipher {
    pub fn cli_options(self) -> &'static [&'static str] {
        match self {
            Self::SqlCipher3 => &["--preset", "3"],
            Self::SqlCipher4 => &["--preset", "4"],
            Self::Custom => &[
                "--custom",
                "--page-size",
                "2048",
                "--kdf-iterations",
                "100000",
                "--kdf-algorithm",
                "sha256",
                "--hmac-algorithm",
                "sha256",
            ],
        }
    }
}
