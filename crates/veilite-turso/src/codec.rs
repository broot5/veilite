use std::num::NonZeroU32;

use sha2::{Digest, Sha256};
use turso_core::{PageCodec, PageCodecContext, PageCodecHeaderInfo, PageCodecId, PageLocation};
use veilite_core::{CipherConfig, HashAlgorithm, PageDecryptor};
use zeroize::Zeroize;

pub(super) struct SqlCipherCodec {
    decoder: PageDecryptor,
    config: CipherConfig,
    id: PageCodecId,
    page_count: u32,
    wal_page_limit: Option<u32>,
}

impl SqlCipherCodec {
    pub(super) fn new(
        decoder: PageDecryptor,
        config: CipherConfig,
        salt: [u8; 16],
        page_count: u32,
        wal_pages: Option<u32>,
        wal_identity: Option<&str>,
    ) -> Self {
        // Non-secret format identity only. Authentication with each caller's
        // key is mandatory before entering Turso's shared database registry.
        // Bind WAL mode to its canonical main path as well: hard links may
        // share a main-file identity while naming different sibling WALs.
        let digest = Sha256::new()
            .chain_update(b"veilite-sqlcipher-codec-v1")
            .chain_update((config.page_size() as u32).to_le_bytes())
            .chain_update(config.kdf_iterations().to_le_bytes())
            .chain_update([
                algorithm_id(config.kdf_algorithm()),
                algorithm_id(config.hmac_algorithm()),
            ])
            .chain_update(salt)
            .chain_update([u8::from(wal_pages.is_some())])
            .chain_update(wal_identity.unwrap_or_default().as_bytes())
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Self {
            decoder,
            config,
            id: PageCodecId::new(id),
            page_count,
            wal_page_limit: wal_pages.map(|frames| page_count.saturating_add(frames)),
        }
    }
}

fn algorithm_id(algorithm: HashAlgorithm) -> u8 {
    match algorithm {
        HashAlgorithm::Sha1 => 1,
        HashAlgorithm::Sha256 => 2,
        HashAlgorithm::Sha512 => 3,
    }
}

impl PageCodec for SqlCipherCodec {
    fn codec_id(&self) -> PageCodecId {
        self.id
    }

    fn bootstrap_page_info(&self, _: &[u8]) -> turso_core::Result<PageCodecHeaderInfo> {
        Ok(PageCodecHeaderInfo {
            page_size: self.config.page_size(),
            reserved_space: self.required_reserved_bytes(),
        })
    }

    fn required_reserved_bytes(&self) -> u8 {
        // CipherConfig restricts reserve sizes to 48 or 80 bytes.
        self.config.reserve_size() as u8
    }

    fn encode_page(
        &self,
        _: PageCodecContext,
        _: &[u8],
        output: &mut [u8],
    ) -> turso_core::Result<()> {
        output.zeroize();
        Err(turso_core::LimboError::ReadOnly)
    }

    fn decode_page(
        &self,
        ctx: PageCodecContext,
        input: &[u8],
        output: &mut [u8],
    ) -> turso_core::Result<()> {
        output.zeroize();
        let in_range = match ctx.location {
            PageLocation::Database => ctx.page_no <= self.page_count,
            PageLocation::Wal => self
                .wal_page_limit
                .is_some_and(|limit| ctx.page_no <= limit),
        };
        if !in_range || input.len() != self.config.page_size() || output.len() != input.len() {
            return Err(turso_core::LimboError::InvalidArgument(
                "unsupported SQLCipher page source, number, or length".into(),
            ));
        }
        let page = NonZeroU32::new(ctx.page_no)
            .ok_or_else(|| turso_core::LimboError::InvalidArgument("SQLCipher page zero".into()))?;
        output.copy_from_slice(input);
        self.decoder
            .decrypt_page_in_place(page, output)
            .map_err(|error| turso_core::LimboError::InvalidArgument(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(config: CipherConfig, salt: [u8; 16]) -> SqlCipherCodec {
        SqlCipherCodec::new(
            PageDecryptor::new(config, b"test", &salt).unwrap(),
            config,
            salt,
            2,
            None,
            None,
        )
    }

    #[test]
    fn rejects_invalid_contexts_and_clears_output() {
        let config =
            CipherConfig::new(1024, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap();
        let codec = codec(config, [0; 16]);
        for (page, location, input_len, output_len) in [
            (0, PageLocation::Database, 1024, 1024),
            (3, PageLocation::Database, 1024, 1024),
            (1, PageLocation::Wal, 1024, 1024),
            (1, PageLocation::Database, 1023, 1024),
            (1, PageLocation::Database, 1024, 1023),
            (1, PageLocation::Database, 1024, 1024),
        ] {
            let mut output = vec![0xaa; output_len];
            assert!(
                codec
                    .decode_page(
                        PageCodecContext::new(page, location),
                        &vec![0; input_len],
                        &mut output
                    )
                    .is_err()
            );
            assert!(output.iter().all(|b| *b == 0));
        }
        let mut output = vec![0xaa; 1024];
        assert!(
            codec
                .encode_page(
                    PageCodecContext::new(1, PageLocation::Database),
                    &[0; 1024],
                    &mut output
                )
                .is_err()
        );
        assert!(output.iter().all(|b| *b == 0));
    }

    #[test]
    fn codec_identity_covers_configuration_and_salt() {
        let config =
            CipherConfig::new(1024, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap();
        let id = codec(config, [0; 16]).codec_id();
        assert_eq!(id, codec(config, [0; 16]).codec_id());
        assert_ne!(id, codec(config, [1; 16]).codec_id());
        for config in [
            CipherConfig::new(2048, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap(),
            CipherConfig::new(1024, 2, HashAlgorithm::Sha256, HashAlgorithm::Sha256).unwrap(),
            CipherConfig::new(1024, 1, HashAlgorithm::Sha1, HashAlgorithm::Sha256).unwrap(),
            CipherConfig::new(1024, 1, HashAlgorithm::Sha256, HashAlgorithm::Sha512).unwrap(),
        ] {
            assert_ne!(id, codec(config, [0; 16]).codec_id());
        }
    }
}
