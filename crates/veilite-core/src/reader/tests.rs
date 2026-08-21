use std::io;
use std::num::NonZeroU32;

use super::*;
use crate::{CipherPreset, SliceSource};

#[test]
fn rejects_invalid_file_sizes_before_key_derivation() {
    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let page_size = CipherConfig::from(preset).page_size();
        assert!(matches!(open_error(&[], preset), ReaderError::EmptyFile));

        let too_small = vec![0; page_size - 1];
        assert!(matches!(
            open_error(&too_small, preset),
            ReaderError::FileTooSmall {
                file_size,
                page_size: actual_page_size,
            } if file_size == u64::try_from(page_size - 1).unwrap()
                && actual_page_size == page_size
        ));

        let incomplete = vec![0; page_size + 1];
        assert!(matches!(
            open_error(&incomplete, preset),
            ReaderError::InvalidFileSize {
                file_size,
                page_size: actual_page_size,
            } if file_size == u64::try_from(page_size + 1).unwrap()
                && actual_page_size == page_size
        ));
    }
}

fn open_error(bytes: &[u8], preset: CipherPreset) -> ReaderError<io::Error> {
    match SqlCipherReader::open(
        SliceSource::new(bytes),
        CipherConfig::from(preset),
        b"passphrase",
    ) {
        Ok(_) => panic!("invalid encrypted database should be rejected"),
        Err(error) => error,
    }
}

struct LengthOnlySource {
    length: u64,
}

impl ReadAt for LengthOnlySource {
    type Error = io::Error;

    fn read_exact_at(&self, _offset: u64, _output: &mut [u8]) -> io::Result<()> {
        unreachable!("oversized database should be rejected before reading the source")
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.length)
    }
}

#[test]
fn rejects_more_pages_than_u32_can_address() {
    let page_count = u64::from(u32::MAX) + 1;

    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let config = CipherConfig::from(preset);
        let source = LengthOnlySource {
            length: page_count * u64::try_from(config.page_size()).unwrap(),
        };
        let Err(error) = SqlCipherReader::open(source, config, b"passphrase") else {
            panic!("oversized database should be rejected");
        };

        assert!(matches!(
            error,
            ReaderError::TooManyPages {
                page_count: actual_page_count,
            } if actual_page_count == page_count
        ));
    }
}

#[test]
fn rejects_invalid_output_page_lengths_and_clears_output() {
    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let config = CipherConfig::from(preset);
        let encrypted = vec![0; config.page_size()];
        let reader =
            SqlCipherReader::open(SliceSource::new(&encrypted), config, b"passphrase").unwrap();

        for actual in [config.page_size() - 1, config.page_size() + 1] {
            let mut output = vec![0xaa; actual];

            let error = reader
                .read_page_into(NonZeroU32::new(1).unwrap(), &mut output)
                .unwrap_err();

            assert!(matches!(
                error,
                ReaderError::InvalidOutputPageLength {
                    expected,
                    actual: error_actual,
                } if expected == config.page_size() && error_actual == actual
            ));
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}

#[test]
fn rejects_out_of_range_pages_and_reads() {
    for preset in [CipherPreset::SqlCipher3, CipherPreset::SqlCipher4] {
        let config = CipherConfig::from(preset);
        let encrypted = vec![0; config.page_size()];
        let reader =
            SqlCipherReader::open(SliceSource::new(&encrypted), config, b"passphrase").unwrap();
        let mut page = vec![0xaa; reader.page_size()];

        let error = reader
            .read_page_into(NonZeroU32::new(2).unwrap(), &mut page)
            .unwrap_err();
        assert!(matches!(
            error,
            ReaderError::PageOutOfRange {
                page_no: 2,
                page_count: 1,
            }
        ));
        assert!(page.iter().all(|byte| *byte == 0));

        let mut output = [0xaa; 2];
        let error = reader
            .read_exact_at(reader.file_size() - 1, &mut output)
            .unwrap_err();
        assert!(matches!(error, ReaderError::UnexpectedEof { .. }));
        assert_eq!(output, [0; 2]);

        let error = reader.read_exact_at(u64::MAX, &mut output).unwrap_err();
        assert!(matches!(error, ReaderError::OffsetOverflow { .. }));
        assert_eq!(output, [0; 2]);

        reader.read_exact_at(u64::MAX, &mut []).unwrap();
    }
}

struct MisreportedLengthSource {
    bytes: Vec<u8>,
    reported_length: u64,
}

impl ReadAt for MisreportedLengthSource {
    type Error = io::Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        SliceSource::new(&self.bytes).read_exact_at(offset, output)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.reported_length)
    }
}

#[test]
fn rejects_short_source_reads_and_clears_output() {
    let config = CipherConfig::from(CipherPreset::SqlCipher4);
    let source = MisreportedLengthSource {
        bytes: vec![0; config.page_size() * 2 - 1],
        reported_length: u64::try_from(config.page_size() * 2).unwrap(),
    };
    let reader = SqlCipherReader::open(source, config, b"passphrase").unwrap();
    let mut output = vec![0xaa; reader.page_size()];

    let error = reader
        .read_page_into(NonZeroU32::new(reader.page_count()).unwrap(), &mut output)
        .unwrap_err();

    assert!(matches!(
        error,
        ReaderError::Source(source_error)
            if source_error.kind() == io::ErrorKind::UnexpectedEof
    ));
    assert!(output.iter().all(|byte| *byte == 0));
}
