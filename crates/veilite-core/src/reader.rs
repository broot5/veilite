use std::num::NonZeroU32;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::decryptor::PageDecryptor;
use crate::{CipherConfig, DecryptError, ReadAt};

const DATABASE_SALT_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum ReaderError<E> {
    #[error("source read failed: {0}")]
    Source(#[source] E),
    #[error("database decryption failed: {0}")]
    Decrypt(#[from] DecryptError),
    #[error("the encrypted database is empty")]
    EmptyFile,
    #[error(
        "encrypted database is shorter than one page: {file_size} bytes for a {page_size}-byte page"
    )]
    FileTooSmall { file_size: u64, page_size: usize },
    #[error("encrypted database size {file_size} is not a multiple of page size {page_size}")]
    InvalidFileSize { file_size: u64, page_size: usize },
    #[error("encrypted database has too many pages: {page_count}")]
    TooManyPages { page_count: u64 },
    #[error("page {page_no} is outside the database page range 1..={page_count}")]
    PageOutOfRange { page_no: u32, page_count: u32 },
    #[error("read range at offset {offset} with length {length} overflows")]
    OffsetOverflow { offset: u64, length: usize },
    #[error("read range at offset {offset} with length {length} exceeds database size {file_size}")]
    UnexpectedEof {
        offset: u64,
        length: usize,
        file_size: u64,
    },
}

pub struct SqlCipherReader<R> {
    source: R,
    decryptor: PageDecryptor,
    file_size: u64,
    page_count: u32,
}

impl<R: ReadAt> SqlCipherReader<R> {
    pub fn open(
        source: R,
        config: CipherConfig,
        passphrase: &[u8],
    ) -> Result<Self, ReaderError<R::Error>> {
        let file_size = source.len().map_err(ReaderError::Source)?;
        let page_size = config.page_size();
        let page_size_u64 = page_size as u64;

        if file_size == 0 {
            return Err(ReaderError::EmptyFile);
        }
        if file_size < page_size_u64 {
            return Err(ReaderError::FileTooSmall {
                file_size,
                page_size,
            });
        }
        if !file_size.is_multiple_of(page_size_u64) {
            return Err(ReaderError::InvalidFileSize {
                file_size,
                page_size,
            });
        }

        let page_count_u64 = file_size / page_size_u64;
        let page_count = u32::try_from(page_count_u64).map_err(|_| ReaderError::TooManyPages {
            page_count: page_count_u64,
        })?;

        let mut salt = [0; DATABASE_SALT_SIZE];
        source
            .read_exact_at(0, &mut salt)
            .map_err(ReaderError::Source)?;
        let decryptor = PageDecryptor::new(config, passphrase, &salt)?;

        Ok(Self {
            source,
            decryptor,
            file_size,
            page_count,
        })
    }

    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.decryptor.page_size()
    }

    #[must_use]
    pub const fn page_count(&self) -> u32 {
        self.page_count
    }

    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    pub fn read_page_into(
        &self,
        page_no: NonZeroU32,
        output: &mut [u8],
    ) -> Result<(), ReaderError<R::Error>> {
        let page_size = self.page_size();
        if output.len() != page_size {
            return Err(DecryptError::InvalidOutputPageLength {
                expected: page_size,
                actual: output.len(),
            }
            .into());
        }
        output.fill(0);

        let page_number = page_no.get();
        if page_number > self.page_count {
            return Err(ReaderError::PageOutOfRange {
                page_no: page_number,
                page_count: self.page_count,
            });
        }

        let page_index = u64::from(page_number - 1);
        let encrypted_offset =
            page_index
                .checked_mul(page_size as u64)
                .ok_or(ReaderError::OffsetOverflow {
                    offset: page_index,
                    length: page_size,
                })?;
        let mut encrypted_page = vec![0; page_size];
        if let Err(error) = self
            .source
            .read_exact_at(encrypted_offset, &mut encrypted_page)
        {
            output.zeroize();
            return Err(ReaderError::Source(error));
        }

        self.decryptor
            .decrypt_page_into(page_no, &encrypted_page, output)?;

        Ok(())
    }

    pub fn read_exact_at(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), ReaderError<R::Error>> {
        if output.is_empty() {
            return Ok(());
        }
        output.fill(0);

        let result = self.read_exact_at_nonempty(offset, output);
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    fn read_exact_at_nonempty(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), ReaderError<R::Error>> {
        let length_u64 = u64::try_from(output.len()).map_err(|_| ReaderError::OffsetOverflow {
            offset,
            length: output.len(),
        })?;
        let end = offset
            .checked_add(length_u64)
            .ok_or(ReaderError::OffsetOverflow {
                offset,
                length: output.len(),
            })?;
        if end > self.file_size {
            return Err(ReaderError::UnexpectedEof {
                offset,
                length: output.len(),
                file_size: self.file_size,
            });
        }

        let page_size = self.page_size();
        let page_size_u64 = page_size as u64;
        let mut plaintext_page = Zeroizing::new(vec![0; page_size]);
        let mut database_offset = offset;
        let mut output_offset = 0;

        while output_offset < output.len() {
            let page_index = database_offset / page_size_u64;
            let page_number = page_index
                .checked_add(1)
                .and_then(|number| u32::try_from(number).ok())
                .and_then(NonZeroU32::new)
                .ok_or(ReaderError::OffsetOverflow {
                    offset,
                    length: output.len(),
                })?;
            let offset_in_page =
                usize::try_from(database_offset % page_size_u64).map_err(|_| {
                    ReaderError::OffsetOverflow {
                        offset,
                        length: output.len(),
                    }
                })?;
            let copy_length = (page_size - offset_in_page).min(output.len() - output_offset);

            self.read_page_into(page_number, &mut plaintext_page)?;

            output[output_offset..output_offset + copy_length]
                .copy_from_slice(&plaintext_page[offset_in_page..offset_in_page + copy_length]);
            output_offset += copy_length;
            database_offset = database_offset
                .checked_add(u64::try_from(copy_length).map_err(|_| {
                    ReaderError::OffsetOverflow {
                        offset,
                        length: output.len(),
                    }
                })?)
                .ok_or(ReaderError::OffsetOverflow {
                    offset,
                    length: output.len(),
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
