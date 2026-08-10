use std::fs::File;
use std::io;
use std::path::Path;

/// Random-access byte source used by [`crate::SqlCipherReader`].
///
/// The source contents and length must remain unchanged while the reader
/// exists. Each read must use the supplied offset independently of any shared
/// file cursor.
pub trait ReadAt {
    type Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error>;

    fn len(&self) -> Result<u64, Self::Error>;

    fn is_empty(&self) -> Result<bool, Self::Error> {
        self.len().map(|length| length == 0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SliceSource<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceSource<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl ReadAt for SliceSource<'_> {
    type Error = io::Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "source offset does not fit in usize",
            )
        })?;
        let end = start.checked_add(output.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "source range overflows usize")
        })?;
        let bytes = self.bytes.get(start..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source range extends past the end of the slice",
            )
        })?;

        output.copy_from_slice(bytes);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        u64::try_from(self.bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "slice length does not fit in u64",
            )
        })
    }
}

#[derive(Debug)]
pub struct FileSource {
    file: File,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        File::open(path).map(Self::from)
    }
}

impl From<File> for FileSource {
    fn from(file: File) -> Self {
        Self { file }
    }
}

impl ReadAt for FileSource {
    type Error = io::Error;

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_exact_at(output, offset)
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;

            let mut bytes_read = 0;
            while bytes_read < output.len() {
                let current_offset = offset
                    .checked_add(u64::try_from(bytes_read).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "read length does not fit in u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "file offset overflows u64")
                    })?;
                let count = self
                    .file
                    .seek_read(&mut output[bytes_read..], current_offset)?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill the requested file range",
                    ));
                }
                bytes_read += count;
            }
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (offset, output);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cursor-independent file reads are unsupported on this platform",
            ))
        }
    }

    fn len(&self) -> io::Result<u64> {
        self.file.metadata().map(|metadata| metadata.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_source_reads_exact_ranges() {
        let source = SliceSource::new(b"0123456789");
        let mut output = [0; 4];

        source.read_exact_at(3, &mut output).unwrap();

        assert_eq!(&output, b"3456");
        assert_eq!(source.len().unwrap(), 10);
    }

    #[test]
    fn slice_source_rejects_ranges_past_the_end() {
        let source = SliceSource::new(b"0123456789");
        let mut output = [0; 2];

        let error = source.read_exact_at(9, &mut output).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
