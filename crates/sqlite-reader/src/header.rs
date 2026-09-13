use crate::ReaderError;

/// Encoding used for text in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    /// UTF-8 bytes.
    Utf8,
    /// Little-endian UTF-16 code units.
    Utf16Le,
    /// Big-endian UTF-16 code units.
    Utf16Be,
}

/// Validated metadata from the 100-byte SQLite database header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub(crate) page_size: u32,
    reserved_bytes: u8,
    page_count: u32,
    encoding: TextEncoding,
    user_version: u32,
    application_id: u32,
}

impl Header {
    pub(crate) fn parse<E>(bytes: &[u8; 100], length: u64) -> Result<Self, ReaderError<E>> {
        Self::parse_inner(bytes, length, false)
    }

    pub(crate) fn snapshot<E>(
        bytes: &[u8; 100],
        size: u32,
        count: u32,
    ) -> Result<Self, ReaderError<E>> {
        let header = Self::parse_inner(bytes, u64::from(size) * u64::from(count), true)?;
        if header.page_size != size {
            return Err(ReaderError::InvalidFormat(
                "source and header page sizes differ",
            ));
        }
        Ok(header)
    }

    fn parse_inner<E>(
        bytes: &[u8; 100],
        length: u64,
        snapshot: bool,
    ) -> Result<Self, ReaderError<E>> {
        use ReaderError::{InvalidFormat, Unsupported};
        if &bytes[..16] != b"SQLite format 3\0" {
            return Err(InvalidFormat("invalid magic"));
        }
        let encoded_size = u16::from_be_bytes([bytes[16], bytes[17]]);
        let page_size = if encoded_size == 1 {
            65_536
        } else {
            u32::from(encoded_size)
        };
        if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(InvalidFormat("invalid page size"));
        }
        if usize::try_from(page_size).is_err() {
            return Err(Unsupported("page size exceeds addressable memory"));
        }
        if !length.is_multiple_of(u64::from(page_size)) {
            return Err(InvalidFormat("file does not contain whole pages"));
        }
        let physical_pages = length / u64::from(page_size);
        if !(1..=u64::from(u32::MAX - 1)).contains(&physical_pages) {
            return Err(InvalidFormat(
                "physical page count is outside SQLite limits",
            ));
        }
        if !matches!(bytes[19], 1 | 2) {
            return Err(Unsupported("file read version"));
        }
        // SQLite permits read-only access with a newer write version when the
        // read version is understood. Version zero is still malformed.
        if bytes[18] == 0 {
            return Err(InvalidFormat("invalid file write version"));
        }
        let reserved_bytes = bytes[20];
        if page_size - u32::from(reserved_bytes) < 480 {
            return Err(InvalidFormat("usable page size is less than 480 bytes"));
        }
        if bytes[21..24] != [64, 32, 32] {
            return Err(InvalidFormat("invalid payload fractions"));
        }
        if bytes[72..92].iter().any(|byte| *byte != 0) {
            return Err(InvalidFormat("nonzero reserved header bytes"));
        }
        let field = |offset| {
            u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        };
        if field(44) != 4 {
            return Err(Unsupported("schema format (only format 4 is supported)"));
        }
        let encoding = match field(56) {
            1 => TextEncoding::Utf8,
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            _ => return Err(Unsupported("text encoding")),
        };
        let declared_pages = field(28);
        // SQLite only trusts the header count when both counters agree.
        let page_count = if !snapshot && declared_pages != 0 && field(24) == field(92) {
            if u64::from(declared_pages) > physical_pages {
                return Err(InvalidFormat("database size exceeds the physical file"));
            }
            declared_pages
        } else {
            u32::try_from(physical_pages).map_err(|_| InvalidFormat("page count overflow"))?
        };
        Ok(Self {
            page_size,
            reserved_bytes,
            page_count,
            encoding,
            user_version: field(60),
            application_id: field(68),
        })
    }

    /// Physical page size, including reserved bytes.
    pub fn page_size(&self) -> usize {
        self.page_size as usize
    }
    /// Bytes reserved at the end of each page.
    pub fn reserved_bytes(&self) -> u8 {
        self.reserved_bytes
    }
    /// Bytes available to SQLite on each page.
    pub fn usable_size(&self) -> usize {
        self.page_size() - usize::from(self.reserved_bytes)
    }
    /// Logical page count, using the physical count when header counters disagree.
    pub fn page_count(&self) -> u32 {
        self.page_count
    }
    /// Database text encoding.
    pub fn text_encoding(&self) -> TextEncoding {
        self.encoding
    }
    /// Application-defined user version.
    pub fn user_version(&self) -> u32 {
        self.user_version
    }
    /// Application-defined file identifier.
    pub fn application_id(&self) -> u32 {
        self.application_id
    }
}
