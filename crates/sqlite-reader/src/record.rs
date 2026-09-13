use crate::{ReaderError, TextEncoding};

/// A text value retaining its original bytes and database encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    bytes: Vec<u8>,
    encoding: TextEncoding,
}

/// Invalid text encoding; decoding never substitutes replacement characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid database text encoding")]
pub struct TextError;

impl Text {
    pub(crate) fn new(bytes: Vec<u8>, encoding: TextEncoding) -> Self {
        Self { bytes, encoding }
    }
    pub(crate) fn encode(value: &str, encoding: TextEncoding) -> Self {
        let bytes = match encoding {
            TextEncoding::Utf8 => value.as_bytes().to_vec(),
            TextEncoding::Utf16Le => value.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            TextEncoding::Utf16Be => value.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        };
        Self { bytes, encoding }
    }
    /// Original bytes, without a terminator.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Encoding of the original bytes.
    pub fn encoding(&self) -> TextEncoding {
        self.encoding
    }
    /// Decodes to Unicode, rejecting malformed UTF-8 or UTF-16.
    pub fn to_string(&self) -> Result<String, TextError> {
        match self.encoding {
            TextEncoding::Utf8 => String::from_utf8(self.bytes.clone()).map_err(|_| TextError),
            encoding => {
                if !self.bytes.len().is_multiple_of(2) {
                    return Err(TextError);
                }
                let units = self.bytes.chunks_exact(2).map(|b| match encoding {
                    TextEncoding::Utf16Le => u16::from_le_bytes([b[0], b[1]]),
                    _ => u16::from_be_bytes([b[0], b[1]]),
                });
                char::decode_utf16(units)
                    .map(|c| c.map_err(|_| TextError))
                    .collect()
            }
        }
    }
}

/// SQLite value, with text kept in its database encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// Signed 64-bit integer.
    Integer(i64),
    /// IEEE 754 double precision value.
    Real(f64),
    /// Encoded text, including potentially invalid Unicode.
    Text(Text),
    /// Arbitrary binary data.
    Blob(Vec<u8>),
}

pub(crate) fn varint<E>(bytes: &[u8], offset: &mut usize) -> Result<u64, ReaderError<E>> {
    let mut value = 0u64;
    for index in 0..9 {
        let byte = *bytes
            .get(*offset)
            .ok_or(ReaderError::InvalidFormat("truncated varint"))?;
        *offset += 1;
        if index == 8 {
            return Ok((value << 8) | u64::from(byte));
        }
        value = (value << 7) | u64::from(byte & 127);
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(ReaderError::InvalidFormat("invalid varint"))
}

pub(crate) fn decode<E>(
    bytes: &[u8],
    encoding: TextEncoding,
) -> Result<Vec<Value>, ReaderError<E>> {
    use ReaderError::InvalidFormat;
    let mut offset = 0;
    let header_size = usize::try_from(varint(bytes, &mut offset)?)
        .map_err(|_| InvalidFormat("record header size overflow"))?;
    let header = bytes
        .get(..header_size)
        .filter(|_| header_size >= offset)
        .ok_or(InvalidFormat("invalid record header size"))?;
    let mut body = header_size;
    let mut values = Vec::new();
    while offset < header_size {
        let serial = varint(header, &mut offset)?;
        let size = match serial {
            0 | 8 | 9 => 0,
            1..=4 => serial,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return Err(InvalidFormat("reserved serial type")),
            _ => (serial - 12) / 2,
        };
        let size =
            usize::try_from(size).map_err(|_| InvalidFormat("record value size overflow"))?;
        let end = body
            .checked_add(size)
            .ok_or(InvalidFormat("record size overflow"))?;
        let data = bytes
            .get(body..end)
            .ok_or(InvalidFormat("truncated record body"))?;
        let value = match serial {
            0 => Value::Null,
            1..=6 => {
                let mut encoded = if data[0] & 128 != 0 { [255; 8] } else { [0; 8] };
                encoded[8 - size..].copy_from_slice(data);
                Value::Integer(i64::from_be_bytes(encoded))
            }
            7 => {
                let mut encoded = [0; 8];
                encoded.copy_from_slice(data);
                let real = f64::from_be_bytes(encoded);
                if real.is_nan() {
                    return Err(InvalidFormat("NaN in stored record"));
                }
                Value::Real(real)
            }
            8 => Value::Integer(0),
            9 => Value::Integer(1),
            _ if serial % 2 == 0 => Value::Blob(data.to_vec()),
            _ => Value::Text(Text::new(data.to_vec(), encoding)),
        };
        values.try_reserve(1).map_err(|_| ReaderError::Allocation)?;
        values.push(value);
        body = end;
    }
    if body != bytes.len() {
        return Err(InvalidFormat("trailing record payload"));
    }
    Ok(values)
}
