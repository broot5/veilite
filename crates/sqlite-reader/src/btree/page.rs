use super::{Kind, word};
use crate::{ReaderError, record::varint};

pub(super) struct Cell {
    pub(super) child: Option<u32>,
    pub(super) rowid: Option<i64>,
    pub(super) start: usize,
    pub(super) local: usize,
    pub(super) total: usize,
    pub(super) overflow: u32,
}

pub(super) struct ParsedPage {
    pub(super) leaf: bool,
    pub(super) cells: Vec<Cell>,
    pub(super) right_child: Option<u32>,
}

// The cursor supplies a full page with the usable size validated by Reader.
// Parsing validates cells and freeblocks without reading pages or scheduling traversal.
pub(super) fn parse<E>(
    bytes: &[u8],
    number: u32,
    expected_kind: Kind,
    page_count: u32,
) -> Result<ParsedPage, ReaderError<E>> {
    use ReaderError::InvalidFormat;
    let usable = bytes.len();
    let base = if number == 1 { 100 } else { 0 };
    let flag = bytes[base];
    let (kind, leaf) = match flag {
        2 => (Kind::Index, false),
        5 => (Kind::Table, false),
        10 => (Kind::Index, true),
        13 => (Kind::Table, true),
        _ => return Err(InvalidFormat("invalid B-tree page type")),
    };
    if kind != expected_kind {
        return Err(InvalidFormat("mixed B-tree page types"));
    }
    let short = |offset: usize| usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
    let count = short(base + 3);
    let header_end = base + if leaf { 8 } else { 12 };
    let pointers_end = header_end + count * 2;
    let content = match short(base + 5) {
        0 => 65536,
        n => n,
    };
    if pointers_end > content || content > usable || bytes[base + 7] > 60 {
        return Err(InvalidFormat("invalid B-tree cell area"));
    }
    let mut intervals = Vec::new();
    let mut free = short(base + 1);
    while free != 0 {
        if free < content || free + 4 > usable {
            return Err(InvalidFormat("invalid freeblock offset"));
        }
        let next = short(free);
        let size = short(free + 2);
        if size < 4 || free + size > usable || (next != 0 && next < free + size) {
            return Err(InvalidFormat("invalid freeblock chain"));
        }
        intervals.push((free, free + size));
        free = next;
    }
    let mut cells = Vec::with_capacity(count);
    for index in 0..count {
        let begin = short(header_end + index * 2);
        if begin < content || begin >= usable {
            return Err(InvalidFormat("invalid cell pointer"));
        }
        let mut offset = begin;
        let child = if leaf {
            None
        } else {
            let child = word(bytes, offset)?;
            offset += 4;
            Some(child)
        };
        let total = if kind == Kind::Table && !leaf {
            0
        } else {
            let size = varint(bytes, &mut offset)?;
            if size > i32::MAX as u64 || size > u64::from(page_count) * usable as u64 {
                return Err(InvalidFormat("payload exceeds database limits"));
            }
            usize::try_from(size).map_err(|_| InvalidFormat("payload size overflow"))?
        };
        let rowid = if kind == Kind::Table {
            Some(i64::from_be_bytes(
                varint(bytes, &mut offset)?.to_be_bytes(),
            ))
        } else {
            None
        };
        let max = if kind == Kind::Table {
            usable - 35
        } else {
            (usable - 12) * 64 / 255 - 23
        };
        let local = if total <= max {
            total
        } else {
            let min = (usable - 12) * 32 / 255 - 23;
            let candidate = min + (total - min) % (usable - 4);
            if candidate <= max { candidate } else { min }
        };
        let end = offset
            .checked_add(local)
            .ok_or(InvalidFormat("cell size overflow"))?;
        let overflow = if total > local { word(bytes, end)? } else { 0 };
        let cell_end = end
            .checked_add(if total > local { 4 } else { 0 })
            .ok_or(InvalidFormat("cell size overflow"))?;
        if cell_end > usable {
            return Err(InvalidFormat("cell exceeds usable page"));
        }
        intervals.push((begin, cell_end));
        cells.push(Cell {
            child,
            rowid,
            start: offset,
            local,
            total,
            overflow,
        });
    }
    intervals.sort_unstable();
    if intervals.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(InvalidFormat("overlapping cells or freeblocks"));
    }
    let right_child = if leaf {
        None
    } else {
        Some(word(bytes, base + 8)?)
    };
    Ok(ParsedPage {
        leaf,
        cells,
        right_child,
    })
}
