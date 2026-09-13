use crate::record::varint;
use crate::{PageSource, ReaderError};
use std::{collections::HashSet, num::NonZeroU32, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Table,
    Index,
}

struct Cell {
    child: Option<u32>,
    rowid: Option<i64>,
    start: usize,
    local: usize,
    total: usize,
    overflow: u32,
}

enum Task {
    Visit(u32),
    Emit(Arc<Vec<u8>>, Cell),
}

pub(crate) struct Cursor<'a, S: PageSource> {
    source: &'a S,
    kind: Kind,
    usable: usize,
    tasks: Vec<Task>,
    visited: HashSet<u32>,
    failed: bool,
}

pub(crate) struct Record {
    pub rowid: Option<i64>,
    pub payload: Vec<u8>,
}

pub(crate) fn word<E>(bytes: &[u8], offset: usize) -> Result<u32, ReaderError<E>> {
    let b = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(ReaderError::InvalidFormat("offset overflow"))?,
        )
        .ok_or(ReaderError::InvalidFormat("truncated page pointer"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

impl<'a, S: PageSource> Cursor<'a, S> {
    pub fn new(source: &'a S, root: u32, kind: Kind, usable: usize) -> Self {
        Self {
            source,
            kind,
            usable,
            tasks: vec![Task::Visit(root)],
            visited: HashSet::new(),
            failed: false,
        }
    }

    fn load(&mut self, page: u32) -> Result<Vec<u8>, ReaderError<S::Error>> {
        if page == 0 || page > self.source.page_count() {
            return Err(ReaderError::PageOutOfRange(page));
        }
        if !self.visited.insert(page) {
            return Err(ReaderError::InvalidFormat(
                "reused or cyclic page reference",
            ));
        }
        let mut bytes = vec![0; self.source.page_size()];
        self.source
            .read_page_into(
                NonZeroU32::new(page).ok_or(ReaderError::PageOutOfRange(page))?,
                &mut bytes,
            )
            .map_err(ReaderError::Source)?;
        Ok(bytes)
    }

    fn visit(&mut self, number: u32) -> Result<(), ReaderError<S::Error>> {
        use ReaderError::InvalidFormat;
        let page = Arc::new(self.load(number)?);
        let bytes = &page[..self.usable];
        let base = if number == 1 { 100 } else { 0 };
        let flag = bytes[base];
        let (kind, leaf) = match flag {
            2 => (Kind::Index, false),
            5 => (Kind::Table, false),
            10 => (Kind::Index, true),
            13 => (Kind::Table, true),
            _ => return Err(InvalidFormat("invalid B-tree page type")),
        };
        if kind != self.kind {
            return Err(InvalidFormat("mixed B-tree page types"));
        }
        let short =
            |offset: usize| usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        let count = short(base + 3);
        let header_end = base + if leaf { 8 } else { 12 };
        let pointers_end = header_end + count * 2;
        let content = match short(base + 5) {
            0 => 65536,
            n => n,
        };
        if pointers_end > content || content > self.usable || bytes[base + 7] > 60 {
            return Err(InvalidFormat("invalid B-tree cell area"));
        }
        let mut intervals = Vec::new();
        let mut free = short(base + 1);
        while free != 0 {
            if free < content || free + 4 > self.usable {
                return Err(InvalidFormat("invalid freeblock offset"));
            }
            let next = short(free);
            let size = short(free + 2);
            if size < 4 || free + size > self.usable || (next != 0 && next < free + size) {
                return Err(InvalidFormat("invalid freeblock chain"));
            }
            intervals.push((free, free + size));
            free = next;
        }
        let mut cells = Vec::with_capacity(count);
        for index in 0..count {
            let begin = short(header_end + index * 2);
            if begin < content || begin >= self.usable {
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
                if size > i32::MAX as u64
                    || size > u64::from(self.source.page_count()) * self.usable as u64
                {
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
                self.usable - 35
            } else {
                (self.usable - 12) * 64 / 255 - 23
            };
            let local = if total <= max {
                total
            } else {
                let min = (self.usable - 12) * 32 / 255 - 23;
                let candidate = min + (total - min) % (self.usable - 4);
                if candidate <= max { candidate } else { min }
            };
            let end = offset
                .checked_add(local)
                .ok_or(InvalidFormat("cell size overflow"))?;
            let overflow = if total > local { word(bytes, end)? } else { 0 };
            let cell_end = end
                .checked_add(if total > local { 4 } else { 0 })
                .ok_or(InvalidFormat("cell size overflow"))?;
            if cell_end > self.usable {
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
        if !leaf {
            self.tasks.push(Task::Visit(word(bytes, base + 8)?));
        }
        for cell in cells.into_iter().rev() {
            let child = cell.child;
            if leaf || kind == Kind::Index {
                self.tasks.push(Task::Emit(Arc::clone(&page), cell));
            }
            if let Some(child) = child {
                self.tasks.push(Task::Visit(child));
            }
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<Option<Record>, ReaderError<S::Error>> {
        use ReaderError::InvalidFormat;
        while let Some(task) = self.tasks.pop() {
            match task {
                Task::Visit(number) => self.visit(number)?,
                Task::Emit(page, cell) => {
                    let mut payload = page[cell.start..cell.start + cell.local].to_vec();
                    let mut next = cell.overflow;
                    while payload.len() < cell.total {
                        let overflow = self.load(next)?;
                        next = word(&overflow, 0)?;
                        let take = (cell.total - payload.len()).min(self.usable - 4);
                        payload
                            .try_reserve(take)
                            .map_err(|_| ReaderError::Allocation)?;
                        payload.extend_from_slice(&overflow[4..4 + take]);
                    }
                    if next != 0 {
                        return Err(InvalidFormat("overflow chain exceeds payload"));
                    }
                    return Ok(Some(Record {
                        rowid: cell.rowid,
                        payload,
                    }));
                }
            }
        }
        Ok(None)
    }
}

impl<S: PageSource> Iterator for Cursor<'_, S> {
    type Item = Result<Record, ReaderError<S::Error>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.advance() {
            Ok(record) => record.map(Ok),
            Err(error) => {
                self.failed = true;
                self.tasks.clear();
                Some(Err(error))
            }
        }
    }
}
