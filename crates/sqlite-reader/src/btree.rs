mod page;

use crate::{PageSource, ReaderError};
use page::Cell;
use std::{collections::HashSet, num::NonZeroU32, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Table,
    Index,
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
        let page = Arc::new(self.load(number)?);
        let parsed = page::parse(
            &page[..self.usable],
            number,
            self.kind,
            self.source.page_count(),
        )?;
        if let Some(right_child) = parsed.right_child {
            self.tasks.push(Task::Visit(right_child));
        }
        for cell in parsed.cells.into_iter().rev() {
            let child = cell.child;
            if parsed.leaf || self.kind == Kind::Index {
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
