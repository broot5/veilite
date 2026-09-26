use sqlite_reader::{
    Database, FileSource, PageSource, ReadAt, ReaderError, SliceSource, TextEncoding,
};
use std::io;
use std::num::NonZeroU32;

const UTF8: &[u8] = include_bytes!("fixtures/header-utf8.db");
const LE: &[u8] = include_bytes!("fixtures/header-utf16le.db");
const BE: &[u8] = include_bytes!("fixtures/header-utf16be.db");

fn set(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn sqlite_fixtures_have_expected_headers_and_exact_pages() {
    for (bytes, size, encoding) in [
        (UTF8, 512, TextEncoding::Utf8),
        (LE, 4096, TextEncoding::Utf16Le),
        (BE, 65536, TextEncoding::Utf16Be),
    ] {
        let db = Database::open(SliceSource::new(bytes)).unwrap();
        assert_eq!(db.page_size(), size);
        assert_eq!(db.page_count(), 2);
        assert_eq!(db.header().text_encoding(), encoding);
        assert_eq!(db.header().reserved_bytes(), 0);
        assert_eq!(db.header().usable_size(), size);
        assert_eq!(db.header().user_version(), 42);
        assert_eq!(db.header().application_id(), 1447382089);
        let mut output = vec![0; size];
        for number in [2, 1, 2] {
            db.read_page_into(NonZeroU32::new(number).unwrap(), &mut output)
                .unwrap();
            let start = (number as usize - 1) * size;
            assert_eq!(output, bytes[start..start + size]);
        }
    }
}

#[test]
fn file_source_reads_independently_of_existing_cursor() {
    use std::io::{Seek, SeekFrom};
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/header-utf8.db");
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    let db = Database::open(FileSource::from(file)).unwrap();
    let mut page = vec![0; db.page_size()];
    db.read_page_into(NonZeroU32::MIN, &mut page).unwrap();
    assert_eq!(page, UTF8[..512]);
}

#[test]
fn all_page_sizes_and_reserve_boundaries() {
    for power in 9..=16 {
        let size = 1usize << power;
        for reserve in [0, 1, 32, 33, 255] {
            let mut bytes = vec![0; size * 2];
            bytes[..100].copy_from_slice(&UTF8[..100]);
            let encoded = if size == 65536 { 1 } else { size as u16 };
            bytes[16..18].copy_from_slice(&encoded.to_be_bytes());
            bytes[20] = reserve;
            let result = Database::open(SliceSource::new(&bytes));
            if size - usize::from(reserve) < 480 {
                assert!(matches!(result, Err(ReaderError::InvalidFormat(_))));
            } else {
                assert_eq!(
                    result.unwrap().header().usable_size(),
                    size - usize::from(reserve)
                );
            }
        }
    }
}

#[test]
fn rejects_malformed_and_unsupported_headers_without_panics() {
    for length in [0, 15, 99, 100, 511, 513, 1023] {
        assert!(Database::open(SliceSource::new(&UTF8[..length])).is_err());
    }
    for (offset, value) in [
        (0, 0),
        (16, 0),
        (17, 3),
        (18, 0),
        (19, 3),
        (20, 33),
        (21, 63),
        (22, 31),
        (23, 31),
        (47, 1),
        (59, 0),
        (59, 4),
        (72, 1),
        (91, 1),
    ] {
        let mut bytes = UTF8.to_vec();
        bytes[offset] = value;
        assert!(
            Database::open(SliceSource::new(&bytes)).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn header_count_is_only_trusted_when_valid() {
    let mut bytes = UTF8.to_vec();
    set(&mut bytes, 28, 3);
    assert!(Database::open(SliceSource::new(&bytes)).is_err());
    set(&mut bytes, 92, 0); // stale counter: use the physical length
    assert_eq!(
        Database::open(SliceSource::new(&bytes))
            .unwrap()
            .page_count(),
        2
    );
    set(&mut bytes, 28, 0);
    assert_eq!(
        Database::open(SliceSource::new(&bytes))
            .unwrap()
            .page_count(),
        2
    );
    bytes.copy_from_slice(UTF8);
    set(&mut bytes, 28, 1);
    let db = Database::open(SliceSource::new(&bytes)).unwrap();
    assert_eq!(db.page_count(), 1);
    let mut output = [9; 512];
    assert!(matches!(
        db.read_page_into(NonZeroU32::new(2).unwrap(), &mut output),
        Err(ReaderError::PageOutOfRange(2))
    ));
    assert_eq!(output, [0; 512]);
}

struct FailingPages;
impl ReadAt for FailingPages {
    type Error = io::Error;
    fn len(&self) -> io::Result<u64> {
        Ok(1024)
    }
    fn read_exact_at(&self, _: u64, output: &mut [u8]) -> io::Result<()> {
        if output.len() == 100 {
            output.copy_from_slice(&UTF8[..100]);
            Ok(())
        } else {
            output[..10].fill(42);
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }
}

#[test]
fn failed_page_reads_clear_partial_output_and_preserve_source_error() {
    let db = Database::open(FailingPages).unwrap();
    let mut output = [9; 512];
    let error = db.read_page_into(NonZeroU32::MIN, &mut output).unwrap_err();
    assert!(matches!(error, ReaderError::Source(e) if e.kind() == io::ErrorKind::UnexpectedEof));
    assert_eq!(output, [0; 512]);
    let mut short = [9; 4];
    assert!(matches!(
        db.read_page_into(NonZeroU32::MIN, &mut short),
        Err(ReaderError::InvalidOutputLength)
    ));
    assert_eq!(short, [0; 4]);
}

#[test]
fn checkpointed_wal_mode_header_is_not_automatically_rejected() {
    let mut bytes = UTF8.to_vec();
    bytes[18..20].fill(2);
    assert!(Database::open(SliceSource::new(&bytes)).is_ok());
}

#[test]
fn newer_write_versions_allow_readonly_page_access() {
    for read_version in [1, 2] {
        for write_version in [3, u8::MAX] {
            let mut bytes = UTF8.to_vec();
            bytes[18] = write_version;
            bytes[19] = read_version;
            let db = Database::open(SliceSource::new(&bytes)).unwrap();
            let mut page = vec![0; db.page_size()];
            db.read_page_into(NonZeroU32::MIN, &mut page).unwrap();
            assert_eq!(page, bytes[..db.page_size()]);
        }
    }
}

#[test]
fn unsupported_read_versions_are_rejected_regardless_of_write_version() {
    for read_version in [0, 3, u8::MAX] {
        for write_version in [1, 2, 3, u8::MAX] {
            let mut bytes = UTF8.to_vec();
            bytes[18] = write_version;
            bytes[19] = read_version;
            assert!(matches!(
                Database::open(SliceSource::new(&bytes)),
                Err(ReaderError::Unsupported(_))
            ));
        }
    }
}

struct HugeSource(u64);
impl ReadAt for HugeSource {
    type Error = io::Error;
    fn len(&self) -> io::Result<u64> {
        Ok(self.0)
    }
    fn read_exact_at(&self, _: u64, output: &mut [u8]) -> io::Result<()> {
        output.copy_from_slice(&UTF8[..100]);
        set(output, 28, 0);
        Ok(())
    }
}

#[test]
fn physical_page_limit_is_checked_without_allocating_the_file() {
    let max = u64::from(u32::MAX - 1);
    assert_eq!(
        Database::open(HugeSource(max * 512)).unwrap().page_count(),
        u32::MAX - 1
    );
    assert!(Database::open(HugeSource((max + 1) * 512)).is_err());
    assert!(Database::open(HugeSource(u64::MAX)).is_err());
}
