use sqlite_reader::{Database, PageSource, Reader, ReaderError, SliceSource, Value};
use std::{io, num::NonZeroU32};

const UTF8: &[u8] = include_bytes!("fixtures/reader-utf8.db");
const LE: &[u8] = include_bytes!("fixtures/reader-utf16le.db");
const BE: &[u8] = include_bytes!("fixtures/reader-utf16be.db");
const STRESS: &[u8] = include_bytes!("fixtures/stress.db");

#[test]
fn large_pages_read_rows_and_empty_leaf_content_offsets() {
    for bytes in [
        &include_bytes!("fixtures/header-utf16le.db")[..],
        &include_bytes!("fixtures/header-utf16be.db")[..],
    ] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("sample").unwrap();
        let rows = table.rows().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rowid(), Some(7));
        assert_eq!(text(rows[0].get("text_value").unwrap()), "hello 한글");
        assert_eq!(
            rows[0].get("payload"),
            Some(&Value::Blob(vec![0, 1, 127, 255]))
        );

        let mut pages = Pages::new(bytes);
        // An empty 65536-byte leaf encodes its content offset as zero.
        let content = (pages.size as u16).to_be_bytes();
        let leaf = pages.page_mut(2);
        leaf.fill(0);
        leaf[0] = 13;
        leaf[5..7].copy_from_slice(&content);
        let reader = Reader::open(pages).unwrap();
        let table = reader.table("sample").unwrap();
        let mut rows = table.rows();
        assert!(rows.next().is_none());
        assert!(rows.next().is_none());
    }
}

#[test]
fn reserved_bytes_are_excluded_from_cells_and_overflow() {
    let mut pages = Pages::new(include_bytes!("fixtures/header-utf8.db"));
    // 512-byte pages with 32 reserved bytes give the minimum usable size, 480.
    // Move the single schema cell before the reserve; its record is unchanged.
    let schema = pages.page_mut(1);
    let start = u16::from_be_bytes([schema[108], schema[109]]) as usize;
    schema.copy_within(start..512, start - 32);
    let start = ((start - 32) as u16).to_be_bytes();
    schema[105..107].copy_from_slice(&start);
    schema[108..110].copy_from_slice(&start);
    schema[20] = 32;
    schema[28..32].copy_from_slice(&4u32.to_be_bytes());

    let blob: Vec<u8> = (0..1000).map(|n| (n % 251) as u8).collect();
    // Record: five-byte header, NULL id/text, BLOB serial type 2012 (1000 bytes).
    let mut record = vec![5, 0, 0, 0x8f, 0x5c];
    record.extend_from_slice(&blob);
    // The 1005-byte payload has 53 local bytes and two 476-byte overflow parts.
    let leaf = pages.page_mut(2);
    leaf.fill(0);
    leaf[0] = 13;
    leaf[3..5].copy_from_slice(&1u16.to_be_bytes());
    leaf[5..7].copy_from_slice(&420u16.to_be_bytes());
    leaf[8..10].copy_from_slice(&420u16.to_be_bytes());
    leaf[420..423].copy_from_slice(&[0x87, 0x6d, 7]); // payload length, rowid
    leaf[423..476].copy_from_slice(&record[..53]);
    leaf[476..480].copy_from_slice(&3u32.to_be_bytes());
    for (part, next) in record[53..].chunks_exact(476).zip([4u32, 0]) {
        let mut overflow = vec![0; 512];
        overflow[..4].copy_from_slice(&next.to_be_bytes());
        overflow[4..480].copy_from_slice(part);
        pages.reversed.insert(0, overflow);
    }
    // Nonzero sentinels make accidental consumption of reserve visible in the BLOB.
    for page in &mut pages.reversed {
        page[480..].fill(0xa5);
    }
    let reader = Reader::open(pages).unwrap();
    assert_eq!(reader.header().usable_size(), 480);
    let table = reader.table("sample").unwrap();
    let rows = table.rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rowid(), Some(7));
    assert_eq!(rows[0].get("id"), Some(&Value::Integer(7)));
    assert_eq!(rows[0].get("text_value"), Some(&Value::Null));
    assert_eq!(rows[0].get("payload"), Some(&Value::Blob(blob)));
}

#[test]
fn duplicate_keys_and_numeric_separators_match_sqlite() {
    let reader = Reader::open(Pages::new(UTF8)).unwrap();
    let mut actual = String::new();
    for name in ["duplicates", "same_key"] {
        let table = reader.table(name).unwrap();
        let row = table.rows().next().unwrap().unwrap();
        let a = match row.get("a").unwrap() {
            Value::Integer(n) => n.to_string(),
            v => text(v),
        };
        let b = match row.get("b").unwrap() {
            Value::Integer(n) => n.to_string(),
            v => text(v),
        };
        actual.push_str(&format!("{}|{a}|{b}\n", text(row.get("payload").unwrap())));
    }
    let table = reader.table("repeated_rowid").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    actual.push_str(&format!(
        "{}|{}|{}\n",
        row.rowid().unwrap(),
        int(row.get("a").unwrap()),
        text(row.get("b").unwrap())
    ));
    let table = reader.table("separators").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    let Value::Real(real) = row.get("r").unwrap() else {
        panic!()
    };
    actual.push_str(&format!(
        "{}|{}|{real:.1}|text|{}\n",
        int(row.get("i").unwrap()),
        int(row.get("h").unwrap()),
        text(row.get("t").unwrap())
    ));
    for name in ["duplicates", "same_key"] {
        for col in reader.table(name).unwrap().columns() {
            actual.push_str(&format!(
                "{}|{}\n",
                col.name(),
                col.primary_key_position().unwrap_or(0)
            ));
        }
    }
    assert_expected(
        &actual,
        include_str!("fixtures/reader-ddl.expected"),
        "reader-utf8 / DDL",
    );
}

#[test]
fn numeric_default_boundaries_and_strict_metadata_match_sqlite() {
    let reader = Reader::open(Pages::new(UTF8)).unwrap();
    let table = reader.table("boundaries").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    let types = row.values()[1..]
        .iter()
        .map(|v| match v {
            Value::Integer(_) => "integer",
            Value::Real(_) => "real",
            _ => "unexpected",
        })
        .collect::<Vec<_>>()
        .join("|");
    let mut actual = format!("{types}\n");
    for name in [
        "strict_key",
        "strict_alias",
        "strict_desc",
        "strict_composite",
        "ordinary_key",
    ] {
        let table = reader.table(name).unwrap();
        for column in table.columns() {
            actual.push_str(&format!(
                "{}|{}|{}|{}\n",
                column.name(),
                column.declared_type(),
                u8::from(column.not_null()),
                column.primary_key_position().unwrap_or(0)
            ));
        }
    }
    assert_expected(
        &actual,
        include_str!("fixtures/reader-boundaries.expected"),
        "reader-utf8 / boundaries",
    );
    assert_eq!(row.get("exact"), Some(&Value::Integer(i64::MIN)));
    for name in ["rounded", "underflow"] {
        assert_eq!(row.get(name), Some(&Value::Real(i64::MIN as f64)));
    }
    assert_eq!(row.get("upper"), Some(&Value::Real(-(i64::MIN as f64))));
    assert_eq!(
        row.get("inside"),
        Some(&Value::Integer(-9223372036854774784))
    );
}

#[test]
fn deterministic_byte_mutations_terminate_without_panics() {
    let original = include_bytes!("fixtures/header-utf8.db");
    for offset in 0..original.len() {
        for mask in [1, 128, 255] {
            let mut bytes = original.to_vec();
            bytes[offset] ^= mask;
            let Ok(database) = Database::open(SliceSource::new(&bytes)) else {
                continue;
            };
            let Ok(reader) = Reader::open(database) else {
                continue;
            };
            let _ = reader.schema();
            if let Ok(table) = reader.table("sample") {
                let mut rows = table.rows();
                let mut ended = false;
                for _ in 0..128 {
                    match rows.next() {
                        None | Some(Err(_)) => {
                            ended = true;
                            break;
                        }
                        Some(Ok(_)) => {}
                    }
                }
                assert!(ended, "mutation at {offset} with {mask} did not terminate");
                assert!(rows.next().is_none());
            }
        }
    }
}

// Deliberately has no ReadAt implementation or contiguous database image.
// Reverse storage ensures callers must use logical page numbers.
struct Pages {
    reversed: Vec<Vec<u8>>,
    size: usize,
    fail: Option<u32>,
}
impl Pages {
    fn new(bytes: &[u8]) -> Self {
        let db = Database::open(SliceSource::new(bytes)).unwrap();
        Self {
            reversed: bytes
                .chunks_exact(db.page_size())
                .map(<[u8]>::to_vec)
                .rev()
                .collect(),
            size: db.page_size(),
            fail: None,
        }
    }

    fn page_mut(&mut self, number: u32) -> &mut [u8] {
        assert!((1..=self.page_count()).contains(&number), "page {number}");
        let index = self.reversed.len() - number as usize;
        &mut self.reversed[index]
    }
}
impl PageSource for Pages {
    type Error = io::Error;
    fn page_size(&self) -> usize {
        self.size
    }
    fn page_count(&self) -> u32 {
        self.reversed.len() as u32
    }
    fn read_page_into(&self, page: NonZeroU32, output: &mut [u8]) -> io::Result<()> {
        output.fill(0);
        if output.len() != self.size || page.get() > self.page_count() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.fail == Some(page.get()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        output.copy_from_slice(&self.reversed[self.reversed.len() - page.get() as usize]);
        Ok(())
    }
}

#[track_caller]
fn assert_expected(actual: &str, expected: &str, context: &str) {
    let mut actual = actual.split_inclusive('\n');
    let mut expected = expected.split_inclusive('\n');
    for line in 1.. {
        let a = actual.next();
        let b = expected.next();
        assert_eq!(a, b, "{context}, expected-file line {line}");
        if a.is_none() {
            break;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
fn int(value: &Value) -> i64 {
    match value {
        Value::Integer(n) => *n,
        v => panic!("expected integer: {v:?}"),
    }
}
fn text_hex(value: &Value) -> String {
    match value {
        Value::Text(s) => hex(s.as_bytes()),
        v => panic!("expected text: {v:?}"),
    }
}
fn text(value: &Value) -> String {
    match value {
        Value::Text(s) => s.to_string().unwrap(),
        v => panic!("expected text: {v:?}"),
    }
}

#[test]
fn named_rows_match_sqlite_in_all_encodings_through_page_only_sources() {
    for (bytes, expected) in [
        (UTF8, include_str!("fixtures/reader-utf8.expected")),
        (LE, include_str!("fixtures/reader-utf16le.expected")),
        (BE, include_str!("fixtures/reader-utf16be.expected")),
    ] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("pEoPlE").unwrap();
        assert_eq!(
            table.columns().iter().map(|c| c.name()).collect::<Vec<_>>(),
            [
                "id",
                "display name",
                "score",
                "data",
                "note",
                "amount",
                "extra",
                "absent"
            ]
        );
        assert_eq!(table.columns()[0].primary_key_position(), Some(1));
        assert!(table.columns()[1].not_null());
        let mut result = String::new();
        for row in table.rows() {
            let row = row.unwrap();
            let id = int(row.get("ID").unwrap());
            assert_eq!(row.rowid(), Some(id));
            let score = match row.get("score").unwrap() {
                Value::Null => "NULL".into(),
                Value::Real(n) => format!("{n:.1}"),
                v => panic!("expected REAL: {v:?}"),
            };
            let length = match row.get("data").unwrap() {
                Value::Null => -1,
                Value::Blob(b) => b.len() as i64,
                _ => panic!(),
            };
            let extra = match row.get("extra").unwrap() {
                Value::Blob(b) => hex(b),
                _ => panic!(),
            };
            assert_eq!(row.get("absent"), Some(&Value::Null));
            assert_eq!(row.get("missing"), None);
            result.push_str(&format!(
                "{id}|{}|{score}|{length}|{}|integer|{}|{extra}|null\n",
                text_hex(row.get("display name").unwrap()),
                text_hex(row.get("note").unwrap()),
                int(row.get("amount").unwrap())
            ));
        }
        assert_expected(
            &result,
            expected,
            &format!("People / {:?}", reader.header().text_encoding()),
        );
    }
}

#[test]
fn without_rowid_restores_declared_order_and_large_index_payloads() {
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("reordered").unwrap();
        assert!(table.without_rowid());
        assert_eq!(table.columns()[2].primary_key_position(), Some(1));
        assert_eq!(table.columns()[1].primary_key_position(), Some(2));
        let rows = table.rows().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].rowid(), None);
        assert_eq!(rows[0].values()[0], Value::Blob(vec![0; 16384]));
        assert_eq!(text(&rows[0].values()[1]), "big");
        assert_eq!(rows[0].values()[2], Value::Integer(2));
        assert_eq!(rows[0].values()[3], Value::Real(4.5));
        assert_eq!(rows[1].values()[0], Value::Blob(vec![1, 2]));
        assert_eq!(text(&rows[1].values()[1]), "한글");
        assert_eq!(rows[1].values()[3], Value::Real(3.0));
    }
}

#[test]
fn schema_and_supported_tables_survive_unsupported_ddl() {
    let reader = Reader::open(Pages::new(UTF8)).unwrap();
    let objects = reader.schema().unwrap();
    assert!(
        objects
            .iter()
            .any(|o| o.kind == "view" && o.name == "people_view")
    );
    assert!(
        objects
            .iter()
            .any(|o| o.kind == "trigger" && o.name == "people_trigger")
    );
    assert!(matches!(
        reader.table("expression_default"),
        Err(ReaderError::Unsupported(_))
    ));
    assert_eq!(
        reader
            .table("constraints")
            .unwrap()
            .rows()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        1
    );
    let table = reader.table("descending").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    assert_eq!(row.rowid(), Some(9));
    assert_eq!(row.get("id"), Some(&Value::Integer(42)));
    let table = reader.table("table_key").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    assert_eq!(row.rowid(), Some(42));
    assert_eq!(row.get("id"), Some(&Value::Integer(42)));
    let table = reader.table("strict_values").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    assert_eq!(text(row.get("opaque").unwrap()), "000123");
    assert_eq!(row.get("score"), Some(&Value::Real(3.0)));
    assert_eq!(
        reader
            .table("sqlite_schema")
            .unwrap()
            .rows()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        objects.len()
    );
}

#[test]
fn multilevel_trees_include_interior_index_records_and_patterned_overflow() {
    let body_for = |id| format!("{id:04}:{}", "abcd".repeat(if id == 1 { 310 } else { 57 }));
    let reader = Reader::open(Pages::new(STRESS)).unwrap();
    let table = reader.table("rows").unwrap();
    let mut actual = String::new();
    for row in table.rows() {
        let row = row.unwrap();
        let id = int(row.get("id").unwrap());
        let Value::Blob(body) = row.get("body").unwrap() else {
            panic!()
        };
        let expected_body = body_for(id);
        assert_eq!(body, expected_body.as_bytes());
        actual.push_str(&format!(
            "{id}|{}|{}|{}\n",
            text(row.get("label").unwrap()),
            body.len(),
            hex(&body[..5])
        ));
    }
    assert_expected(
        &actual,
        include_str!("fixtures/stress.expected"),
        "stress / rows",
    );
    let ids: Vec<_> = (1..=75).rev().filter(|n| n % 7 != 0).collect();
    let table = reader.table("keys").unwrap();
    let rows = table.rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| int(r.get("id").unwrap()))
            .collect::<Vec<_>>(),
        ids
    );
    for row in rows {
        let id = int(row.get("id").unwrap());
        assert_eq!(
            row.get("body"),
            Some(&Value::Blob(body_for(id).into_bytes()))
        );
    }
    for name in ["labels", "key_labels"] {
        let index = reader.index(name).unwrap();
        let entries = index.entries().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(entries.iter().map(|e| int(&e[1])).collect::<Vec<_>>(), ids);
        for (entry, id) in entries.iter().zip(&ids) {
            assert_eq!(text(&entry[0]), format!("label-{id:04}"));
        }
    }
}

#[test]
fn selected_page_count_is_authoritative_and_source_failures_stay_distinct() {
    let mut pages = Pages::new(UTF8);
    let count = pages.page_count();
    let first = pages.page_mut(1);
    first[28..32].copy_from_slice(&1u32.to_be_bytes());
    let reader = Reader::open(pages).unwrap();
    assert_eq!(reader.header().page_count(), count);
    let root = reader
        .schema()
        .unwrap()
        .into_iter()
        .find(|o| o.name == "People")
        .unwrap()
        .root_page;
    let mut pages = Pages::new(UTF8);
    pages.fail = Some(root);
    let reader = Reader::open(pages).unwrap();
    let table = reader.table("People").unwrap();
    let mut rows = table.rows();
    assert!(
        matches!(rows.next(), Some(Err(ReaderError::Source(e))) if e.kind() == io::ErrorKind::PermissionDenied)
    );
    assert!(rows.next().is_none());
}

#[test]
fn corrupt_btree_cells_and_cycles_fail_without_partial_rows() {
    let base = Reader::open(Pages::new(STRESS)).unwrap();
    let root = base
        .schema()
        .unwrap()
        .into_iter()
        .find(|o| o.name == "rows")
        .unwrap()
        .root_page;
    for mutation in 0..4 {
        let mut pages = Pages::new(STRESS);
        let page = pages.page_mut(root);
        assert_eq!(page[0], 5); // actual SQLite interior table page
        match mutation {
            0 => page[0] = 255,
            1 => page[12..14].copy_from_slice(&1u16.to_be_bytes()),
            2 => {
                let cell = u16::from_be_bytes([page[12], page[13]]) as usize;
                page[cell..cell + 4].copy_from_slice(&root.to_be_bytes());
            }
            _ => page[8..12].copy_from_slice(&u32::MAX.to_be_bytes()),
        }
        let reader = Reader::open(pages).unwrap();
        let table = reader.table("rows").unwrap();
        let mut rows = table.rows();
        let mut saw_error = false;
        for result in rows.by_ref() {
            if result.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error);
        assert!(rows.next().is_none());
    }
}

#[test]
fn serial_widths_match_logical_values() {
    let integers = [
        0,
        1,
        127,
        -128,
        128,
        -129,
        32767,
        -32768,
        32768,
        -32769,
        8388607,
        -8388608,
        8388608,
        -8388609,
        2147483647,
        -2147483648,
        2147483648,
        -2147483649,
        140737488355327,
        -140737488355328,
        140737488355328,
        -140737488355329,
        i64::MAX,
        i64::MIN,
    ];
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("numeric_values").unwrap();
        let values = table
            .rows()
            .map(|r| r.unwrap().values()[0].clone())
            .collect::<Vec<_>>();
        let mut expected = vec![Value::Null];
        expected.extend(integers.map(Value::Integer));
        expected.extend([
            Value::Real(1.5),
            Value::Real(-1.5),
            Value::Blob(vec![0, 255]),
        ]);
        assert_eq!(values, expected);
    }
}

#[test]
fn large_text_matches_in_all_encodings() {
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("texts").unwrap();
        let row = table.rows().next().unwrap().unwrap();
        assert_eq!(text(row.get("value").unwrap()), "한🔐".repeat(2731));
    }
}

#[test]
fn quoted_ddl_and_combined_table_options_match_logical_values() {
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("quoted\"table").unwrap();
        let row = table.rows().next().unwrap().unwrap();
        assert_eq!(row.get("primary"), Some(&Value::Integer(5)));
        assert_eq!(row.get("space name"), Some(&Value::Integer(-12)));
        assert_eq!(text(row.get("check").unwrap()), "default");
        let table = reader.table("both_options").unwrap();
        assert!(table.without_rowid());
        assert_eq!(
            table.rows().next().unwrap().unwrap().get("id"),
            Some(&Value::Integer(7))
        );
    }
}

#[test]
fn constant_defaults_match_logical_values() {
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("defaults").unwrap();
        let row = table.rows().next().unwrap().unwrap();
        assert_eq!(row.get("integer_value"), Some(&Value::Integer(i64::MIN)));
        assert_eq!(row.get("hex_value"), Some(&Value::Integer(-1)));
        assert_eq!(row.get("real_value"), Some(&Value::Real(3.0)));
        assert_eq!(text(row.get("text_value").unwrap()), "42");
        assert_eq!(row.get("bool_value"), Some(&Value::Integer(1)));
        assert_eq!(row.get("blob_value"), Some(&Value::Blob(vec![0, 255])));
        assert_eq!(row.get("numeric_value"), Some(&Value::Real(12.5)));
    }
}

#[test]
fn empty_and_wide_tables_match_logical_values() {
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        assert!(reader.table("empty").unwrap().rows().next().is_none());
        let table = reader.table("wide").unwrap();
        let row = table.rows().next().unwrap().unwrap();
        assert_eq!(row.values(), vec![Value::Null; 130]);
    }
}

#[test]
fn invalid_utf8_preserves_bytes_and_rejects_string_conversion() {
    let reader = Reader::open(Pages::new(UTF8)).unwrap();
    let table = reader.table("invalid_text").unwrap();
    let row = table.rows().next().unwrap().unwrap();
    let Value::Text(text) = &row.values()[0] else {
        panic!()
    };
    assert_eq!(text.as_bytes(), &[128]);
    assert!(text.to_string().is_err());
}

#[test]
fn overflow_corruption_or_io_failure_never_emits_a_partial_large_row() {
    let overflow: u32 = include_str!("fixtures/reader-utf8.overflow")
        .trim()
        .parse()
        .unwrap();
    for mutation in 0..3 {
        let mut pages = Pages::new(UTF8);
        match mutation {
            0 => pages.page_mut(overflow)[..4].copy_from_slice(&overflow.to_be_bytes()),
            1 => pages.page_mut(overflow)[..4].fill(0),
            _ => pages.fail = Some(overflow),
        }
        let reader = Reader::open(pages).unwrap();
        let table = reader.table("People").unwrap();
        let mut rows = table.rows();
        for id in [i64::MIN, -129, 0] {
            assert_eq!(rows.next().unwrap().unwrap().rowid(), Some(id));
        }
        let error = rows.next().unwrap().unwrap_err();
        if mutation == 2 {
            assert!(matches!(error, ReaderError::Source(_)));
        } else {
            assert!(matches!(
                error,
                ReaderError::InvalidFormat(_) | ReaderError::PageOutOfRange(_)
            ));
        }
        assert!(rows.next().is_none());
    }
}

#[test]
fn malformed_record_headers_and_serial_types_are_errors() {
    let reader = Reader::open(Pages::new(LE)).unwrap();
    let root = reader
        .schema()
        .unwrap()
        .into_iter()
        .find(|o| o.name == "numeric_values")
        .unwrap()
        .root_page;
    for mutation in 0..3 {
        let mut pages = Pages::new(LE);
        let page = pages.page_mut(root);
        assert_eq!(page[0], 13);
        let cell = u16::from_be_bytes([page[8], page[9]]) as usize;
        assert_eq!(&page[cell..cell + 4], &[2, 1, 2, 0]); // SQLite's first NULL record
        match mutation {
            0 => page[cell + 3] = 10,
            1 => page[cell + 2] = 127,
            _ => page[cell] = 1,
        }
        let reader = Reader::open(pages).unwrap();
        let table = reader.table("numeric_values").unwrap();
        let mut rows = table.rows();
        assert!(matches!(
            rows.next(),
            Some(Err(ReaderError::InvalidFormat(_)))
        ));
        assert!(rows.next().is_none());
    }
}

#[test]
fn real_text_defaults_match_sqlite_in_every_encoding() {
    for (bytes, expected) in [
        (
            UTF8,
            include_str!("fixtures/reader-utf8.real-defaults.expected"),
        ),
        (
            LE,
            include_str!("fixtures/reader-utf16le.real-defaults.expected"),
        ),
        (
            BE,
            include_str!("fixtures/reader-utf16be.real-defaults.expected"),
        ),
    ] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let table = reader.table("real_text_defaults").unwrap();
        let mut actual = String::new();
        for row in table.rows() {
            let row = row.unwrap();
            actual.push_str(
                &row.values()[1..]
                    .iter()
                    .map(text_hex)
                    .collect::<Vec<_>>()
                    .join("|"),
            );
            actual.push('\n');
        }
        assert_expected(
            &actual,
            expected,
            &format!("real_text_defaults / {:?}", reader.header().text_encoding()),
        );
    }
}

#[test]
fn numeric_defaults_match_sqlite_bits_and_types() {
    let expected = include_str!("fixtures/reader-numeric.expected");
    for bytes in [UTF8, LE, BE] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        let mut actual = String::new();
        for name in [
            "INTEGER0", "INTEGER1", "NUMERIC0", "NUMERIC1", "REAL0", "REAL1", "TEXT0", "TEXT1",
            "BLOB0", "BLOB1",
        ] {
            let table = reader.table(name).unwrap();
            for row in table.rows() {
                for (i, value) in row.unwrap().values().iter().enumerate() {
                    let encoded = match value {
                        Value::Integer(n) => format!("I{n}"),
                        Value::Real(n) => format!("R{:016x}", n.to_bits()),
                        Value::Text(t) => format!("T{}", t.to_string().unwrap()),
                        v => panic!("unexpected value {v:?}"),
                    };
                    actual.push_str(&format!("{} {i} {encoded}\n", name));
                }
            }
        }
        assert_expected(
            &actual,
            expected,
            &format!(
                "numeric defaults (table and column in each line) / {:?}",
                reader.header().text_encoding()
            ),
        );
    }
}

#[test]
fn stored_generated_columns_match_sqlite() {
    fn encoded(value: &Value) -> String {
        let bytes_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match value {
            Value::Null => "N".into(),
            Value::Integer(n) => format!("I{n}"),
            Value::Real(n) => format!("R{:016x}", n.to_bits()),
            Value::Text(t) => format!("T{}", bytes_hex(t.as_bytes())),
            Value::Blob(b) => format!("B{}", bytes_hex(b)),
        }
    }
    for (bytes, expected) in [
        (
            UTF8,
            include_str!("fixtures/reader-utf8.generated.expected"),
        ),
        (
            LE,
            include_str!("fixtures/reader-utf16le.generated.expected"),
        ),
        (
            BE,
            include_str!("fixtures/reader-utf16be.generated.expected"),
        ),
    ] {
        let reader = Reader::open(Pages::new(bytes)).unwrap();
        assert!(
            reader
                .schema()
                .unwrap()
                .iter()
                .any(|o| o.name == "mixed_generated")
        );
        for name in ["virtual_explicit", "virtual_implicit", "mixed_generated"] {
            assert!(matches!(
                reader.table(name),
                Err(ReaderError::Unsupported("VIRTUAL generated columns"))
            ));
        }
        let mut actual = String::new();
        for name in ["stored_rows", "stored_wr", "stored_strict"] {
            let table = reader.table(name).unwrap();
            for column in table.columns() {
                actual.push_str(&format!(
                    "{name}|{}|{}|{}|{}|{}\n",
                    column.name(),
                    column.declared_type(),
                    u8::from(column.not_null()),
                    column.primary_key_position().unwrap_or(0),
                    if column.is_stored_generated() { 3 } else { 0 }
                ));
                if column.is_stored_generated() {
                    assert!(column.default_value().is_none());
                }
            }
            for row in table.rows() {
                let row = row.unwrap();
                for (column, value) in table.columns().iter().zip(row.values()) {
                    assert_eq!(row.get(column.name()), Some(value));
                }
                actual.push_str(
                    &row.values()
                        .iter()
                        .map(encoded)
                        .collect::<Vec<_>>()
                        .join("|"),
                );
                actual.push('\n');
            }
        }
        for entry in reader.index("stored_index").unwrap().entries() {
            actual.push_str(
                &entry
                    .unwrap()
                    .iter()
                    .map(encoded)
                    .collect::<Vec<_>>()
                    .join("|"),
            );
            actual.push('\n');
        }
        assert_expected(
            &actual,
            expected,
            &format!("generated columns / {:?}", reader.header().text_encoding()),
        );
    }
}

#[test]
fn stored_generated_null_is_valid_but_missing_slot_is_an_error() {
    let bytes = UTF8;
    let base = Reader::open(Pages::new(bytes)).unwrap();
    let schema = base.schema().unwrap();
    for (name, column_count, without_rowid) in
        [("stored_strict", 3u8, false), ("stored_wr", 4, true)]
    {
        let root = schema.iter().find(|o| o.name == name).unwrap().root_page;
        for missing in [false, true] {
            let mut pages = Pages::new(bytes);
            let page = pages.page_mut(root);
            // Replace the root with a single structurally valid record. All
            // serial types are NULL; the missing case omits the final STORED slot.
            let slots = column_count - u8::from(missing);
            let payload_len = slots + 1;
            let mut cell = vec![payload_len];
            if !without_rowid {
                cell.push(4); // rowid
            }
            cell.push(payload_len); // record header length
            cell.resize(cell.len() + usize::from(slots), 0);
            let usable = page.len() - usize::from(bytes[20]);
            let offset = usable - cell.len();
            page.fill(0);
            page[0] = if without_rowid { 10 } else { 13 };
            page[3..5].copy_from_slice(&1u16.to_be_bytes());
            page[5..7].copy_from_slice(&(offset as u16).to_be_bytes());
            page[8..10].copy_from_slice(&(offset as u16).to_be_bytes());
            page[offset..usable].copy_from_slice(&cell);
            let reader = Reader::open(pages).unwrap();
            let table = reader.table(name).unwrap();
            let mut rows = table.rows();
            let result = rows.next().unwrap();
            if missing {
                assert!(matches!(
                    result,
                    Err(ReaderError::InvalidFormat("missing STORED generated value"))
                ));
            } else {
                let row = result.unwrap();
                for column in table.columns().iter().filter(|c| c.is_stored_generated()) {
                    assert_eq!(row.get(column.name()), Some(&Value::Null));
                }
            }
            assert!(rows.next().is_none());
        }
    }
}
