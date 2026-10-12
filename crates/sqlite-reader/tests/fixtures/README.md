# SQLite test fixtures

Tests use committed databases and SQLite-generated expected results; running
`cargo test -p sqlite-reader` requires neither SQLite nor Python.

| Files | Purpose |
| --- | --- |
| `header-*` | Headers and page reads at 512, 4096, and 65536 bytes. |
| `reader-*` | Rows, schema, defaults, and generated columns in all three encodings. |
| `stress.*` | Multilevel table/index trees, overflow, and deletions. |

The seven databases total about 1 MiB. Reader and stress pages are 512 bytes
and payloads are kept small while crossing the tested boundaries. All stored
DBs have zero reserved bytes; row tests reuse the large-page DBs and build empty
leaves and reserved-byte overflow cases in memory.

`.expected` files contain SQLite query results. `decimal.tsv` records decimal
inputs and binary64 bits; `reader-utf8.overflow` identifies a fault-injection page.
Numeric expectations apply to the pinned SQLite build.
`reader-grammar.expected` compares quoted defaults before and after insertion,
parenthesized rowid aliases, and nested key collations in all three encodings.
The generator checks that all three encodings produce the same grammar results.

## Regenerate

From this directory, run:

```sh
python3 generate.py
```

Both `sqlite3` on PATH and Python’s `sqlite3` binding must use SQLite 3.54.0
with this source ID:

```text
2026-10-09 15:46:58 be8d059e9a49089ab2dce5ed26dd87aaf598fdc5fbe0b107c0dd758464bcd5e3
```

The script checks the versions, loads the SQL files, adds numeric cases,
and regenerates the databases and expected results. Each database must pass
`PRAGMA integrity_check`. Review the generated diff before committing.

## Schema and default-value tests

All three reader databases execute the same `reader.sql`. The generator compares
SQLite results across encodings and writes one shared `reader-ddl.expected`.
Each line identifies its table and record kind:

```text
table|column|name|declared type|not null|primary key position
table|row|rowid|value|...
```

Values use `N` for NULL, `I` for integers, `R` for binary64 bits in hex, and `T`
for UTF-8 text bytes in hex. A missing rowid is `N`. Rust tests select complete
lines by table name and compare metadata, types, and values with this output.
`@VT@` in the SQL source denotes a literal vertical tab inserted by the generator.
Cases cover numeric whitespace, identifier defaults, CHECK conflict clauses,
quoted types, repeated keys, and rowid aliases. Rows inserted before and after
ADD COLUMN exercise both missing defaults and stored values. Unsupported
expression defaults are checked separately in the schema tests.
