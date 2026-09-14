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

## Regenerate

From this directory, run:

```sh
python3 generate.py
```

Both `sqlite3` on PATH and Python’s `sqlite3` binding must use SQLite 3.53.4
with this source ID:

```text
2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc
```

The script checks the versions, loads the three SQL files, adds numeric cases,
and regenerates the databases and expected results. Each database must pass
`PRAGMA integrity_check`. Review the generated diff before committing.
