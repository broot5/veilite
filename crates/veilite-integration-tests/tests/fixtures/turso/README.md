# Turso integration fixtures

Synthetic encrypted databases for unpublished integration tests.

## Generation

| Property | Value |
| --- | --- |
| Checked-in generation engine | SQLCipher Community 4.18.0 / SQLite 3.53.4 |
| Cipher profile | Compatibility 3 |
| Page size | 1024 bytes |
| Public test passphrase | `veilite-turso-fixture` |

Compatibility 3 refers to the SQLCipher 4 engine profile, not a SQLCipher 3 executable.

## Files

| File | Purpose |
| --- | --- |
| `rows.db` | Logical row layout samples generated from [`rows.sql`](rows.sql) |
| `rows.sql` | NULL, INTEGER PRIMARY KEY, ADD COLUMN defaults, and WITHOUT ROWID samples |
| `stored.db` | A STORED generated column sample |
| `generate.py` | Generates and validates both databases |

## Regeneration

Run from this directory:

```sh
python3 generate.py /path/to/sqlcipher --output-dir /path/to/output --timeout 30
```

The generator validates both databases and writes `/path/to/output/rows.db` and
`/path/to/output/stored.db`. Omit `--output-dir` to replace the checked-in Turso
fixtures after validation.

See the [shared generation notes](../README.md#regeneration) for prerequisites,
validation, and generation metadata rules.
