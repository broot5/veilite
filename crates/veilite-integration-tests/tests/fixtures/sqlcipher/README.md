# SQLCipher main fixtures

Synthetic encrypted databases for unpublished integration tests. The three
profiles share the same schema and data; only their cipher settings differ.

## Generation

| Property | Value |
| --- | --- |
| Checked-in generation engine | SQLCipher Community 4.18.0 |
| Cipher profile | Compatibility 3, compatibility 4, and custom (see below) |
| Page size | 1024, 4096, and 2048 bytes, respectively |
| Public test passphrase | Profile-specific (see below) |

| Profile | Cipher settings | Public test passphrase |
| --- | --- | --- |
| `3` | Compatibility 3 | `veilite-sqlcipher3-test-key` |
| `4` | Compatibility 4 | `veilite-sqlcipher4-test-key` |
| `custom` | 2048-byte pages, 100,000 SHA-256 KDF iterations, SHA-256 page HMAC | `veilite-sqlcipher-custom-test-key` |

Compatibility 3 refers to the SQLCipher 4 engine profile, not a SQLCipher 3 executable.

## Files

| File | Purpose |
| --- | --- |
| `3.db`, `4.db`, `custom.db` | People, audit records, and binary samples, including a large BLOB, encrypted with each profile |
| `3.sql`, `4.sql`, `custom.sql` | Profile settings followed by the shared [`schema.sql`](schema.sql) |
| `schema.sql` | Shared schema and synthetic data |
| `generate.py` | Generates and validates all three databases |

## Regeneration

Run from this directory:

```sh
python3 generate.py /path/to/sqlcipher --output-dir /path/to/output --timeout 30
```

The generator validates all three profiles and writes `/path/to/output/3.db`,
`/path/to/output/4.db`, and `/path/to/output/custom.db`. Omit `--output-dir` to
replace the checked-in main fixtures after validation.

See the [shared generation notes](../README.md#regeneration) for prerequisites,
validation, and generation metadata rules.
