# SQLCipher WAL fixtures

Synthetic encrypted database and WAL pairs for unpublished integration tests.

## Generation

| Property | Value |
| --- | --- |
| Checked-in generation engine | SQLCipher Community 4.20.0 / SQLite 3.54.1 |
| Cipher profile | Compatibility 3, compatibility 4, and custom (see below) |
| Page size | 1024, 4096, and 2048 bytes, respectively |
| Public test passphrase | `wal-fixture` |

| Directory | Cipher profile |
| --- | --- |
| `3/` | Compatibility 3 |
| `4/` | Compatibility 4 |
| `custom/` | 2048-byte pages, 100,000 SHA-256 KDF iterations, SHA-256 page HMAC |

Compatibility 3 refers to the SQLCipher 4 engine profile, not a SQLCipher 3 executable.

## Files

Each profile directory contains the same file set:

| File | Purpose |
| --- | --- |
| `main.db` | Initial database shared by both WAL files |
| `history.wal` | Two commits followed by an uncommitted tail |
| `shrink.wal` | WAL after rollback, deletion, and VACUUM |
| `expected.db` | SQLCipher-checkpointed reference image for `history.wal` |
| `shrunk.db` | SQLCipher-checkpointed reference image for `shrink.wal` |

[`generate.py`](generate.py) generates and validates all three profiles. It copies
inputs only while its writer is idle; it is not a live backup tool.

## Regeneration

Run from this directory:

```sh
python3 generate.py /path/to/sqlcipher --output-dir /path/to/output --timeout 30
```

The generator validates all three profiles and writes their file sets to
`/path/to/output/3/`, `/path/to/output/4/`, and `/path/to/output/custom/`.
Omit `--output-dir` to replace the checked-in WAL fixtures after validation.

See the [shared generation notes](../README.md#regeneration) for prerequisites,
validation, and generation metadata rules.
