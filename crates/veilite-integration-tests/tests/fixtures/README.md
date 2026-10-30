# Integration fixtures

These encrypted databases contain synthetic data and public test passphrases.
They belong to the unpublished integration-test crate. Normal Rust tests use the
checked-in files and do not require SQLCipher.

## Fixture sets

| Directory | Contents |
| --- | --- |
| [`sqlcipher/`](sqlcipher/README.md) | Main databases using compatibility 3, compatibility 4, and custom SHA-256 settings |
| [`turso/`](turso/README.md) | Logical row layout and generated column samples |
| [`wal/`](wal/README.md) | Main/WAL pairs and checkpointed reference images for three profiles |

Each README records the checked-in generation engine, cipher settings, public
passphrase, file purposes, and regeneration command.

## Regeneration

Prerequisites: Python 3 and a SQLCipher command-line executable. The generators
use only the Python standard library. Follow each fixture set's command from the
specified directory; `/path/to/sqlcipher` must point to the executable.

All generators accept these options:

| Option | Behavior |
| --- | --- |
| `--output-dir /path/to/output` | Writes generated files to a separate destination; omitted, replaces that generator's checked-in fixture set |
| `--timeout 30` | Limits each engine operation to 30 seconds; also bounds WAL copy-barrier waits |

The main generator manages all three main profiles together. Their `3.sql`, `4.sql`, and `custom.sql`
files load the shared [`schema.sql`](sqlcipher/schema.sql). If running a SQL file directly,
use the `sqlcipher/` directory as the working directory and a new database path.
Prefer the generator so creation includes validation.

Generators create fresh temporary databases and validate all outputs before
copying them to the destination. They check integrity, expected data, and failure
to query without a key. WAL reference images include checks for every row's ID
and payload. Validation remains enabled with Python optimization. Stalled WAL
writers are terminated and reaped.

The engine versions are printed, not pinned by the scripts. When replacing
checked-in fixtures, update the affected README and generation metadata to match.
Encrypted bytes vary on regeneration because salts and IVs are random. Compare
logical contents and reference-engine checks rather than expecting identical bytes.
