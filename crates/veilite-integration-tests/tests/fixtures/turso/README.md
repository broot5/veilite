# Turso integration fixtures

SQLCipher 3 snapshots generated with SQLCipher Community 4.18.0 / SQLite 3.53.4.
Test passphrase: `veilite-turso-fixture`.

```sh
python3 generate.py /path/to/sqlcipher
```

- `rows.db`: NULL, INTEGER PRIMARY KEY, ADD COLUMN defaults, WITHOUT ROWID column order.
- `stored.db`: rejection of STORED generated columns.
