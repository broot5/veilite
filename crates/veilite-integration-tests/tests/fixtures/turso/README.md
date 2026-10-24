# Turso integration fixtures

These synthetic SQLCipher 3 snapshots were generated independently with
SQLCipher Community 4.18.0 / SQLite 3.53.4. The public test passphrase is
`veilite-turso-fixture`. Regenerate with:

```sh
python3 generate.py /path/to/sqlcipher
```

`rows.sql` covers NULL, a later INTEGER PRIMARY KEY, a missing ADD COLUMN
default, and WITHOUT ROWID column order. Overflow BLOBs are covered by the
shared SQLCipher 3/4/custom fixtures. `stored.db` checks rejection of STORED
generated columns by the pinned Turso engine. The generator checks expected
values and `integrity_check` with the reference engine. Normal Rust tests need
no reference engine.
