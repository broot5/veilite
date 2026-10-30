.bail on

-- SQLCipher Community 4.18.0 / compatibility 4
-- Test-only passphrase: veilite-sqlcipher4-test-key
-- The connection must be keyed before the first database read or write.
PRAGMA cipher_default_compatibility = 4;
PRAGMA key = 'veilite-sqlcipher4-test-key';
PRAGMA cipher_compatibility = 4;
PRAGMA journal_mode = DELETE;

.read schema.sql
