.bail on

-- SQLCipher Community 4.18.0 / compatibility 3
-- Test-only passphrase: veilite-sqlcipher3-test-key
-- The connection must be keyed before the first database read or write.
PRAGMA cipher_default_compatibility = 3;
PRAGMA key = 'veilite-sqlcipher3-test-key';
PRAGMA cipher_compatibility = 3;
PRAGMA journal_mode = DELETE;

.read schema.sql
