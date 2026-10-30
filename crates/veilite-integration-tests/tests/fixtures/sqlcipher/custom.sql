.bail on

-- SQLCipher Community 4.18.0 / custom configuration
-- Test-only passphrase: veilite-sqlcipher-custom-test-key
-- The connection must be keyed before the first database read or write.
PRAGMA cipher_default_compatibility = 4;
PRAGMA cipher_default_page_size = 2048;
PRAGMA cipher_default_kdf_iter = 100000;
PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA256;
PRAGMA cipher_default_hmac_algorithm = HMAC_SHA256;

PRAGMA key = 'veilite-sqlcipher-custom-test-key';

PRAGMA cipher_page_size = 2048;
PRAGMA kdf_iter = 100000;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256;
PRAGMA cipher_hmac_algorithm = HMAC_SHA256;
PRAGMA cipher_use_hmac = ON;
PRAGMA cipher_plaintext_header_size = 0;
PRAGMA journal_mode = DELETE;

.read schema.sql
