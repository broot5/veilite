.bail on

-- SQLCipher Community 4.17.0 / compatibility 4
-- Test-only passphrase: veilite-sqlcipher4-test-key
-- The connection must be keyed before the first database read or write.
PRAGMA cipher_default_compatibility = 4;
PRAGMA key = 'veilite-sqlcipher4-test-key';
PRAGMA cipher_compatibility = 4;
PRAGMA journal_mode = DELETE;

BEGIN IMMEDIATE;

PRAGMA user_version = 42;
PRAGMA application_id = 0x56454c49;

CREATE TABLE people (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    note TEXT,
    score REAL NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    FOREIGN KEY (person_id) REFERENCES people(id)
) STRICT;

CREATE TABLE binary_samples (
    name TEXT PRIMARY KEY,
    payload BLOB NOT NULL
) WITHOUT ROWID;

CREATE INDEX people_name_idx ON people(name);

CREATE VIEW active_people AS
SELECT id, name, score
FROM people
WHERE active = 1;

CREATE TRIGGER people_insert_audit
AFTER INSERT ON people
BEGIN
    INSERT INTO audit_log(person_id, action)
    VALUES (NEW.id, 'insert');
END;

INSERT INTO people(id, name, note, score, active, created_at) VALUES
    (1, 'Alice', 'plain ASCII', 98.5, 1, '2026-08-04T00:00:00Z'),
    (2, '홍길동', '한국어, emoji 🔐, and ''quotes''', -12.25, 1, '2026-08-04T01:02:03Z'),
    (3, 'Null Tester', NULL, 0.0, 0, '2026-08-04T23:59:59Z');

INSERT INTO binary_samples(name, payload) VALUES
    ('all-byte-edges', X'000102037F80FCFDFEFF'),
    ('large-zero-blob', zeroblob(10000));

COMMIT;
