PRAGMA journal_mode = DELETE;
PRAGMA auto_vacuum = INCREMENTAL;
CREATE TABLE "People" (
    "id" INTEGER PRIMARY KEY,
    "display name" TEXT NOT NULL,
    score REAL,
    data BLOB
);
INSERT INTO People VALUES (-9223372036854775808, '한글 🔐', 3, X'00017FFF');
INSERT INTO People VALUES (-129, 'quote''s', -12.5, X'');
INSERT INTO People VALUES (0, '', NULL, NULL);
-- Cross the three-byte payload-length boundary without oversized blobs.
INSERT INTO People VALUES (9223372036854775807, 'last', 0, zeroblob(16384));
ALTER TABLE People ADD COLUMN note TEXT DEFAULT ('old '' note');
ALTER TABLE People ADD COLUMN amount NUMERIC DEFAULT '3.0e+5';
ALTER TABLE People ADD COLUMN extra BLOB DEFAULT X'007FFF';
ALTER TABLE People ADD COLUMN absent TEXT;
CREATE INDEX people_name ON People("display name" COLLATE BINARY DESC);

CREATE TABLE reordered (
    payload BLOB, label TEXT, part INTEGER, score REAL,
    CONSTRAINT pk PRIMARY KEY(part DESC, label COLLATE BINARY)
) WITHOUT ROWID;
INSERT INTO reordered VALUES (X'0102', '한글', 1, 3);
INSERT INTO reordered VALUES (zeroblob(16384), 'big', 2, 4.5);
CREATE INDEX reordered_label ON reordered(label);

CREATE TABLE descending(id INTEGER PRIMARY KEY DESC, value TEXT);
INSERT INTO descending(rowid,id,value) VALUES(9,42,'separate');
CREATE TABLE table_key(id INTEGER, value TEXT, PRIMARY KEY(id DESC));
INSERT INTO table_key VALUES(42,'alias');
CREATE TABLE strict_values(id INT PRIMARY KEY, opaque ANY, score REAL) STRICT;
INSERT INTO strict_values VALUES(1, '000123', 3);
CREATE TABLE constraints(
    id INTEGER CONSTRAINT pk PRIMARY KEY AUTOINCREMENT,
    parent INTEGER REFERENCES People(id) ON DELETE SET NULL NOT DEFERRABLE INITIALLY IMMEDIATE,
    value VARCHAR(32) COLLATE NOCASE UNIQUE ON CONFLICT IGNORE,
    quantity INT NOT NULL ON CONFLICT ABORT CHECK(quantity > 0),
    CONSTRAINT check_pair CHECK (parent IS NULL OR quantity >= 1),
    FOREIGN KEY(parent) REFERENCES People(id)
);
INSERT INTO constraints(parent,value,quantity) VALUES(NULL,'fine',1);
CREATE TABLE generated(id INTEGER, value INTEGER GENERATED ALWAYS AS (id+1) STORED);
INSERT INTO generated(id) VALUES(1);
CREATE TABLE expression_default(id INTEGER, value TEXT DEFAULT (upper('x')));
INSERT INTO expression_default(id) VALUES(1);
CREATE VIEW people_view AS SELECT id FROM People;
CREATE TRIGGER people_trigger AFTER INSERT ON People BEGIN SELECT 1; END;

CREATE TABLE numeric_values(v);
INSERT INTO numeric_values VALUES
    (NULL),(0),(1),(127),(-128),(128),(-129),(32767),(-32768),(32768),(-32769),
    (8388607),(-8388608),(8388608),(-8388609),(2147483647),(-2147483648),
    (2147483648),(-2147483649),(140737488355327),(-140737488355328),
    (140737488355328),(-140737488355329),(9223372036854775807),(-9223372036854775808),
    (1.5),(-1.5),(X'00FF');
CREATE TABLE texts(id INTEGER PRIMARY KEY, value TEXT);
-- UTF-16 is just over 16 KiB; both encodings need multi-byte payload lengths.
INSERT INTO texts VALUES(1,replace(hex(zeroblob(2731)),'00','한🔐'));
CREATE TABLE invalid_text(value TEXT);
INSERT INTO invalid_text VALUES(CAST(X'80' AS TEXT));
CREATE TABLE "quoted""table" (
    "primary" INTEGER PRIMARY KEY,
    [check] TEXT DEFAULT 'default',
    `space name` NUMERIC DEFAULT (-12),
    typeless DEFAULT NULL
);
INSERT INTO "quoted""table"("primary") VALUES(5);
CREATE TABLE both_options(payload TEXT, id INTEGER, PRIMARY KEY(id)) STRICT, WITHOUT ROWID;
INSERT INTO both_options VALUES('strict',7);
CREATE TABLE defaults(id INTEGER PRIMARY KEY);
INSERT INTO defaults VALUES(1);
ALTER TABLE defaults ADD COLUMN integer_value INTEGER DEFAULT -9223372036854775808;
ALTER TABLE defaults ADD COLUMN hex_value INTEGER DEFAULT 0xFFFFFFFFFFFFFFFF;
ALTER TABLE defaults ADD COLUMN real_value REAL DEFAULT 3;
ALTER TABLE defaults ADD COLUMN text_value TEXT DEFAULT 42;
ALTER TABLE defaults ADD COLUMN bool_value INTEGER DEFAULT TRUE;
ALTER TABLE defaults ADD COLUMN blob_value BLOB DEFAULT X'00FF';
ALTER TABLE defaults ADD COLUMN numeric_value NUMERIC DEFAULT ' 12.5 ';
CREATE TABLE real_text_defaults(id INTEGER PRIMARY KEY);
INSERT INTO real_text_defaults VALUES(1);
ALTER TABLE real_text_defaults ADD COLUMN a TEXT DEFAULT 1.5;
ALTER TABLE real_text_defaults ADD COLUMN b TEXT DEFAULT -0.0;
ALTER TABLE real_text_defaults ADD COLUMN c TEXT DEFAULT 1e15;
ALTER TABLE real_text_defaults ADD COLUMN d TEXT DEFAULT 1e-5;
ALTER TABLE real_text_defaults ADD COLUMN e TEXT DEFAULT 1.234567890123456;
ALTER TABLE real_text_defaults ADD COLUMN f TEXT DEFAULT 1e308;
ALTER TABLE real_text_defaults ADD COLUMN g TEXT DEFAULT 5e-324;
ALTER TABLE real_text_defaults ADD COLUMN h TEXT DEFAULT 1e999;
ALTER TABLE real_text_defaults ADD COLUMN i TEXT DEFAULT -1e999;
ALTER TABLE real_text_defaults ADD COLUMN j TEXT DEFAULT 9.999999999999999;
ALTER TABLE real_text_defaults ADD COLUMN k TEXT DEFAULT +1.50;
ALTER TABLE real_text_defaults ADD COLUMN l TEXT DEFAULT -01.50;
ALTER TABLE real_text_defaults ADD COLUMN m TEXT DEFAULT 1_000.50;
ALTER TABLE real_text_defaults ADD COLUMN n TEXT DEFAULT 0009223372036854775808;
ALTER TABLE real_text_defaults ADD COLUMN o TEXT DEFAULT -0009223372036854775808;
ALTER TABLE real_text_defaults ADD COLUMN p TEXT DEFAULT 00042;
ALTER TABLE real_text_defaults ADD COLUMN q TEXT DEFAULT 0x20;
ALTER TABLE real_text_defaults ADD COLUMN r TEXT DEFAULT (1.0);
INSERT INTO real_text_defaults VALUES(2,'stored','-0','1e15','x','x','x','x','x','x','x','x','x','x','x','x','x','x','x');
INSERT INTO real_text_defaults(id) VALUES(3);
CREATE TABLE duplicate_key(a INTEGER,b TEXT,PRIMARY KEY(a,a)) WITHOUT ROWID;

-- Numeric boundaries and primary-key metadata
CREATE TABLE boundaries(id INTEGER PRIMARY KEY);
INSERT INTO boundaries VALUES(1);
ALTER TABLE boundaries ADD COLUMN exact NUMERIC DEFAULT '-9223372036854775808';
ALTER TABLE boundaries ADD COLUMN rounded NUMERIC DEFAULT '-9223372036854775808.0';
ALTER TABLE boundaries ADD COLUMN underflow NUMERIC DEFAULT '-9223372036854775809';
ALTER TABLE boundaries ADD COLUMN upper NUMERIC DEFAULT '9223372036854775808';
ALTER TABLE boundaries ADD COLUMN inside NUMERIC DEFAULT '-9223372036854774784.0';
CREATE TABLE strict_key(id INT PRIMARY KEY, value TEXT) STRICT;
CREATE TABLE strict_alias(id INTEGER PRIMARY KEY, value TEXT) STRICT;
CREATE TABLE strict_desc(id INTEGER PRIMARY KEY DESC, value TEXT) STRICT;
CREATE TABLE strict_composite(a INT,b TEXT,PRIMARY KEY(a,b)) STRICT;
CREATE TABLE ordinary_key(id INT PRIMARY KEY, value TEXT);

-- Repeated primary keys and numeric separators
CREATE TABLE duplicates(payload TEXT,a TEXT COLLATE NOCASE,b INTEGER,
 PRIMARY KEY(a,a COLLATE nocase,b,a COLLATE BINARY)) WITHOUT ROWID;
INSERT INTO duplicates VALUES('payload','Case',7);
CREATE TABLE same_key(payload TEXT,a INTEGER,b TEXT,PRIMARY KEY(a,a,b,b)) WITHOUT ROWID;
INSERT INTO same_key VALUES('value',42,'b');
CREATE TABLE repeated_rowid(a INTEGER,b TEXT,PRIMARY KEY(a,a));
INSERT INTO repeated_rowid(rowid,a,b) VALUES(9,42,'separate');
CREATE TABLE separators(id INTEGER PRIMARY KEY);
INSERT INTO separators VALUES(1);
ALTER TABLE separators ADD COLUMN i INTEGER DEFAULT -9_223_372_036_854_775_808;
ALTER TABLE separators ADD COLUMN h INTEGER DEFAULT 0xFF_FF;
ALTER TABLE separators ADD COLUMN r REAL DEFAULT 1_2.5_0e+0_1;
ALTER TABLE separators ADD COLUMN t NUMERIC DEFAULT '1_000';

-- Stored and virtual generated columns
CREATE TABLE stored_rows (
    doubled REAL GENERATED ALWAYS AS (base * 2) STORED,
    id INTEGER PRIMARY KEY,
    label TEXT AS (printf('%s:%d', '한,(字)', id)) STORED COLLATE NOCASE NOT NULL UNIQUE,
    base INTEGER,
    chained TEXT CONSTRAINT derived AS (label || ':' || doubled) STORED,
    absent INTEGER AS (NULL) STORED,
    data BLOB AS (zeroblob(1024)) STORED
);
INSERT INTO stored_rows(id,base) VALUES(7,3),(9,NULL);
UPDATE stored_rows SET base=4 WHERE id=7;
ALTER TABLE stored_rows ADD COLUMN tail TEXT DEFAULT 'added';
CREATE INDEX stored_index ON stored_rows(label,doubled);
CREATE TABLE stored_wr (
    computed TEXT AS (a || ':' || b) STORED,
    b INTEGER,
    a TEXT,
    rounded REAL AS (b*2) STORED,
    PRIMARY KEY(a,b)
) WITHOUT ROWID;
INSERT INTO stored_wr(a,b) VALUES('가',2),('나',3);
CREATE TABLE stored_strict (
    id INTEGER PRIMARY KEY,
    rendered TEXT GENERATED ALWAYS AS (id*2) STORED,
    amount REAL AS (id*3) STORED
) STRICT;
INSERT INTO stored_strict(id) VALUES(4);
CREATE TABLE virtual_explicit(a, b AS (a+1) VIRTUAL);
CREATE TABLE virtual_implicit(a, b AS (a+1));
CREATE TABLE mixed_generated(a, b AS (a+1) STORED, c AS (a+2) VIRTUAL);
