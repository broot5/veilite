PRAGMA journal_mode = DELETE;
PRAGMA auto_vacuum = FULL;
CREATE TABLE rows(id INTEGER PRIMARY KEY, label TEXT, body BLOB);
-- Enough rows for three-level table/index trees; only row 1 needs long overflow.
WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<75)
INSERT INTO rows SELECT v, printf('label-%04d',v), CAST(printf('%04d:',v) || replace(hex(zeroblob(CASE v WHEN 1 THEN 310 ELSE 57 END)),'00','abcd') AS BLOB) FROM n;
CREATE INDEX labels ON rows(label DESC);
CREATE TABLE keys(body BLOB, label TEXT, id INTEGER, PRIMARY KEY(id DESC,label)) WITHOUT ROWID;
INSERT INTO keys SELECT body,label,id FROM rows;
CREATE INDEX key_labels ON keys(label DESC);
DELETE FROM rows WHERE id%7=0;
DELETE FROM keys WHERE id%7=0;
