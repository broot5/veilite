PRAGMA journal_mode = DELETE;
PRAGMA user_version = 42;
PRAGMA application_id = 1447382089;
CREATE TABLE sample(id INTEGER PRIMARY KEY, text_value TEXT, payload BLOB);
INSERT INTO sample VALUES(7, 'hello 한글', X'00017FFF');
