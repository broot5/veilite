"""Regenerate with SQLCipher Community 4.18.0 / SQLite 3.53.4.

Usage: python3 generate.py /path/to/sqlcipher
Only synthetic data and a public test passphrase are used.
"""
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent
engine = sys.argv[1] if len(sys.argv) > 1 else "sqlcipher"
version = subprocess.check_output([engine, "--version"], text=True)
assert version.startswith("3.53.4 ") and "4.18.0 community" in version, version
key = "PRAGMA key='veilite-turso-fixture'; PRAGMA cipher_compatibility=3;"
prefix = ".bail on\nPRAGMA cipher_default_compatibility=3;\n" + key
cases = {
    "rows": (root / "rows.sql").read_text(),
    "stored": "CREATE TABLE t(x, y GENERATED ALWAYS AS (x+1) STORED); INSERT INTO t(x) VALUES(1);",
}
with tempfile.TemporaryDirectory() as directory:
    for name, schema in cases.items():
        path = pathlib.Path(directory) / (name + ".db")
        sql = prefix + "\nPRAGMA encoding='UTF-8';\n" + schema + "\nPRAGMA integrity_check;"
        result = subprocess.run([engine, str(path)], input=sql, text=True, capture_output=True, check=True)
        assert result.stdout.strip().splitlines()[-1] == "ok", result.stdout
        if name == "rows":
            queries = """
SELECT a IS NULL,b FROM nullable;
SELECT label,id FROM alias_later;
SELECT a,b FROM defaults;
SELECT a,b FROM reordered;
"""
            result = subprocess.run([engine, str(path)], input=".bail on\n" + key + queries,
                                    text=True, capture_output=True, check=True)
            # PRAGMA key emits 'ok' before the four query results.
            assert result.stdout.strip().splitlines()[-4:] == ["1|x", "x|42", "x|7", "A|B"], result.stdout
        (root / path.name).write_bytes(path.read_bytes())
