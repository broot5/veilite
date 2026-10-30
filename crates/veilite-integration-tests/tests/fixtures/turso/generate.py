"""Regenerate with SQLCipher and report the engine versions used.

Usage: python3 generate.py /path/to/sqlcipher
Only synthetic data and a public test passphrase are used.
"""
import pathlib
import sys
import tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from support import options, versions, run, expect_tail, require_encrypted

root = pathlib.Path(__file__).resolve().parent
args = options(root)
versions(args)
key = "PRAGMA key='veilite-turso-fixture'; PRAGMA cipher_compatibility=3;"
prefix = ".bail on\nPRAGMA cipher_default_compatibility=3;\n" + key
cases = {
    "rows": (root / "rows.sql").read_text(encoding="utf-8"),
    "stored": "CREATE TABLE t(x, y GENERATED ALWAYS AS (x+1) STORED); INSERT INTO t(x) VALUES(1);",
}
with tempfile.TemporaryDirectory() as directory:
    for name, schema in cases.items():
        path = pathlib.Path(directory) / (name + ".db")
        sql = prefix + "\nPRAGMA encoding='UTF-8';\n" + schema + "\nPRAGMA integrity_check;"
        result = run(args, path, sql)
        expect_tail(result.stdout, ["ok"], name)
        if name == "rows":
            queries = """
SELECT a IS NULL,b FROM nullable;
SELECT label,id FROM alias_later;
SELECT a,b FROM defaults;
SELECT a,b FROM reordered;
"""
            result = run(args, path, key + queries)
            # PRAGMA key emits 'ok' before the four query results.
            expect_tail(result.stdout, ["1|x", "x|42", "x|7", "A|B"], name)
        require_encrypted(args, path)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name in cases:
        (args.output_dir / (name + ".db")).write_bytes((pathlib.Path(directory) / (name + ".db")).read_bytes())
