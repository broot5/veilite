"""Generate the three main SQLCipher fixtures after reference-engine validation."""
import pathlib
import shutil
import sys
import tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from support import options, versions, run, expect_tail, require_encrypted

ROOT = pathlib.Path(__file__).resolve().parent
args = options(ROOT)
versions(args)
with tempfile.TemporaryDirectory(prefix="veilite-main-fixtures-") as temporary:
    staging = pathlib.Path(temporary)
    for name in ["3", "4", "custom"]:
        path = staging / f"{name}.db"
        sql = (ROOT / f"{name}.sql").read_text(encoding="utf-8")
        run(args, path, sql, cwd=ROOT)
        settings = sql.split(".read", 1)[0]
        queries = """
PRAGMA integrity_check;
PRAGMA user_version;
PRAGMA application_id;
SELECT id,name,coalesce(note,'NULL'),score,active,created_at FROM people ORDER BY id;
SELECT person_id,action FROM audit_log ORDER BY id;
SELECT name,hex(payload) FROM binary_samples ORDER BY name;
"""
        pattern = "".join(f"{i:04}:" for i in range(2000)).encode().hex().upper()
        expected = [
            "ok", "42", str(0x56454c49),
            "1|Alice|plain ASCII|98.5|1|2026-08-04T00:00:00Z",
            "2|홍길동|한국어, emoji 🔐, and 'quotes'|-12.25|1|2026-08-04T01:02:03Z",
            "3|Null Tester|NULL|0.0|0|2026-08-04T23:59:59Z",
            "1|insert", "2|insert", "3|insert",
            "all-byte-edges|000102037F80FCFDFEFF", "large-pattern-blob|" + pattern,
        ]
        expect_tail(run(args, path, settings + queries).stdout, expected, name)
        require_encrypted(args, path)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name in ["3", "4", "custom"]:
        shutil.copyfile(staging / f"{name}.db", args.output_dir / f"{name}.db")
