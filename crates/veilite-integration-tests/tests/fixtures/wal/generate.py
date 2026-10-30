"""Generate small SQLCipher WAL regression fixtures. Only synthetic data is used.

Usage: python3 generate.py /path/to/sqlcipher
The writer is idle at each copy barrier. Never use this as live backup code.
"""
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from support import options, versions, run, expect_tail, require, require_encrypted, writer

args = options(ROOT)
KEY = "PRAGMA key='wal-fixture';\n"


def settings(profile):
    if profile != "custom":
        return f"PRAGMA cipher_default_compatibility={profile};\n{KEY}PRAGMA cipher_compatibility={profile};\n"
    return """PRAGMA cipher_default_compatibility=4;
PRAGMA cipher_default_page_size=2048;
PRAGMA cipher_default_kdf_iter=100000;
PRAGMA cipher_default_kdf_algorithm=PBKDF2_HMAC_SHA256;
PRAGMA cipher_default_hmac_algorithm=HMAC_SHA256;
""" + KEY + """PRAGMA cipher_page_size=2048;
PRAGMA kdf_iter=100000;
PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA256;
PRAGMA cipher_hmac_algorithm=HMAC_SHA256;
"""


def checkpoint(directory, profile, main, wal, name, count, version):
    db = directory / name
    db.write_bytes(main)
    pathlib.Path(str(db) + "-wal").write_bytes(wal)
    result = run(
        args, db, settings(profile) + "\nPRAGMA wal_checkpoint(TRUNCATE);\n"
        "SELECT count(*) FROM items; PRAGMA user_version; PRAGMA integrity_check;\n"
        "SELECT id,hex(payload) FROM items ORDER BY id;\n",
    )
    rows = [f"{i}|" + ("62617365" if i == 0 else "6368616E676564" if i == 1 else "00" * 1024)
            for i in range(count)]
    expect_tail(result.stdout, [str(count), str(version), "ok"] + rows, f"{profile}/{name}")
    require_encrypted(args, db)


versions(args)
with tempfile.TemporaryDirectory(prefix="veilite-wal-fixtures-") as temporary:
    staging = pathlib.Path(temporary)
    for profile in ["3", "4", "custom"]:
        directory = staging / profile
        directory.mkdir()
        source = directory / "writer.db"
        with writer(args, source) as process:
            process.barrier(".bail on\n" + settings(profile) + """
CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB);
INSERT INTO items VALUES(0, X'62617365');
PRAGMA journal_mode=WAL;
PRAGMA wal_autocheckpoint=0;
PRAGMA wal_checkpoint(TRUNCATE);
BEGIN;
WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<12)
INSERT INTO items SELECT x,zeroblob(1024) FROM n;
PRAGMA user_version=1;
COMMIT;
""")
            main = source.read_bytes()
            (directory / "main.db").write_bytes(main)
            process.barrier("BEGIN; DELETE FROM items WHERE id>8; UPDATE items SET payload=X'6368616e676564' WHERE id=1; PRAGMA user_version=2; COMMIT;")
            committed = pathlib.Path(str(source) + "-wal").read_bytes()
            process.barrier("PRAGMA cache_size=3; BEGIN; UPDATE items SET payload=zeroblob(4096); PRAGMA user_version=99;")
            history = pathlib.Path(str(source) + "-wal").read_bytes()
            require(len(history) > len(committed), "uncommitted pages must spill")
            require(history[:len(committed)] == committed, "committed WAL prefix changed")
            (directory / "history.wal").write_bytes(history)
            process.barrier("ROLLBACK; DELETE FROM items WHERE id>2; PRAGMA user_version=3; VACUUM;")
            shrink = pathlib.Path(str(source) + "-wal").read_bytes()
            (directory / "shrink.wal").write_bytes(shrink)
            require(source.read_bytes() == main, "copy source main must remain unchanged")
        checkpoint(directory, profile, main, history, "expected.db", 9, 2)
        checkpoint(directory, profile, main, shrink, "shrunk.db", 3, 3)
        print(profile, "main", len(main), "committed WAL", len(committed), "with tail", len(history), "shrink WAL", len(shrink))
    # Publish only after all profiles pass the reference engine checks.
    for profile in ["3", "4", "custom"]:
        (args.output_dir / profile).mkdir(parents=True, exist_ok=True)
        for name in ["main.db", "history.wal", "shrink.wal", "expected.db", "shrunk.db"]:
            shutil.copyfile(staging / profile / name, args.output_dir / profile / name)
