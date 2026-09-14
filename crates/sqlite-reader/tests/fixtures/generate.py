"""Regenerate using SQLite 3.53.4 CLI; not used by cargo test."""
from pathlib import Path
import random
import sqlite3
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parent
version = subprocess.check_output(['sqlite3', '--version'], text=True).strip()
if version != '3.53.4 2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc (64-bit)':
    raise SystemExit(f'Unexpected fixture generator: {version}')
with sqlite3.connect(':memory:') as connection:
    source_id = connection.execute('select sqlite_source_id()').fetchone()[0]
if source_id != ' '.join(version.split()[1:4]):
    raise SystemExit(f'Python SQLite source ID differs from CLI: {source_id}')


def add_numeric_defaults(connection):
    rng = random.Random(410)
    literals = ['1.0', '-0.0', '0009223372036854775808', '-0009223372036854775808']
    literals += [str(rng.randrange(-10**19, 10**19)) + 'e' + str(rng.randrange(-330, 310)) for _ in range(160)]
    literals += [str(2**k+d)+'.0' for k in [51, 52, 53, 62, 63] for d in [-2, -1, 0, 1, 2]]
    literals += ['-0x8000000000000000', '0x8000000000000000', '-0xFFFFFFFFFFFFFFFF',
                 '1e99999', '-1e99999', '1e-99999', '-1e-99999', '5e-324',
                 '1_234.5', '.5', '1.', '1e+2', '0.' + '0'*400 + '1', '9'*400]
    lines = []
    for affinity in ['INTEGER', 'NUMERIC', 'REAL', 'TEXT', 'BLOB']:
        for quoted in [False, True]:
            table = affinity + str(int(quoted))
            connection.execute(f'CREATE TABLE {table}(id)')
            connection.execute(f'INSERT INTO {table} VALUES(0)')
            for i, literal in enumerate(literals):
                expression = "'" + literal + "'" if quoted else literal
                connection.execute(f'ALTER TABLE {table} ADD COLUMN c{i} {affinity} DEFAULT ({expression})')
            for i, value in enumerate(connection.execute(f'SELECT * FROM {table}').fetchone()):
                if isinstance(value, int):
                    encoded = 'I' + str(value)
                elif isinstance(value, float):
                    encoded = 'R' + struct.pack('>d', value).hex()
                else:
                    encoded = 'T' + value
                lines.append(f'{table} {i} {encoded}\n')
    return ''.join(lines)


def generated_expected(connection, encoding):
    lines = []
    def encoded(value):
        if value is None:
            return 'N'
        if isinstance(value, int):
            return 'I' + str(value)
        if isinstance(value, float):
            return 'R' + struct.pack('>d', value).hex()
        if isinstance(value, bytes):
            return 'B' + value.hex()
        codec = {'UTF-8': 'utf-8', 'UTF-16le': 'utf-16le', 'UTF-16be': 'utf-16be'}[encoding]
        return 'T' + value.encode(codec).hex()
    for table, order in [('stored_rows', 'id'), ('stored_wr', 'a,b'), ('stored_strict', 'id')]:
        for cid, col, typ, nn, default, pk, hidden in connection.execute(f"PRAGMA table_xinfo('{table}')"):
            lines.append(f'{table}|{col}|{typ}|{nn}|{pk}|{hidden}\n')
        for row in connection.execute(f'SELECT * FROM {table} ORDER BY {order}'):
            lines.append('|'.join(encoded(v) for v in row) + '\n')
    # Raw index entries retain SQLite's integer encoding of integral REALs.
    for row in connection.execute('SELECT label,CAST(doubled AS INTEGER),id FROM stored_rows ORDER BY label COLLATE NOCASE,doubled,id'):
        lines.append('|'.join(encoded(v) for v in row) + '\n')
    return ''.join(lines)


def query(database, sql):
    return subprocess.check_output(['sqlite3', '-readonly', str(database), sql], text=True)


numeric_expected = None
for name, size, encoding, script in [
    ('header-utf8', 512, 'UTF-8', 'header.sql'),
    ('header-utf16le', 4096, 'UTF-16le', 'header.sql'),
    ('header-utf16be', 65536, 'UTF-16be', 'header.sql'),
    ('reader-utf8', 512, 'UTF-8', 'reader.sql'),
    ('reader-utf16le', 512, 'UTF-16le', 'reader.sql'),
    ('reader-utf16be', 512, 'UTF-16be', 'reader.sql'),
    ('stress', 512, 'UTF-8', 'stress.sql'),
]:
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / 'fixture.db'
        connection = sqlite3.connect(database)
        connection.execute(f'PRAGMA page_size={size}')
        connection.execute(f"PRAGMA encoding='{encoding}'")
        connection.executescript((root / script).read_text())
        if script == 'reader.sql':
            connection.execute('CREATE TABLE empty(value)')
            connection.execute('CREATE TABLE wide(' + ','.join(f'c{i}' for i in range(130)) + ')')
            connection.execute('INSERT INTO wide VALUES(' + ','.join('NULL' for _ in range(130)) + ')')
            expected = add_numeric_defaults(connection)
            if numeric_expected is not None and expected != numeric_expected:
                raise RuntimeError(f'Numeric results differ for {encoding}')
            numeric_expected = expected
            (root / f'{name}.generated.expected').write_text(generated_expected(connection, encoding))
        connection.commit()
        result = connection.execute('PRAGMA integrity_check').fetchone()[0]
        if result != 'ok':
            raise RuntimeError(result)
        connection.close()
        (root / f'{name}.db').write_bytes(database.read_bytes())
        if script == 'header.sql':
            continue
        if script == 'stress.sql':
            sql = "SELECT id, label, length(body), hex(substr(body,1,5)) FROM rows ORDER BY id;"
            (root / 'stress.expected').write_text(query(database, sql))
            continue
        sql = """SELECT id, hex("display name"), coalesce(CAST(score AS TEXT),'NULL'),
            coalesce(length(data),-1), hex(note), typeof(amount), amount, hex(extra), typeof(absent)
            FROM People ORDER BY id;"""
        (root / f'{name}.expected').write_text(query(database, sql))
        sql = 'SELECT ' + ','.join(f'hex({col})' for col in 'abcdefghijklmnopqr') + ' FROM real_text_defaults ORDER BY id;'
        (root / f'{name}.real-defaults.expected').write_text(query(database, sql))
        if name == 'reader-utf8':
            # Locate fault injection independently of the reader's overflow code.
            sql = "SELECT pageno FROM dbstat WHERE name='People' AND pagetype='overflow' ORDER BY pageno LIMIT 1;"
            (root / f'{name}.overflow').write_text(query(database, sql))
            sql = """SELECT typeof(exact),typeof(rounded),typeof(underflow),typeof(upper),typeof(inside) FROM boundaries;
                SELECT name,type,"notnull",pk FROM pragma_table_info('strict_key');
                SELECT name,type,"notnull",pk FROM pragma_table_info('strict_alias');
                SELECT name,type,"notnull",pk FROM pragma_table_info('strict_desc');
                SELECT name,type,"notnull",pk FROM pragma_table_info('strict_composite');
                SELECT name,type,"notnull",pk FROM pragma_table_info('ordinary_key');"""
            (root / 'reader-boundaries.expected').write_text(query(database, sql))
            sql = """SELECT payload,a,b FROM duplicates;SELECT payload,a,b FROM same_key;
                SELECT rowid,a,b FROM repeated_rowid;SELECT i,h,r,typeof(t),t FROM separators;
                SELECT name,pk FROM pragma_table_info('duplicates');
                SELECT name,pk FROM pragma_table_info('same_key');"""
            (root / 'reader-ddl.expected').write_text(query(database, sql))
(root / 'reader-numeric.expected').write_text(numeric_expected)


# A larger independent oracle for decimal parsing, including the significand
# retention boundary, very long tokens, and decimal points/exponent extremes.
connection = sqlite3.connect(':memory:')
rng = random.Random(3510)
decimals = ['0', '-0', '+.5', '1.', '18446744073709551615', '18446744073709551616',
            '9'*1000, '0.'+'0'*1000+'1', '-1e-1000000',
            # SQLite drops digits beyond its bounded significand before rounding.
            '3500000000000000.2500001', '-3500000000000000.2500001',
            '184467440737095516159', '184467440737095516159e-20']
for _ in range(4096):
    digits = ''.join(str(rng.randrange(10)) for _ in range(rng.randrange(1, 60)))
    point = rng.randrange(len(digits)+1)
    decimals.append(('-' if rng.randrange(2) else '') + digits[:point] + '.' + digits[point:] + 'e' + str(rng.randrange(-400, 401)))
lines = []
for literal in decimals:
    value = connection.execute('SELECT CAST(? AS REAL)', (literal,)).fetchone()[0]
    lines.append(literal + '\t' + struct.pack('>d', value).hex() + '\n')
(root / 'decimal.tsv').write_text(''.join(lines))
connection.close()
