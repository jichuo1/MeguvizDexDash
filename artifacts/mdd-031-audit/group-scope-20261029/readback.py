#!/usr/bin/env python3
"""Read back exact positional grouping failures and same-input SQLite results."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(name, success):
    d = BASE / name
    record = json.loads((d / 'record.json').read_text(encoding='utf8'))
    require((record['exit_code'] == 0) == success, name + ': unexpected exit')
    for stream in ('stdout', 'stderr'):
        require(sha(d / (stream + '.txt')) == record[stream]['sha256'], name + ': stream changed')
    return {'path': (d / 'record.json').relative_to(ROOT).as_posix(),
            'sha256': sha(d / 'record.json'), 'exit_code': record['exit_code']}


def rows(path):
    data = json.loads(path.read_text(encoding='utf8'))
    require(data['operation_status'] == 'ok' and data['result']['calculation_complete'], 'incomplete SQL result')
    return [[int(cell['value']) for cell in row] for row in data['result']['rows']]


def main():
    passed = ['group_alias', 'group_collision', 'having_alias', 'having_aggregate', 'group_nested_ord',
              'sqlite-oracle', 'sqlite-signed-oracle', 'green-test', 'build-after', 'after', 'full', 'clippy']
    failed = ['red-test', 'red-signed']
    records = [command(name, True) for name in passed] + [command(name, False) for name in failed]
    for name, fragment in [('red-test', 'GROUP BY ((1))'), ('red-signed', 'GROUP BY (+1)')]:
        stderr = (BASE / name / 'stderr.txt').read_text(encoding='utf8')
        require(fragment in stderr and 'Some(3)' in stderr, name + ': original wrong group not observed')
    log = (BASE / 'full/stdout.txt').read_text(encoding='utf8')
    require('31 passed; 0 failed; 0 ignored' in log and '1 passed; 0 failed; 0 ignored' in log,
            'SQL package test count differs')
    input_path = ROOT / 'artifacts/mdd-031-audit/order-alias-20261029/input/stdout.txt'
    input_data = json.loads(input_path.read_text(encoding='utf8'))
    require(input_data['operation_status'] == 'ok' and input_data['result']['calculation_complete'], 'fixture input incomplete')
    ids = [int(row[0]['value']) for row in input_data['result']['rows']]
    require(ids == list(range(13)), 'fixture identity changed')
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE native_strings(string_idx INTEGER)')
    db.executemany('INSERT INTO native_strings VALUES (?)', [(i,) for i in ids])
    sql = 'SELECT string_idx % 2 AS parity, COUNT(*) AS n FROM native_strings GROUP BY (1) ORDER BY parity'
    reference = [list(row) for row in db.execute(sql)]
    before, after = rows(BASE / 'group_nested_ord/stdout.txt'), rows(BASE / 'after/stdout.txt')
    require(before == [[0, 13]] and after == reference == [[0, 7], [1, 6]], 'group output differs')
    print(json.dumps({'status': 'passed-scoped', 'fixture_rows': len(ids), 'before': before,
                      'after': after, 'sqlite': reference, 'sqlite_version': sqlite3.sqlite_version,
                      'fixture_input_sha256': sha(input_path),
                      'sources': {p: sha(ROOT / p) for p in ['crates/mdd-sql/src/bridge.rs',
                                   'crates/mdd-sql/src/dialects/ast.rs', 'Cargo.lock']},
                      'records': records, 'profile_admitted': False,
                      'scope': 'synthetic fixed fixture and SQLite only; no A0/A1 or full SQL qualification'}))


if __name__ == '__main__':
    main()
