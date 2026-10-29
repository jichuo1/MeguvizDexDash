#!/usr/bin/env python3
"""Recheck recorded alias-order failures and the same-input SQLite comparison."""
import hashlib
import json
from pathlib import Path
import sqlite3


ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(name, success):
    directory = BASE / name
    record = read(directory / 'record.json')
    require((record['exit_code'] == 0) == success, name + ': unexpected exit')
    for stream in ('stdout', 'stderr'):
        require(sha(directory / (stream + '.txt')) == record[stream]['sha256'], name + ': stream changed')
    return {'path': (directory / 'record.json').relative_to(ROOT).as_posix(),
            'sha256': sha(directory / 'record.json'), 'exit_code': record['exit_code']}


def numbers(path):
    payload = read(path)
    require(payload['operation_status'] == 'ok' and payload['result']['calculation_complete'], 'incomplete bridge result')
    return [int(row[0]['value']) for row in payload['result']['rows']]


def main():
    names = ['build', 'before', 'input', 'sqlite-oracle', 'sqlite-extra', 'green-test',
             'green-expanded', 'green-nested', 'full-final', 'clippy-final', 'build-after', 'after']
    failures = ['red-test', 'red-nested', 'red-nested-ordinal']
    records = [command(n, True) for n in names] + [command(n, False) for n in failures]
    for name, fragment in [('red-test', 'ORDER BY id'), ('red-nested', 'ORDER BY ((id))'),
                           ('red-nested-ordinal', 'ORDER BY (1)')]:
        stderr = (BASE / name / 'stderr.txt').read_text(encoding='utf8')
        require(fragment in stderr and 'left: [[Some(3)], [Some(2)], [Some(1)]]' in stderr,
                name + ': failure is not the recorded ordering error')
    total = (BASE / 'full-final/stdout.txt').read_text(encoding='utf8')
    require('30 passed; 0 failed; 0 ignored' in total and '1 passed; 0 failed; 0 ignored' in total,
            'SQL package test counts differ')
    ids = numbers(BASE / 'input/stdout.txt')
    require(ids == list(range(13)), 'fixture input changed')
    before = numbers(BASE / 'before/stdout.txt')
    after = numbers(BASE / 'after/stdout.txt')
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE native_strings(string_idx INTEGER)')
    db.executemany('INSERT INTO native_strings VALUES (?)', [(i,) for i in ids])
    sql = 'SELECT 10 - string_idx AS string_idx FROM native_strings ORDER BY string_idx LIMIT 3'
    reference = [row[0] for row in db.execute(sql)]
    require(before == [10, 9, 8] and after == reference == [-2, -1, 0], 'same-input oracle differs')
    print(json.dumps({'status': 'passed-scoped', 'fixture_rows': len(ids), 'before': before,
                      'after': after, 'sqlite': reference, 'sqlite_version': sqlite3.sqlite_version,
                      'sources': {p: sha(ROOT / p) for p in ['crates/mdd-sql/src/bridge.rs',
                                   'crates/mdd-sql/src/dialects/ast.rs', 'Cargo.lock']},
                      'records': records, 'profile_admitted': False,
                      'scope': 'small synthetic fixture and SQLite reference; no A0/A1 or full SQL qualification'}))


if __name__ == '__main__':
    main()
