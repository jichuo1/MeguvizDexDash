#!/usr/bin/env python3
"""Verify final positional boundary evidence without rewriting the earlier readback."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    expected = {'readback-run': 0, 'red-large': 101, 'red-large-negative': 101,
                'green-large': 0, 'green-large-negative': 0, 'sqlite-large-oracle': 0,
                'full-large-final': 0, 'clippy-large-final': 0}
    records = {}
    for name, code in expected.items():
        directory = BASE / name
        path = directory / 'record.json'
        record = json.loads(path.read_text(encoding='utf8'))
        require(record['exit_code'] == code, name + ': unexpected exit')
        for stream in ('stdout', 'stderr'):
            require(sha(directory / (stream + '.txt')) == record[stream]['sha256'], name + ': stream drift')
        records[name] = {'record_sha256': sha(path), 'exit_code': code}
    require('PROJECTION_ORDINAL_OUT_OF_RANGE' in (BASE / 'red-large/stderr.txt').read_text(),
            'positive boundary did not fail as recorded')
    require('ORDER_OR_GROUP_ORDINAL_NEGATIVE' in (BASE / 'red-large-negative/stderr.txt').read_text(),
            'negative boundary did not fail as recorded')
    oracle = json.loads((BASE / 'sqlite-large-oracle/stdout.txt').read_text(encoding='utf8'))
    require([item['status'] for item in oracle['cases']] == ['error', 'ok', 'error', 'ok', 'ok'],
            'SQLite positional boundary changed')
    require(all(item['rows'] == [[3]] for item in oracle['cases'] if item['status'] == 'ok'),
            'constant grouping differs')
    tests = (BASE / 'full-large-final/stdout.txt').read_text(encoding='utf8')
    require('32 passed; 0 failed; 0 ignored' in tests and '1 passed; 0 failed; 0 ignored' in tests,
            'final SQL package test counts differ')
    sources = {p: sha(ROOT / p) for p in ['crates/mdd-sql/src/bridge.rs',
                                         'crates/mdd-sql/src/dialects/ast.rs', 'Cargo.lock']}
    print(json.dumps({'status': 'passed-scoped', 'records': records, 'sources': sources,
                      'sqlite_version': oracle['sqlite_version'], 'negative_cases': 2,
                      'profile_admitted': False,
                      'scope': 'final positional grouping boundary against SQLite; A0/A1 not measured'}))


if __name__ == '__main__':
    main()
