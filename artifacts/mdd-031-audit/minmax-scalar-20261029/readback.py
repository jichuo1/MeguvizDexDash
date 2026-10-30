#!/usr/bin/env python3
"""Verify recorded MIN/MAX failure, numeric fix, scope, and source identities."""
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
    expected = {'before': 1, 'red-test': 101, 'green-test': 0, 'green-expanded': 0,
                'budget': 0, 'green-collation': 0, 'sqlite-oracle': 0, 'full': 0,
                'clippy': 0, 'build-after': 0, 'after': 0}
    records = {}
    for name, code in expected.items():
        directory = BASE / name
        path = directory / 'record.json'
        result = json.loads(path.read_text(encoding='utf8'))
        require(result['exit_code'] == code, name + ': exit mismatch')
        for stream in ('stdout', 'stderr'):
            require(sha(directory / (stream + '.txt')) == result[stream]['sha256'], name + ': stream drift')
        records[name] = {'sha256': sha(path), 'exit_code': code}
    before = json.loads((BASE / 'before/stdout.txt').read_text(encoding='utf8'))
    after = json.loads((BASE / 'after/stdout.txt').read_text(encoding='utf8'))
    require(before['operation_status'] == 'error' and before['error']['code'] == 'INVALID_ARGUMENT'
            and 'wrong number of arguments' in before['error']['message'], 'before failure changed')
    require(after['operation_status'] == 'ok' and after['result']['calculation_complete'], 'after incomplete')
    require([[int(cell['value']) for cell in row] for row in after['result']['rows']] == [[1, 2]],
            'numeric output changed')
    oracle = json.loads((BASE / 'sqlite-oracle/stdout.txt').read_text(encoding='utf8'))
    require(oracle['cases'][0]['rows'] == [[1, 2]], 'SQLite numeric reference changed')
    require(oracle['cases'][5]['rows'] == [['a', 'B']]
            and oracle['cases'][7]['rows'] == [['B', 'a']], 'SQLite collation references changed')
    tests = (BASE / 'full/stdout.txt').read_text(encoding='utf8')
    require('34 passed; 0 failed; 0 ignored' in tests and '1 passed; 0 failed; 0 ignored' in tests,
            'SQL package test counts differ')
    sources = {p: sha(ROOT / p) for p in ['crates/mdd-sql/src/bridge.rs',
               'crates/mdd-sql/src/dialects/ast.rs', 'crates/mdd-sql/src/dialects/functions.rs', 'Cargo.lock']}
    print(json.dumps({'status': 'passed-scoped', 'records': records, 'sources': sources,
                      'sqlite_version': oracle['sqlite_version'], 'profile_admitted': False,
                      'scope': 'synthetic inputs; explicit COLLATE remains unsupported; no A0/A1 or full profile'}))


if __name__ == '__main__':
    main()
