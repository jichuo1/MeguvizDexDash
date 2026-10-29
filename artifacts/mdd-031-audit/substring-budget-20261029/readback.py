#!/usr/bin/env python3
"""Read back substring quota failures, lease release and retained value semantics."""
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
    expected = {'red-steps': 101, 'red-workspace': 101, 'green-steps': 0,
                'green-workspace': 0, 'green-all': 0, 'full': 0, 'clippy': 0}
    records = {}
    for name, code in expected.items():
        directory = BASE / name
        path = directory / 'record.json'
        record = json.loads(path.read_text(encoding='utf8'))
        require(record['exit_code'] == code, name + ': exit mismatch')
        for stream in ('stdout', 'stderr'):
            require(sha(directory / (stream + '.txt')) == record[stream]['sha256'], name + ': stream drift')
        records[name] = {'record_sha256': sha(path), 'exit_code': code}
    for name in ('red-steps', 'red-workspace'):
        stderr = (BASE / name / 'stderr.txt').read_text(encoding='utf8')
        require('on an `Ok` value: SqlResult' in stderr, name + ': quota bypass was not reproduced')
    targeted = (BASE / 'green-all/stdout.txt').read_text(encoding='utf8')
    require('6 passed; 0 failed; 0 ignored' in targeted, 'targeted test count differs')
    tests = (BASE / 'full/stdout.txt').read_text(encoding='utf8')
    require('42 passed; 0 failed; 0 ignored' in tests and '1 passed; 0 failed; 0 ignored' in tests,
            'SQL package test counts differ')
    sources = {p: sha(ROOT / p) for p in ['crates/mdd-sql/src/dialects/functions.rs',
                                         'crates/mdd-sql/src/runtime_tests.rs', 'Cargo.lock']}
    print(json.dumps({'status': 'passed-scoped', 'records': records, 'sources': sources,
                      'scope': 'text substring offset vector only; per-unit steps and logical workspace lease',
                      'limitations': ['text and argument clones are not covered', 'SQLite buffers and RSS not covered',
                                      'Native bytes fast path and transport are separate',
                                      'no full dialect or HostLab qualification'],
                      'profile_admitted': False}))


if __name__ == '__main__':
    main()
