#!/usr/bin/env python3
"""Read back actual SQL case-conversion quota and cancellation evidence."""
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
    expected = {'red': 101, 'green': 0, 'green-both': 0, 'full': 0, 'clippy': 0}
    records = {}
    for name, exit_code in expected.items():
        folder = BASE / name
        path = folder / 'record.json'
        record = json.loads(path.read_text(encoding='utf8'))
        require(record['exit_code'] == exit_code, name + ': exit mismatch')
        for stream in ('stdout', 'stderr'):
            require(sha(folder / (stream + '.txt')) == record[stream]['sha256'], name + ': stream drift')
        records[name] = {'record_sha256': sha(path), 'exit_code': exit_code}
    failure = (BASE / 'red/stderr.txt').read_text(encoding='utf8')
    require('case_conversion_long_text_respects_session_step_budget' in failure
            and 'called `Result::unwrap_err()` on an `Ok` value: SqlResult' in failure,
            'red test did not reproduce a successful quota bypass')
    green = (BASE / 'green-both/stdout.txt').read_text(encoding='utf8')
    require('3 passed; 0 failed; 0 ignored' in green, 'target test count differs')
    full = (BASE / 'full/stdout.txt').read_text(encoding='utf8')
    require('37 passed; 0 failed; 0 ignored' in full and '1 passed; 0 failed; 0 ignored' in full,
            'SQL package test count differs')
    sources = {path: sha(ROOT / path) for path in ['crates/mdd-sql/src/dialects/functions.rs',
                                                    'crates/mdd-sql/src/runtime_tests.rs', 'Cargo.lock']}
    print(json.dumps({'status': 'passed-scoped', 'records': records, 'sources': sources,
                      'scope': 'ASCII case conversion step accounting; runtime quota and cancellation',
                      'limitations': ['text and argument copies are not charged by this change',
                                      'SQLite allocations and RSS not measured',
                                      'no full dialect or HostLab profile qualification'],
                      'profiles_admitted': False}))


if __name__ == '__main__':
    main()
