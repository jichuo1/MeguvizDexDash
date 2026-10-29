#!/usr/bin/env python3
"""Verify actual bridge output against fixed expectations and SQLite microcases."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def main():
    for folder in ('build-extended', 'probe-extended'):
        path = HERE / folder
        record = read(path / 'record.json')
        require(record['exit_code'] == 0, folder + ' failed')
        for stream in ('stdout', 'stderr'):
            require(sha(path / (stream + '.txt')) == record[stream]['sha256'], folder + ' output changed')
    before = read(HERE / 'first-probe.json')
    require(sha(HERE / 'src/main-before.rs') == before['source_sha256']
            and sha(HERE / 'probe/stdout.txt') == before['stdout_sha256'], 'first failure changed')
    prior = read(HERE / 'probe/stdout.txt')
    require(len(prior['records']) == 27 and all(
        x['result']['status'] == 'prepare_error'
        and x['result']['error']['message'] == 'ONLY_POSITIONAL_BARE_PARAMETERS_SUPPORTED'
        for x in prior['records']), 'initial parameter failure differs')
    data = read(HERE / 'probe-extended/stdout.txt')
    rows = {(x['dialect'], x['case']): x['result'] for x in data['records']}
    cases = {'long_empty_low_budget', 'long_empty_sufficient_budget', 'short_match', 'null_input',
             'empty_exact', 'empty_many', 'underscore', 'literal_underscore', 'cancelled', 'deadline',
             'async_cancel', 'dangling_escape', 'escaped_percent'}
    require(len(data['records']) == len(rows) == 39 and set(rows) == {
        (dialect, case) for dialect in ('native', '010', '011') for case in cases}, 'case denominator changed')
    for dialect in ('native', '010', '011'):
        for case, error in [('long_empty_low_budget', 'QUOTA_EXCEEDED'), ('cancelled', 'CANCELLED'),
                            ('async_cancel', 'CANCELLED'), ('deadline', 'DEADLINE_EXCEEDED'),
                            ('dangling_escape', 'INVALID_ARGUMENT')]:
            result = rows[(dialect, case)]
            require(result['status'] == 'error' and result['error']['code'] == error, dialect + '/' + case)
        require(rows[(dialect, 'dangling_escape')]['error']['message'] == 'LIKE_DANGLING_ESCAPE',
                'trailing escape error changed')
        for case, value in [('long_empty_sufficient_budget', '0'), ('empty_exact', '1'),
                            ('empty_many', '1'), ('literal_underscore', '1'), ('escaped_percent', '1'),
                            ('short_match', '0' if dialect == 'native' else '1'),
                            ('underscore', '1' if dialect == 'native' else '0')]:
            result = rows[(dialect, case)]
            require(result['status'] == 'ok' and result['result']['calculation_complete']
                    and result['result']['rows'] == [[{'type':'i64','value':value}]], dialect + '/' + case)
        result = rows[(dialect, 'null_input')]
        require(result['status'] == 'ok' and result['result']['rows'] == [[{'type':'null'}]], dialect + '/null')
    db = sqlite3.connect(':memory:')
    try:
        sqlite = {
            'dangling_escape': db.execute('SELECT ? LIKE ? ESCAPE ?', ('ab', 'ab\\', '\\')).fetchone()[0],
            'escaped_percent': db.execute('SELECT ? LIKE ? ESCAPE ?', ('a%b', 'a\\%b', '\\')).fetchone()[0],
            'null_input': db.execute('SELECT ? LIKE ?', (None, '%')).fetchone()[0],
            'short_match': db.execute('SELECT ? LIKE ?', ('Abc', 'a%c')).fetchone()[0],
        }
    finally:
        db.close()
    require(sqlite == {'dangling_escape': 0, 'escaped_percent': 1, 'null_input': None, 'short_match': 1},
            'SQLite comparison differs')
    report = {'status':'passed-scoped', 'cases':39, 'dialects':['native','010','011'],
              'probe_sha256':sha(HERE / 'src/main.rs'), 'cargo_lock_sha256':sha(HERE / 'Cargo.lock'),
              'functions_sha256':sha(ROOT / 'crates/mdd-sql/src/dialects/functions.rs'),
              'binary_sha256':sha(ROOT / 'artifacts/local/like-independent-20261029-target/debug/mdd-independent-q03-probe.exe'),
              'stdout_sha256':sha(HERE / 'probe-extended/stdout.txt'), 'sqlite_version':sqlite3.sqlite_version,
              'sqlite_observed':sqlite, 'trailing_escape_difference':'bridge INVALID_ARGUMENT; SQLite returns 0',
              'old_engine_trailing_escape':'not verified in this run',
              'async_cancellation_boundary':'thread requested cancellation after 1 ms; exact checkpoint phase not observed',
              'profiles_admitted':False, 'scope':'standalone bridge with synthetic parameters; no worker or full dialect qualification'}
    output = HERE / 'qualification.json'
    require(not output.exists(), 'qualification already exists')
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8', newline='\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
