#!/usr/bin/env python3
"""Read-only verification of bounded real-session LIKE workspace evidence."""
import hashlib
import json
from pathlib import Path
import tomllib

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
    for name in ('build', 'probe'):
        directory = HERE / name
        record = read(directory / 'record.json')
        job = read(directory / 'supervisor.json')
        require(record['exit_code'] == 0 and not record['timed_out'] and record['tree_empty_verified']
                and job['status'] == 'completed' and job['tree_empty_verified']
                and job['assigned_before_resume'], name + ' process incomplete')
        require(sha(directory / 'supervisor.json') == record['supervisor_sha256'], name + ' supervisor changed')
        for stream in ('stdout', 'stderr'):
            require(sha(directory / (stream + '.txt')) == record[stream + '_sha256'], name + ' stream changed')
    sources = read(HERE / 'source-before.json')
    for path, digest in sources.items():
        require(sha(ROOT / path) == digest, 'source changed after build: ' + path)
    require(sources['crates/mdd-sql/src/dialects/functions.rs'] ==
            '062dac4d1fe72eaa4b4d71aa9672380d6ddad0d04122e86c5ca185a0523f9654', 'unexpected LIKE source')
    def external(path):
        packages = tomllib.loads(path.read_text(encoding='utf8'))['package']
        return {(p['name'], p['version'], p.get('checksum')) for p in packages if p.get('source')}
    a, b = external(ROOT / 'Cargo.lock'), external(HERE / 'Cargo.lock')
    require(len(a) == len(b) == 46 and a == b, 'external lock mismatch')
    data = read(HERE / 'probe/stdout.txt')
    values = {r['case']: r for r in data['records']}
    require(len(values) == len(data['records']) == 4 and not data['profile_admitted'], 'case set differs')
    low = values['low']
    require(low['status'] == 'error' and low['error']['code'] == 'QUOTA_EXCEEDED'
            and low['error']['details']['budget'] == 'query_workspace_bytes'
            and low['used_after'] == 0 and not low['execution_complete'], 'low budget terminal differs')
    success = values['sufficient']
    require(success['status'] == 'ok' and success['rows'] == [[{'type':'i64','value':'1'}]]
            and success['calculation_complete'] and success['execution_complete']
            and 0 < success['used_with_result'] <= 8192 and success['used_after_drop'] == 0,
            'successful result/temporary release differs')
    before = values['cancel_before']
    require(before['status'] == 'error' and before['error']['code'] == 'CANCELLED'
            and not before['execution_complete'] and before['used_after'] == 0, 'pre-cancel differs')
    during = values['cancel_while_reserved']
    require(during['observed_token_reservation'] > 100_000 and during['result']['status'] == 'error'
            and during['result']['error']['code'] == 'CANCELLED' and not during['execution_complete']
            and during['used_after'] == 0, 'reservation/cancellation terminal differs')
    result = {'status':'passed-scoped', 'cases':4, 'low_budget_error':'QUOTA_EXCEEDED',
              'used_with_result':success['used_with_result'], 'used_after_drop':success['used_after_drop'],
              'observed_before_cancellation':during['observed_token_reservation'], 'cancel_terminal':'CANCELLED',
              'used_after_cancel':during['used_after'], 'source_count':len(sources),
              'probe_sha256':sha(HERE / 'src/main.rs'), 'runner_sha256':sha(HERE / 'run_bounded.py'),
              'binary_sha256':sha(ROOT / 'artifacts/local/like-independent-20261029-target/debug/mdd-like-workspace-independent.exe'),
              'stdout_sha256':sha(HERE / 'probe/stdout.txt'), 'profile_admitted':False,
              'scope':'real snapshot/session/query budget tree; logic allocation only; no SQLite, decoded parameters, allocator overhead, RSS or transport accounting',
              'cancel_scope':'reservation observed before requesting cancellation; precise internal instruction at request is not observed'}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
