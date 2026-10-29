#!/usr/bin/env python3
"""Read-only check of real-session ESCAPE/NULL and reservation release."""
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
        folder = HERE / name
        record, job = read(folder / 'record.json'), read(folder / 'supervisor.json')
        require(record['exit_code'] == 0 and not record['timed_out'] and record['tree_empty_verified']
                and job['status'] == 'completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name + ' did not complete')
        require(sha(folder / 'supervisor.json') == record['supervisor_sha256'], 'supervisor changed')
        for stream in ('stdout', 'stderr'):
            require(sha(folder / (stream + '.txt')) == record[stream + '_sha256'], 'stream changed')
    sources = read(HERE / 'source-before.json')
    for path, expected in sources.items():
        require(sha(ROOT / path) == expected, 'source changed: ' + path)
    def external(path):
        return {(p['name'], p['version'], p.get('checksum'))
                for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    a, b = external(ROOT / 'Cargo.lock'), external(HERE / 'Cargo.lock')
    require(len(a) == len(b) == 46 and a == b, 'locked dependencies differ')
    report = read(HERE / 'probe/stdout.txt')
    cases = {r['case']:r for r in report['records']}
    require(len(cases) == len(report['records']) == 3 and not report['profile_admitted'], 'case set')
    failure = cases['dangling_escape']
    require(failure['status'] == 'error' and failure['error']['code'] == 'INVALID_ARGUMENT'
            and failure['error']['message'] == 'LIKE_DANGLING_ESCAPE' and failure['after'] == 0
            and not failure['execution_complete'], 'dangling escape terminal or release')
    for case, expected in [('null_value', [[{'type':'null'}]]),
                           ('escaped_percent', [[{'type':'i64','value':'1'}]])]:
        result = cases[case]
        require(result['status'] == 'ok' and result['rows'] == expected and result['execution_complete']
                and result['held'] > 0 and result['after'] == 0, case + ' terminal or release')
    result = {'status':'passed-scoped','cases':3,'source_count':len(sources),
              'source_sha256':sha(HERE / 'src/main.rs'),
              'binary_sha256':sha(ROOT / 'artifacts/local/like-independent-20261029-target/debug/mdd-like-workspace-extras.exe'),
              'stdout_sha256':sha(HERE / 'probe/stdout.txt'),'dangling_error':'INVALID_ARGUMENT/LIKE_DANGLING_ESCAPE',
              'released_after_error':True,'released_after_success':True,'profile_admitted':False,
              'scope':'real session, current native bridge; old engine escape semantics not measured; logical workspace is not RSS'}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
