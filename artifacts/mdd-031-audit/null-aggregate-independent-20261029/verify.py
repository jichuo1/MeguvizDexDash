#!/usr/bin/env python3
"""Read raw SQLite and bridge receipts without normalizing DTO identity."""
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


def cell(value):
    if value['type'] == 'null':
        require('value' not in value, 'unexpected native NULL representation')
        return None
    require(value['type'] == 'i64' and isinstance(value['value'], str), 'unexpected candidate cell')
    return int(value['value'])


def main():
    for name in ('sqlite-run', 'sqlite-order-run', 'sqlite-order-extra-run'):
        folder = HERE / name; record = read(folder / 'record.json')
        require(record['exit_code'] == 0, name + ' failed')
        for stream in ('stdout', 'stderr'):
            require(sha(folder / (stream + '.txt')) == record[stream]['sha256'], name + ' stream changed')
    for name in ('build-fixed', 'probe'):
        folder = HERE / name; record = read(folder / 'record.json'); job = read(folder / 'supervisor.json')
        require(record['exit_code'] == 0 and not record['timed_out'] and record['tree_empty_verified']
                and job['status'] == 'completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name + ' job failed')
        require(sha(folder / 'supervisor.json') == record['supervisor_sha256'], name + ' supervisor changed')
        for stream in ('stdout', 'stderr'):
            require(sha(folder / (stream + '.txt')) == record[stream + '_sha256'], name + ' stream changed')
    first = read(HERE / 'build/record.json')
    require(first['exit_code'] == 101 and not first['timed_out']
            and sha(HERE / 'build/stderr.txt') == first['stderr_sha256']
            and 'E0308' in (HERE / 'build/stderr.txt').read_text(encoding='utf8'),
            'first probe compilation failure differs')
    first_source = read(HERE / 'source-before.json')
    require(sha(HERE / 'src/main-before.rs') == first_source['artifacts/mdd-031-audit/null-aggregate-independent-20261029/src/main.rs'],
            'original probe source changed')
    sources = read(HERE / 'source-before-fixed.json')
    for path, digest in sources.items():
        require(sha(ROOT / path) == digest, 'tested source changed: ' + path)
    def external(path):
        return {(p['name'],p['version'],p.get('checksum'))
                for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(external(ROOT / 'Cargo.lock') == external(HERE / 'Cargo.lock')
            and len(external(HERE / 'Cargo.lock')) == 46, 'external lock differs')
    references = [read(HERE / p) for p in ('sqlite-reference.json','sqlite-order-reference.json','sqlite-order-extra.json')]
    expected = {row['case']:row for ref in references for row in ref['records']}
    require(len(expected) == sum(len(ref['records']) for ref in references) == 19, 'SQLite denominator')
    a0 = references[0]['a0_exact_query']
    a0_path = ROOT / 'artifacts/mdd-031/a0-literals/observations.json'
    require(sha(a0_path) == a0['observation_sha256'], 'A0 reference changed')
    data = read(HERE / 'probe/stdout.txt')
    records = {(x['dialect'],x['case']):x for x in data['records']}
    require(len(records) == len(data['records']) == 72 and data['profile_admitted'] is False, 'bridge denominator')
    errors = {'result_limit':'QUOTA_EXCEEDED','step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED',
              'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED'}
    matches = 0
    for dialect in ('native','010','011'):
        for case, ref in expected.items():
            actual = records[(dialect,case)]
            require(actual['sql'] == ref['sql'], 'SQL mismatch: ' + case)
            result = actual['result']
            if ref.get('status') == 'error':
                require(result['status'] in ('error','prepare_error')
                        and result['error']['code'] == 'INVALID_ARGUMENT', 'binding error lost: ' + case)
            else:
                require(result['status'] == 'ok' and result['result']['calculation_complete']
                        and result['result']['columns'] == ref['columns'], 'columns or terminal differ: ' + case)
                projected = [[cell(value) for value in row] for row in result['result']['rows']]
                require(projected == ref['rows'], 'SQLite value/order differs: ' + dialect + '/' + case)
            matches += 1
        for case, code in errors.items():
            result = records[(dialect,case)]['result']
            require(result['status'] == 'error' and result['error']['code'] == code, 'terminal differs: ' + case)
            if case == 'source_changed':
                require(result['error']['stage'] == 'fixture.source', 'source change was rewritten')
    old_cells = a0['rows']
    bridge_cells = records[('010','a0_null_order')]['result']['result']['rows']
    require(old_cells == [[{'type':'null','value':None}],[{'type':'uint64','value':'0'}]]
            and bridge_cells == [[{'type':'null'}],[{'type':'i64','value':'0'}]], 'A0 DTO difference lost')
    report = {'status':'passed-scoped', 'candidate_cases':len(records), 'sqlite_comparisons':matches,
              'control_terminals':len(errors)*3, 'sqlite_version':references[0]['sqlite_version'],
              'a0_exact_query_value_order_equal':True, 'a0_exact_query_dto_equal':False,
              'a0_dto_difference':'NULL value key absent and zero uint64 vs i64',
              'source_changed_scope':'injected by synthetic provider; not a disk mutation test',
              'missing_facts_scope':'injected by synthetic provider; not full corpus',
              'no_new_a0_a1_runs':True,'profile_admitted':False,
              'source_sha256':sources,'binary_sha256':sha(ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-null-aggregate-independent.exe'),
              'candidate_stdout_sha256':sha(HERE/'probe/stdout.txt'),
              'scope':'synthetic provider and SQLite oracle; no production facts, transport, or full SQL qualification'}
    output = HERE / 'qualification.json'
    require(not output.exists(), 'do not overwrite qualification')
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({k:report[k] for k in ('status','candidate_cases','sqlite_comparisons','control_terminals',
                                            'a0_exact_query_value_order_equal','a0_exact_query_dto_equal','profile_admitted')}))


if __name__ == '__main__':
    main()
