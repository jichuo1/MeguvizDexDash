#!/usr/bin/env python3
"""Read-only recheck: recompute SQLite references and verify bridge receipts."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def cell(value):
    if value['type'] == 'null':
        require('value' not in value, 'native NULL representation changed')
        return None
    require(value['type'] == 'i64' and isinstance(value['value'],str), 'unexpected native cell')
    return int(value['value'])


def main():
    report = read(HERE/'qualification.json')
    receipt = read(HERE/'verify-run/record.json')
    require(report['status'] == 'passed-scoped' and not report['profile_admitted']
            and not report['a0_exact_query_dto_equal'] and receipt['exit_code'] == 0,
            'qualification overclaimed or command failed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/('verify-run/'+stream+'.txt')) == receipt[stream]['sha256'], 'verify stream changed')
    for path,digest in report['source_sha256'].items():
        require(sha(ROOT/path) == digest, 'tested source changed: '+path)
    require(sha(HERE/'probe/stdout.txt') == report['candidate_stdout_sha256'], 'candidate stdout changed')
    binary = ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-null-aggregate-independent.exe'
    require(sha(binary) == report['binary_sha256'], 'candidate binary changed')
    docs = [read(HERE/path) for path in ('sqlite-reference.json','sqlite-order-reference.json','sqlite-order-extra.json')]
    require(all(doc['sqlite_version'] == sqlite3.sqlite_version for doc in docs), 'SQLite version changed')
    refs = {case['case']:case for doc in docs for case in doc['records']}
    require(len(refs) == 19, 'reference denominator changed')
    candidate = read(HERE/'probe/stdout.txt')
    records = {(item['dialect'],item['case']):item for item in candidate['records']}
    require(len(records) == len(candidate['records']) == 72 and not candidate['profile_admitted'], 'candidate denominator')
    checked=0
    for name,ref in refs.items():
        db=sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE facts(v INTEGER,alt INTEGER NOT NULL)')
            if name != 'empty_aggregate':
                db.executemany('INSERT INTO facts(v,alt) VALUES (?,?)',[(None,7),(2,3),(2,-9),(-1,2)])
            try:
                cur=db.execute(ref['sql'])
                actual={'status':'ok','columns':[x[0] for x in cur.description],
                        'rows':[list(x) for x in cur.fetchall()]}
            except sqlite3.Error as error:
                actual={'status':'error','error_type':type(error).__name__,'message':str(error)}
        finally:
            db.close()
        ref_status=ref.get('status','ok')
        require(actual['status']==ref_status,'SQLite status drift: '+name)
        if ref_status=='ok':
            require(actual['rows']==ref['rows'] and actual['columns']==ref['columns'],'SQLite rows drift: '+name)
        else:
            require(actual['message']==ref['message'],'SQLite error drift: '+name)
        for dialect in ('native','010','011'):
            item=records[(dialect,name)]; result=item['result']
            require(item['sql']==ref['sql'],'SQL text mismatch')
            if ref_status=='ok':
                require(result['status']=='ok' and result['result']['calculation_complete']
                        and result['result']['columns']==ref['columns']
                        and [[cell(c) for c in row] for row in result['result']['rows']]==ref['rows'],
                        'candidate rows drift: '+dialect+'/'+name)
            else:
                require(result['status'] in ('error','prepare_error') and result['error']['code']=='INVALID_ARGUMENT',
                        'candidate error drift: '+name)
            checked+=1
    codes={'result_limit':'QUOTA_EXCEEDED','step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED',
           'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED'}
    for dialect in ('native','010','011'):
        for name,code in codes.items():
            result=records[(dialect,name)]['result']
            require(result['status']=='error' and result['error']['code']==code,'terminal drift: '+name)
    a0=docs[0]['a0_exact_query']; a0_path=ROOT/'artifacts/mdd-031/a0-literals/observations.json'
    require(sha(a0_path)==a0['observation_sha256'] and a0['rows']==[
        [{'type':'null','value':None}],[{'type':'uint64','value':'0'}]],'A0 evidence drift')
    require(records[('010','a0_null_order')]['result']['result']['rows']==[
        [{'type':'null'}],[{'type':'i64','value':'0'}]],'candidate DTO difference lost')
    print(json.dumps({'status':'passed-readback-only','sqlite_comparisons':checked,
                      'candidate_cases':72,'controls':15,'reference_a0_value_equal':True,
                      'reference_a0_dto_equal':False,'profile_admitted':False,
                      'scope':'SQLite recomputed in memory; no new A0/A1 run, synthetic provider errors injected'}))


if __name__=='__main__':
    main()
