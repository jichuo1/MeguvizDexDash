#!/usr/bin/env python3
"""Read-only recheck of GROUP/ORDER positional numeric boundary evidence."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
PRIOR=ROOT/'artifacts/mdd-031-audit/group-ordinal-independent-20261029'


def require(ok,why):
    if not ok: raise RuntimeError(why)


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):return json.loads(p.read_text(encoding='utf8'))


def value(v):
    if v['type']=='null':
        require('value' not in v,'NULL representation changed');return None
    require(v['type']=='i64' and isinstance(v['value'],str),'unexpected native cell')
    return int(v['value'])


def main():
    q=read(HERE/'qualification.json');record=read(HERE/'verify-run/record.json')
    require(q['status']=='passed-scoped' and record['exit_code']==0 and not q['profile_admitted']
            and not q['dto_equal'] and not q['a0_a1_started'],'scope or qualification differs')
    for stream in ('stdout','stderr'):
        require(sha(HERE/('verify-run/'+stream+'.txt'))==record[stream]['sha256'],'verifier stream changed')
    for path,digest in q['source_sha256'].items():require(sha(ROOT/path)==digest,'source changed: '+path)
    require(sha(HERE/'sqlite-reference.json')==q['extra_reference_sha256']
            and sha(PRIOR/'sqlite-reference.json')==q['prior_reference_sha256']
            and sha(HERE/'probe/stdout.txt')==q['probe_stdout_sha256'],'reference or candidate changed')
    binary=ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-group-ordinal-boundary.exe'
    require(sha(binary)==q['binary_sha256'],'binary changed')
    docs=[read(PRIOR/'sqlite-reference.json'),read(HERE/'sqlite-reference.json')]
    require(all(d['sqlite_version']==sqlite3.sqlite_version for d in docs),'SQLite version differs')
    refs={x['case']:x for d in docs for x in d['records']}
    data=read(HERE/'probe/stdout.txt');rows={(r['dialect'],r['case']):r for r in data['records']}
    require(len(refs)==26 and len(rows)==len(data['records'])==90 and not data['profile_admitted'],'denominator')
    comparisons=0
    for name,ref in refs.items():
        db=sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE facts(k INTEGER,alt INTEGER NOT NULL)')
            db.executemany('INSERT INTO facts(k,alt) VALUES (?,?)',[(None,9),(1,10),(1,20),(2,30)])
            try:
                cur=db.execute(ref['sql']);actual={'status':'ok','columns':[x[0] for x in cur.description],
                                                   'rows':[list(x) for x in cur.fetchall()]}
            except sqlite3.Error as e:actual={'status':'error','message':str(e)}
        finally:db.close()
        require(actual['status']==ref['status'],'SQLite status changed: '+name)
        if ref['status']=='ok':require(actual['columns']==ref['columns'] and actual['rows']==ref['rows'],'SQLite rows drift')
        else:require(actual['message']==ref['message'],'SQLite error drift')
        for dialect in ('native','010','011'):
            item=rows[(dialect,name)];result=item['result'];require(item['sql']==ref['sql'],'query mismatch')
            if ref['status']=='ok':
                require(result['status']=='ok' and result['result']['calculation_complete']
                        and result['result']['columns']==ref['columns'],'bridge terminal/columns differ')
                got=[[value(v) for v in row] for row in result['result']['rows']]
                same=sorted(got)==sorted(ref['rows']) if name.startswith('order_') else got==ref['rows']
                require(same,'bridge rows differ: '+dialect+'/'+name)
            else:require(result['status'] in ('error','prepare_error') and result['error']['code']=='INVALID_ARGUMENT',
                         'bridge invalid query error differs')
            comparisons+=1
    controls={'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED',
              'step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED'}
    for dialect in ('native','010','011'):
        for name,code in controls.items():
            r=rows[(dialect,name)]['result'];require(r['status']=='error' and r['error']['code']==code,'control differs')
    print(json.dumps({'status':'passed-readback-only','sqlite_comparisons':comparisons,'controls':12,
                      'a0_a1_started':False,'profile_admitted':False,
                      'scope':'in-memory SQLite and saved synthetic-provider bridge results; no transport qualification'}))


if __name__=='__main__':main()
