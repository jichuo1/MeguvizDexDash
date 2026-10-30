#!/usr/bin/env python3
"""Recompute SQLite in memory and read saved candidate evidence without writes."""
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def require(ok,why):
    if not ok: raise RuntimeError(why)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):return json.loads(path.read_text(encoding='utf8'))


def value(cell):
    if cell['type']=='null':
        require('value' not in cell,'NULL representation changed');return None
    require(cell['type']=='i64' and isinstance(cell['value'],str),'unexpected typed cell')
    return int(cell['value'])


def main():
    report=read(HERE/'qualification.json'); verify=read(HERE/'verify-run/record.json')
    require(report['status']=='passed-scoped' and verify['exit_code']==0
            and not report['profile_admitted'] and not report['dto_equal'] and not report['a0_a1_started'],
            'scope or original verifier changed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/('verify-run/'+stream+'.txt'))==verify[stream]['sha256'],'verifier stream changed')
    for path,digest in report['source_sha256'].items():require(sha(ROOT/path)==digest,'source changed: '+path)
    require(sha(HERE/'probe/stdout.txt')==report['probe_stdout_sha256']
            and sha(HERE/'sqlite-reference.json')==report['sqlite_reference_sha256'],'raw evidence changed')
    binary=ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-group-ordinal-independent.exe'
    require(sha(binary)==report['binary_sha256'],'binary changed')
    refs=read(HERE/'sqlite-reference.json')
    require(refs['sqlite_version']==sqlite3.sqlite_version and len(refs['records'])==14,'SQLite identity')
    data=read(HERE/'probe/stdout.txt'); rows={(r['dialect'],r['case']):r for r in data['records']}
    require(len(rows)==len(data['records'])==54 and not data['profile_admitted'],'candidate denominator')
    comparisons=0
    for ref in refs['records']:
        db=sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE facts(k INTEGER,alt INTEGER NOT NULL)')
            db.executemany('INSERT INTO facts(k,alt) VALUES (?,?)',[(None,9),(1,10),(1,20),(2,30)])
            try:
                cur=db.execute(ref['sql'])
                actual={'status':'ok','columns':[x[0] for x in cur.description],'rows':[list(x) for x in cur.fetchall()]}
            except sqlite3.Error as e:
                actual={'status':'error','message':str(e)}
        finally:db.close()
        require(actual['status']==ref['status'],'SQLite status changed: '+ref['case'])
        if ref['status']=='ok':require(actual['columns']==ref['columns'] and actual['rows']==ref['rows'],'SQLite rows changed')
        else:require(actual['message']==ref['message'],'SQLite error changed')
        for dialect in ('native','010','011'):
            item=rows[(dialect,ref['case'])]; result=item['result']
            require(item['sql']==ref['sql'],'SQL mismatch')
            if ref['status']=='ok':
                require(result['status']=='ok' and result['result']['calculation_complete']
                        and result['result']['columns']==ref['columns']
                        and [[value(c) for c in row] for row in result['result']['rows']]==ref['rows'],
                        'bridge results differ: '+dialect+'/'+ref['case'])
            else:require(result['status'] in ('error','prepare_error') and result['error']['code']=='INVALID_ARGUMENT',
                         'bridge error differs: '+ref['case'])
            comparisons+=1
    controls={'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED',
              'step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED'}
    for dialect in ('native','010','011'):
        for name,code in controls.items():
            result=rows[(dialect,name)]['result']
            require(result['status']=='error' and result['error']['code']==code,'control terminal differs')
    print(json.dumps({'status':'passed-readback-only','sqlite_comparisons':comparisons,'controls':12,
                      'a0_a1_started':False,'profile_admitted':False,
                      'scope':'in-memory SQLite recomputation and synthetic provider bridge receipts'}))


if __name__=='__main__':main()
