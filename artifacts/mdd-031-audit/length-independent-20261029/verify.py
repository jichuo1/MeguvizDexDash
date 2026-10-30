#!/usr/bin/env python3
"""Read-only verification of saved length probe, prior A0 and SQLite observations."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok,why):
    if not ok:
        raise ValueError(why)


def main():
    before=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    for path,expected in before['sha256'].items():
        require(sha(ROOT/path)==expected,'source drift: '+path)
    for phase in ('build','probe'):
        folder=HERE/phase
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream drift')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor drift')
    def external(path):
        return sorted((p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source'))
    require(external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock') and len(external(HERE/'Cargo.lock'))==46,'lock differs')
    refrec=json.loads((HERE/'reference/record.json').read_text(encoding='utf8'))
    require(refrec['exit_code']==0,'reference failed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/'reference'/(stream+'.txt'))==refrec[stream]['sha256'],'reference stream drift')
    reference=json.loads((HERE/'reference/stdout.txt').read_text(encoding='utf8'))
    oldpath=ROOT/'artifacts/mdd-031/a0-literals/observations.json'
    require(sha(oldpath)==reference['a0_sha256'],'old reference changed')
    db=sqlite3.connect(':memory:')
    observed={k:db.execute('SELECT length(?)',(v,)).fetchone()[0]
              for k,v in {'ascii':'ABC','empty':'','nul':'A\0B','pair':'😀','null':None}.items()}
    require(observed==reference['sqlite']=={'ascii':3,'empty':0,'nul':1,'pair':1,'null':None},'SQLite output differs')
    data=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(data['profile_admitted'] is False and len(data['cases'])==33,'probe case denominator')
    cases={(c['dialect'],c['case']):c for c in data['cases']}
    require(len(cases)==33,'duplicate case identity')
    def check_result(dialect,name,value):
        row=cases[dialect,name]
        require(row['status']=='ok' and row['complete'] is True and row['used_after_drop']==0,'delivery '+name)
        cell=row['rows'][0][0]
        if value is None:
            require(cell=={'type':'null'},'null representation')
        else:
            require(cell=={'type':'i64','value':str(value)},'value '+name)
    for dialect in ('NativeV1','DexSql010','DexSql011'):
        for name,value in [('ascii',3),('empty',0),('null',None),('nul',3),
                           ('pair',2 if dialect=='NativeV1' else 1),('unpaired',1),
                           ('adjacent',4 if dialect=='NativeV1' else 3),('large_success',10000)]:
            check_result(dialect,name,value)
        cancelled=cases[dialect,'cancel_before']
        require(cancelled['status']=='error' and cancelled['error']['code']=='CANCELLED'
                and not cancelled['execution_complete'] and cancelled['used_after']==0,'pre-cancel')
        steps=cases[dialect,'steps']
        if dialect=='NativeV1':
            check_result(dialect,'steps',50000)
        else:
            require(steps['status']=='error' and steps['error']['code']=='QUOTA_EXCEEDED'
                    and steps['error']['details']['budget']=='query_steps' and not steps['execution_complete']
                    and steps['used_after']==0,'old dialect step quota')
        observed_cancel=cases[dialect,'cancel_observed']
        require(observed_cancel['used_after']==0,'async release')
        if dialect=='NativeV1':
            require(observed_cancel['observed_steps']==0 and observed_cancel['result']['status']=='ok'
                    and observed_cancel['execution_complete'],'native O(1) terminal')
        else:
            require(observed_cancel['observed_steps']>5000 and observed_cancel['result']['status']=='error'
                    and observed_cancel['result']['error']['code']=='CANCELLED'
                    and not observed_cancel['execution_complete'],'old dialect observed cancellation')
    require(reference['a0_supplementary']['value']=='1' and reference['a0_nul']['value']=='3','A0 values')
    binary=ROOT/'artifacts/local/length-independent-20261029-target/debug/mdd-length-independent.exe'
    print(json.dumps({'status':'passed-scoped','cases':33,'legacy_step_quota_cases':2,
                      'native_step_result':'complete O(1)','legacy_observed_cancel_cases':2,
                      'native_async_observation':'already complete before cancellation','sqlite_version':sqlite3.sqlite_version,
                      'a0_pair':1,'a0_nul':3,'sqlite_pair':1,'sqlite_nul':1,'a1':'not_run in reference',
                      'source_before_and_after_equal':True,'functions_sha256':before['sha256']['crates/mdd-sql/src/dialects/functions.rs'],
                      'binary_sha256':sha(binary),'profile_admitted':False,
                      'scope':'synthetic bound sessions; logical steps only, not performance qualification',
                      'limitations':['cancellation requested after observed steps; exact instruction unknown',
                                     'Native direct length does not scan text; not forcibly charged per unit',
                                     'argument clones, SQLite, allocator, RSS and transport not covered',
                                     'A0 has two saved samples; no new A0/A1 execution']}))


if __name__=='__main__':
    main()
