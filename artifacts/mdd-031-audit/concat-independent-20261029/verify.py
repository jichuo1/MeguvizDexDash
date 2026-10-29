#!/usr/bin/env python3
"""Verify isolated concat probe without treating SQLite blob type as candidate equivalence."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SNAP=ROOT/'handoff/concat-3c334c5-20261029'


def require(ok,why):
    if not ok: raise ValueError(why)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before=json.loads((HERE/'snapshot-before.json').read_text(encoding='utf8'))
    pb=json.loads((HERE/'probe-before.json').read_text(encoding='utf8'))
    after=json.loads((HERE/'snapshot-after.json').read_text(encoding='utf8'))
    require(before['base_commit']=='3c334c5d365126268dd0d5488ab33c4d2dd23173'
            and len(before['files_sha256'])==94 and len(before['override_sources'])==2,'snapshot scope')
    require(after['all_snapshot_files_equal'] and after['all_probe_files_equal']
            and after['snapshot_before_sha256']==sha(HERE/'snapshot-before.json')
            and after['probe_before_sha256']==sha(HERE/'probe-before.json'),'snapshot receipt drift')
    for name,digest in before['files_sha256'].items(): require(sha(SNAP/name)==digest,'snapshot drift '+name)
    for name,digest in pb['probe_files_sha256'].items(): require(sha(HERE/name)==digest,'probe drift '+name)
    for phase in ('build','probe'):
        p=HERE/phase; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'): require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],phase+' '+stream)
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor')
    refrec=json.loads((HERE/'reference/record.json').read_text(encoding='utf8'))
    require(refrec['exit_code']==0,'reference failed')
    for stream in ('stdout','stderr'): require(sha(HERE/'reference'/(stream+'.txt'))==refrec[stream]['sha256'],'reference stream')
    ref=json.loads((HERE/'reference/stdout.txt').read_text(encoding='utf8'))
    require(sha(ROOT/'artifacts/mdd-031/a0-literals/observations.json')==ref['a0_source_sha256']
            and ref['a0_null']=={'type':'null','value':None},'old A0 reference')
    db=sqlite3.connect(':memory:')
    sqlite_type,sqlite_hex=db.execute("SELECT typeof(X'00FF'||X'41'),hex(X'00FF'||X'41')").fetchone()
    require((sqlite_type,sqlite_hex)==('text','00FF41') and ref['blob_concat_type']=='text'
            and ref['blob_concat_hex']=='00FF41','SQLite blob observation')
    data=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(not data['profiles_admitted'] and len(data['cases'])==48,'denominator')
    by={(r['dialect'],r['case']):r for r in data['cases']}; require(len(by)==48,'duplicate case')
    for d in ('NativeV1','DexSql010','DexSql011'):
        expected={'ascii':[65,66],'empty':[],'nul':[65,0,66],'unpaired':[0xd800,66],'pair':[0xd83d,0xde00,66]}
        for case,units in expected.items():
            r=by[d,case]; require(r['status']=='ok' and r['complete'] and r['used_after_drop']==0,'text terminal '+case)
            cell=r['rows'][0][0];require(cell['type']=='text' and cell['value']['utf16']==units
                  and cell['value']['original_mutf8'] is None,'text units '+case)
        for case in ('null_left','null_right'):
            r=by[d,case];require(r['status']=='ok' and r['complete'] and r['rows']==[[{'type':'null'}]]
                                 and r['used_after_drop']==0,'NULL result')
        r=by[d,'bytes'];require(r['status']=='ok' and r['complete'] and r['rows']==[[{'type':'bytes','value':[0,255,65]}]]
                               and r['used_after_drop']==0,'bytes result')
        for typ in ('text','bytes'):
            low=by[d,typ+'_low']; require(low['status']=='error' and low['error']['code']=='QUOTA_EXCEEDED'
                  and low['error']['details']['budget']=='query_steps' and not low['execution_complete']
                  and low['used_after']==0,'step quota '+typ)
            high=by[d,typ+'_high'];require(high['status']=='ok' and high['complete'] and high['used_after_drop']==0
                  and high['rows']==[[{'type':'i64','value':'0'}]],'high step result '+typ)
            pre=by[d,typ+'_pre_cancel'];require(pre['status']=='error' and pre['error']['code']=='CANCELLED'
                  and not pre['execution_complete'] and pre['used_after']==0,'pre cancel '+typ)
            active=by[d,typ+'_observed_cancel'];require(active['observed_steps']>5000
                  and active['result']['status']=='error' and active['result']['error']['code']=='CANCELLED'
                  and not active['execution_complete'] and active['used_after']==0,'observed cancel '+typ)
    binary=ROOT/'artifacts/local/concat-independent-20261029-target/debug/mdd-concat-independent.exe'
    require(sha(binary)==after['binary_sha256'],'binary drift')
    print(json.dumps({'status':'passed-scoped','base_commit':before['base_commit'],'snapshot_sources':94,
                      'overrides':before['override_sources'],'cases':48,'quota_cases':6,'pre_cancel_cases':6,
                      'observed_cancel_cases':6,'sqlite_blob_type':'text','candidate_blob_type':'bytes',
                      'same_blob_hex':sqlite_hex,'a0_null_observed':True,'a0_a1_blob_concat':'not_run',
                      'source_before_after_equal':True,'binary_sha256':sha(binary),'profiles_admitted':False,
                      'scope':'synthetic bound SQL sessions from isolated snapshot, not current query source',
                      'limitations':['only one prior A0 NULL observation, no A1 or byte concat reference',
                                     'candidate Bytes and SQLite text are not equal DTO types',
                                     'argument clones, result/SQLite/allocator/RSS/transport not covered',
                                     'cancel requested after observed steps; exact internal instruction unknown']}))


if __name__=='__main__': main()
