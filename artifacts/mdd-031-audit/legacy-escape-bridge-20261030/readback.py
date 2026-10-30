#!/usr/bin/env python3
"""Read back real bridge observations and fixed legacy CLI values."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
LEGACY=ROOT/'artifacts/mdd-031-audit/legacy-escape-concat-20261030/runs/20261030T020336062047Z'
def require(value,reason):
    if not value:raise RuntimeError(reason)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    require(len(sys.argv)==2,'usage: readback.py RUN_NAME')
    run=(HERE/'runs'/sys.argv[1]).resolve();require(run.parent==(HERE/'runs').resolve(),'invalid run')
    report=json.loads((run/'report.json').read_text(encoding='utf8'))
    require(report['status']=='completed_observation' and report['source_unchanged'],'probe incomplete')
    require(not report['profile_admitted'] and not report['task_complete_proven'],'profile scope overstated')
    require(report['source_before']==report['source_after'],'source drift')
    for path,digest in report['source_before'].items():require(sha(ROOT/path)==digest,'source changed: '+path)
    for stage in ('build','probe'):
        job=json.loads((run/stage/'supervisor.json').read_text(encoding='utf8'))
        require(job==report[stage] and job['status']=='completed' and job['exit_code']==0
            and job['assigned_before_resume'] and job['tree_empty_verified'],stage+' job')
        require(job['limits']['memory_commit_bytes']==str(2*1024**3) and job['limits']['affinity_mask']=='15',stage+' limits')
        require(int(report['memory_'+stage]['available_bytes'])>=3*1024**3,stage+' admission')
    require(sha(ROOT/'artifacts/local/sql-independent-target/debug/mdd-independent-q03-probe.exe')==report['binary_sha256'],'binary identity')
    legacy=json.loads((LEGACY/'report.json').read_text(encoding='utf8'))
    old_readback=json.loads((LEGACY/'readback.json').read_text(encoding='utf8'))
    require(old_readback['status']=='passed_scoped_readback' and old_readback['report_sha256']==sha(LEGACY/'report.json'),'legacy readback')
    old={}
    for record in legacy['cases']:
        if record['case'] in ('dangling_like','dangling_not_like','escaped_literal','null_like'):
            path=LEGACY/(record['engine']+'-'+record['case'])/'stdout.txt'
            require(sha(path)==record['stdout_sha256'],'legacy raw output')
            rows=[[v.strip() for v in line.strip('|').split('|')] for line in path.read_text(encoding='utf8').splitlines() if line.startswith('|')]
            require(len(rows)==2 and rows[0]==['result'] and len(rows[1])==1,'legacy table')
            old[(record['engine'],record['case'])]=rows[1][0]
    require(len(old)==8,'legacy comparison incomplete')
    actual=json.loads((run/'probe/stdout.txt').read_text(encoding='utf8'))
    records={(r['dialect'],r['case']):r['result'] for r in actual['records']}
    cases={'dangling_like','dangling_not_like','escaped_literal','null_like','null_escape','low_budget','cancel_before'}
    require(len(records)==len(actual['records'])==21 and set(records)=={(d,c) for d in ('native','010','011') for c in cases},'case denominator')
    for dialect,engine in [('010','A0'),('011','A1')]:
        for case in ('dangling_like','dangling_not_like','escaped_literal','null_like'):
            result=records[(dialect,case)];require(result['status']=='ok' and result['result']['calculation_complete'],'legacy bridge computation')
            cells=result['result']['rows'];expected=old[(engine,case)]
            semantic={'type':'null'} if expected=='NULL' else {'type':'i64','value':expected}
            require(cells==[[semantic]],dialect+' '+case+' semantic mismatch')
    for dialect in ('native','010','011'):
        for case,code in [('low_budget','QUOTA_EXCEEDED'),('cancel_before','CANCELLED')]:
            result=records[(dialect,case)];require(result['status']=='error' and result['error']['code']==code,dialect+' '+case)
        for case in ('null_like','null_escape'):
            result=records[(dialect,case)];require(result['status']=='ok' and result['result']['rows']==[[{'type':'null'}]],dialect+' '+case)
        result=records[(dialect,'escaped_literal')];require(result['status']=='ok' and result['result']['rows']==[[{'type':'i64','value':'1'}]],dialect+' escaped_literal')
    for case in ('dangling_like','dangling_not_like'):
        result=records[('native',case)];require(result['status']=='error' and result['error']['code']=='INVALID_ARGUMENT'
            and result['error']['message']=='LIKE_DANGLING_ESCAPE','native prior behavior')
    result={'status':'passed_scoped_readback','cases':len(records),'legacy_semantic_comparisons':8,
        'report_sha256':sha(run/'report.json'),'stdout_sha256':sha(run/'probe/stdout.txt'),
        'legacy_report_sha256':sha(LEGACY/'report.json'),'binary_sha256':report['binary_sha256'],
        'source_sha256':report['source_before'],'profile_admitted':False,'task_complete_proven':False,
        'scope':'synthetic public bridge and fixed CLI value comparison; no DTO, worker, complete dialect or performance claim'}
    (run/'readback.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'status':result['status'],'cases':result['cases'],'legacy_semantic_comparisons':result['legacy_semantic_comparisons']}))
if __name__=='__main__':main()
