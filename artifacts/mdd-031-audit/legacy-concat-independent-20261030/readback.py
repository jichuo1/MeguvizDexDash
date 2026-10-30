#!/usr/bin/env python3
"""Compare bridge rows to the frozen, separately supervised legacy CLI outputs."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
OLD=ROOT/'artifacts/mdd-031-audit/legacy-concat-matrix-20261030/runs/20261030T021302616646Z'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))
def text(cell):
    if cell.get('type')!='text':return None
    return ''.join(chr(n) for n in cell['value']['utf16'])

def main():
    if len(sys.argv)!=2:raise ValueError('usage: readback.py RUN_NAME')
    run=(HERE/'runs'/sys.argv[1]).resolve()
    if run.parent!=(HERE/'runs').resolve():raise ValueError('invalid run')
    report=read(run/'report.json');old=read(OLD/'report.json');old_verify=read(OLD/'readback.json')
    checks={};failures=[]
    checks['completed_source_and_engine_stable']=report['status']=='completed_observation' and report['source_unchanged'] and report['source_before']==report['source_after'] and report['engine_before']==report['engine_after'] and all(x['matches'] for x in report['engine_before'].values())
    checks['no_source_drift']=all(sha(ROOT/name)==digest for name,digest in report['source_before'].items())
    checks['old_readback_and_report']=old_verify['status']=='passed_scoped_readback' and old_verify['cases']==32 and old_verify['report_sha256']==sha(OLD/'report.json') and old['identities_unchanged']
    checks['old_engine_and_input_identity']=all(item['matches'] and sha(Path(item['path']))==item['sha256']==item['expected_sha256'] for item in old['identities_before'].values())
    for stage in ('build','probe'):
        job=read(run/stage/'supervisor.json');checks[stage+'_supervision']=job==report[stage] and job['status']=='completed' and job['exit_code']==0 and job['assigned_before_resume'] and job['tree_empty_verified'] and job['limits']['memory_commit_bytes']==str(2*1024**3) and job['limits']['affinity_mask']=='15' and int(report['memory_'+stage]['available_bytes'])>=3*1024**3
    binary=ROOT/'artifacts/local/legacy-concat-independent-20261030-target/debug/mdd-concat-independent.exe'
    checks['candidate_binary_identity']=sha(binary)==report['binary_sha256']
    observed=read(run/'probe/stdout.txt');items=observed['records'];records={(r['dialect'],r['result']['case']):r['result'] for r in items}
    cases={'ascii','valid_utf8','split_utf8','split_supplementary','truncated_prefix','invalid_continuation','two_invalid','overlong_nul','blob_text','text_blob','blob_unicode_text','null_right','null_left','source_nul','source_surrogate','source_pair'}
    extras={kind+'_'+mode for kind in ('text','bytes') for mode in ('low','high','pre_cancel','observed_cancel')}
    checks['case_denominator']=len(records)==len(items)==72 and set(records)=={(d,c) for d in ('native','A0','A1') for c in cases|extras}
    checks['profiles_not_admitted']=not observed['profile_admitted'] and not report['profile_admitted'] and not report['task_complete_proven']
    old_cases={}
    for item in old['cases']:
        key=(item['engine'],item['case']);folder=OLD/(key[0]+'-'+key[1]);raw=folder/'stdout.txt'
        if item['status']!='observed' or sha(raw)!=item['stdout_sha256']:
            failures.append(f'old log {key}');continue
        rows=[[v.strip() for v in line.strip('|').split('|')] for line in raw.read_text(encoding='utf8').splitlines() if line.startswith('|')]
        if len(rows)!=2 or rows[0]!=['result_type','result_hex'] or len(rows[1])!=2:
            failures.append(f'old table {key}');continue
        old_cases[key]=dict(zip(rows[0],rows[1]))
    checks['old_raw_32']=len(old_cases)==32 and set(old_cases)=={(d,c) for d in ('A0','A1') for c in cases}
    compared=[]
    for key in sorted(old_cases):
        r=records.get(key,{});expected=old_cases[key]
        valid=r.get('status')=='ok' and r.get('complete') is True and r.get('used_after')==0 and len(r.get('rows',[]))==1 and len(r['rows'][0])==2
        if valid:
            value,h=r['rows'][0];kind=value['type'];hex_value=text(h)
            valid=kind==expected['result_type'] and hex_value==expected['result_hex']
        if valid:compared.append(key)
        else:failures.append(f'legacy mismatch {key}: {r}')
    checks['legacy_32_type_and_hex']=len(compared)==32
    for d in ('native','A0','A1'):
        for kind in ('text','bytes'):
            low=records.get((d,kind+'_low'),{});high=records.get((d,kind+'_high'),{});pre=records.get((d,kind+'_pre_cancel'),{});during=records.get((d,kind+'_observed_cancel'),{})
            if not (low.get('status')=='error' and low.get('error',{}).get('code')=='QUOTA_EXCEEDED' and low.get('used_after')==0 and low.get('execution_complete') is False):failures.append(f'quota {d}/{kind}: {low}')
            if not (high.get('status')=='ok' and high.get('complete') is True and high.get('used_after')==0 and high.get('rows')==[[{'type':'i64','value':'0'}]]):failures.append(f'high {d}/{kind}: {high}')
            if not (pre.get('status')=='error' and pre.get('error',{}).get('code')=='CANCELLED' and pre.get('used_after')==0 and pre.get('execution_complete') is False):failures.append(f'pre-cancel {d}/{kind}: {pre}')
            if not (during.get('status')=='observed_cancel' and during.get('observed_steps',0)>5000 and during.get('outcome',{}).get('status')=='error' and during['outcome']['error']['code']=='CANCELLED' and during.get('used_after')==0 and during.get('execution_complete') is False):failures.append(f'active-cancel {d}/{kind}: {during}')
    checks['all_control_cases']=not any(f.startswith(('quota ','high ','pre-cancel ','active-cancel ')) for f in failures)
    native={case:records.get(('native',case),{}) for case in sorted(cases)}
    result={'status':'passed_scoped' if all(checks.values()) and not failures else 'failed_or_incomplete','checks':checks,'failures':failures,'legacy_comparisons':len(compared),'native_observations':native,'source_sha256':report['source_before'],'candidate_binary_sha256':report['binary_sha256'],'report_sha256':sha(run/'report.json'),'probe_stdout_sha256':sha(run/'probe/stdout.txt'),'readback_sha256':sha(Path(__file__)),'profile_admitted':False,'task_complete_proven':False,'scope':'synthetic DEX, public bridge semantic type and HEX comparison; no DTO wire, production worker, full corpus or performance qualification'}
    (run/'readback.json').write_text(json.dumps(result,indent=2,ensure_ascii=True)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'status':result['status'],'checks':checks,'failures':failures,'legacy_comparisons':len(compared)}))
    return 0 if result['status']=='passed_scoped' else 1
if __name__=='__main__':raise SystemExit(main())
