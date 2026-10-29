#!/usr/bin/env python3
"""Read-only SQLite/bridge comparison; append only the qualification receipt."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def require(ok,why):
    if not ok: raise RuntimeError(why)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):return json.loads(path.read_text(encoding='utf8'))


def value(cell):
    if cell['type']=='null':
        require('value' not in cell,'native NULL shape changed');return None
    require(cell['type']=='i64' and isinstance(cell['value'],str),'unexpected typed value')
    return int(cell['value'])


def main():
    ref_record=read(HERE/'sqlite-run/record.json')
    require(ref_record['exit_code']==0,'SQLite command failed')
    for s in ('stdout','stderr'):
        require(sha(HERE/('sqlite-run/'+s+'.txt'))==ref_record[s]['sha256'],'SQLite stream changed')
    for name in ('build','probe'):
        p=HERE/name; rec=read(p/'record.json'); job=read(p/'supervisor.json')
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified']
                and job['status']=='completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name+' did not complete')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],name+' supervisor changed')
        for s in ('stdout','stderr'):
            require(sha(p/(s+'.txt'))==rec[s+'_sha256'],name+' stream changed')
    sources=read(HERE/'source-before.json')
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'source changed: '+path)
    def external(path):
        return {(p['name'],p['version'],p.get('checksum'))
                for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(ROOT/'Cargo.lock'))==46 and external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock'),
            'external lock mismatch')
    reference=read(HERE/'sqlite-reference.json')
    refs={r['case']:r for r in reference['records']}
    candidate=read(HERE/'probe/stdout.txt')
    rows={(r['dialect'],r['case']):r for r in candidate['records']}
    require(len(refs)==14 and len(rows)==len(candidate['records'])==54 and not candidate['profile_admitted'],
            'case denominator differs')
    controls={'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED',
              'step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED'}
    comparisons=0
    for dialect in ('native','010','011'):
        for name,ref in refs.items():
            item=rows[(dialect,name)]; result=item['result']; require(item['sql']==ref['sql'],'SQL differs: '+name)
            if ref['status']=='ok':
                require(result['status']=='ok' and result['result']['calculation_complete']
                        and result['result']['columns']==ref['columns']
                        and [[value(c) for c in row] for row in result['result']['rows']]==ref['rows'],
                        'value/order/column mismatch: '+dialect+'/'+name)
            else:
                require(result['status'] in ('error','prepare_error') and result['error']['code']=='INVALID_ARGUMENT',
                        'binding error lost: '+dialect+'/'+name)
            comparisons+=1
        for name,code in controls.items():
            result=rows[(dialect,name)]['result']
            require(result['status']=='error' and result['error']['code']==code,'control lost: '+dialect+'/'+name)
            if name=='source_changed':require(result['error']['stage']=='fixture.source','source error rewritten')
    report={'status':'passed-scoped','candidate_cases':len(rows),'sqlite_comparisons':comparisons,
            'control_terminals':len(controls)*3,'sqlite_version':reference['sqlite_version'],
            'source_sha256':sources,'probe_stdout_sha256':sha(HERE/'probe/stdout.txt'),
            'binary_sha256':sha(ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-group-ordinal-independent.exe'),
            'sqlite_reference_sha256':sha(HERE/'sqlite-reference.json'),
            'a0_a1_started':False,'profile_admitted':False,'dto_equal':False,
            'scope':'synthetic provider and SQLite values/ordering; A0/A1 not sampled; no full profile or transport qualification',
            'injected_controls':'source change and incomplete facts are synthetic provider errors'}
    path=HERE/'qualification.json';require(not path.exists(),'qualification already exists')
    path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({k:report[k] for k in ('status','candidate_cases','sqlite_comparisons','control_terminals','a0_a1_started','profile_admitted')}))


if __name__=='__main__':main()
