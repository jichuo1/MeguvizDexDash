#!/usr/bin/env python3
"""Compare latest SQL ordinal behavior to independently executed SQLite references."""
import hashlib
import json
from pathlib import Path
import tomllib

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
    require(v['type']=='i64' and isinstance(v['value'],str),'unexpected candidate cell')
    return int(v['value'])


def main():
    for folder in (HERE/'sqlite-run',PRIOR/'sqlite-run'):
        rec=read(folder/'record.json');require(rec['exit_code']==0,'SQLite reference failed')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream]['sha256'],'SQLite output changed')
    for name in ('build','probe'):
        folder=HERE/name;rec=read(folder/'record.json');job=read(folder/'supervisor.json')
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified']
                and job['status']=='completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name+' job failed')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],'job receipt changed')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],'job stream changed')
    sources=read(HERE/'source-before.json')
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'source changed: '+path)
    def external(path):
        return {(p['name'],p['version'],p.get('checksum'))
                for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(ROOT/'Cargo.lock'))==46 and external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock'),
            'external lock differs')
    prior=read(PRIOR/'sqlite-reference.json');extra=read(HERE/'sqlite-reference.json')
    refs={r['case']:r for doc in (prior,extra) for r in doc['records']}
    data=read(HERE/'probe/stdout.txt');rows={(r['dialect'],r['case']):r for r in data['records']}
    require(len(refs)==26 and len(rows)==len(data['records'])==90 and not data['profile_admitted'],
            'case denominator differs')
    controls={'missing_limit_zero':'INCOMPLETE_FACTS','source_changed':'SOURCE_CHANGED',
              'step_limit':'QUOTA_EXCEEDED','cancelled':'CANCELLED'}
    comparisons=0
    for dialect in ('native','010','011'):
        for name,ref in refs.items():
            item=rows[(dialect,name)]; result=item['result'];require(item['sql']==ref['sql'],'SQL differs: '+name)
            if ref['status']=='ok':
                require(result['status']=='ok' and result['result']['calculation_complete']
                        and result['result']['columns']==ref['columns'],'terminal/columns differ: '+name)
                got=[[value(v) for v in row] for row in result['result']['rows']]
                # ORDER BY a constant does not define the order of equal keys.
                equal=sorted(got)==sorted(ref['rows']) if name.startswith('order_') else got==ref['rows']
                require(equal,'value/order differs: '+dialect+'/'+name)
            else:
                require(result['status'] in ('error','prepare_error') and result['error']['code']=='INVALID_ARGUMENT',
                        'binding error lost: '+dialect+'/'+name)
            comparisons+=1
        for name,code in controls.items():
            result=rows[(dialect,name)]['result']
            require(result['status']=='error' and result['error']['code']==code,'terminal differs: '+name)
            if name=='source_changed':require(result['error']['stage']=='fixture.source','source error rewritten')
    result={'status':'passed-scoped','candidate_cases':90,'sqlite_comparisons':comparisons,'controls':12,
            'integer_boundary_cases':36,'sqlite_version':extra['sqlite_version'],'source_sha256':sources,
            'prior_reference_sha256':sha(PRIOR/'sqlite-reference.json'),'extra_reference_sha256':sha(HERE/'sqlite-reference.json'),
            'probe_stdout_sha256':sha(HERE/'probe/stdout.txt'),
            'binary_sha256':sha(ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-group-ordinal-boundary.exe'),
            'a0_a1_started':False,'profile_admitted':False,'dto_equal':False,
            'scope':'synthetic provider and SQLite value/order reference; constant-key ORDER ties compared as multiset',
            'injected_controls':'SOURCE_CHANGED and INCOMPLETE_FACTS are synthetic provider errors'}
    output=HERE/'qualification.json';require(not output.exists(),'do not overwrite qualification')
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({k:result[k] for k in ('status','candidate_cases','sqlite_comparisons','controls',
                                           'integer_boundary_cases','a0_a1_started','profile_admitted')}))


if __name__=='__main__':main()
