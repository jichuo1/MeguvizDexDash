#!/usr/bin/env python3
"""Read-only recomputation of SQLite case controls and saved session terminals."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
CASES=('low','long_ok','ascii','empty','null','nul','non_ascii','non_scalar','cancel_before','cancel_observed')


def require(ok,why):
    if not ok:raise RuntimeError(why)


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):return json.loads(p.read_text(encoding='utf8'))


def text(units):return b''.join(int(v).to_bytes(2,'little') for v in units).decode('utf-16-le',errors='strict')


def main():
    sqlite_record=read(HERE/'sqlite-run/record.json')
    require(sqlite_record['exit_code']==0,'SQLite command failed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/('sqlite-run/'+stream+'.txt'))==sqlite_record[stream]['sha256'],'SQLite stream changed')
    for name in ('build-full','probe-full'):
        folder=HERE/name;rec=read(folder/'record.json');job=read(folder/'supervisor.json')
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified']
                and job['status']=='completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name+' job incomplete')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],'supervisor changed')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],'job stream changed')
    previous=read(HERE/'initial-run-identity.json');initial=read(HERE/'probe/stdout.txt')
    require(sha(HERE/'src/main-before-full.rs')==previous['source_sha256']
            and sha(HERE/'probe/stdout.txt')==previous['stdout_sha256']
            and len(initial['records'])==previous['records']==60,'initial summary run changed')
    sources=read(HERE/'source-before-full.json')
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'source changed: '+path)
    def external(p):
        return {(x['name'],x['version'],x.get('checksum'))
                for x in tomllib.loads(p.read_text(encoding='utf8'))['package'] if x.get('source')}
    require(len(external(ROOT/'Cargo.lock'))==46 and external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock'),
            'external lock differs')
    reference=read(HERE/'sqlite-reference.json');require(reference['sqlite_version']==sqlite3.sqlite_version,'SQLite version')
    refs={x['case']:x for x in reference['records']};require(len(refs)==5,'SQLite denominator')
    db=sqlite3.connect(':memory:')
    try:
        for name,item in refs.items():
            lo,hi=db.execute('SELECT lower(?),upper(?)',(item['input'],item['input'])).fetchone()
            require((lo,hi)==(item['lower'],item['upper']),'SQLite reference drift: '+name)
    finally:db.close()
    data=read(HERE/'probe-full/stdout.txt');rows={(x['dialect'],x['result']['operator'],x['result']['case']):x['result'] for x in data['records']}
    require(len(rows)==len(data['records'])==60 and not data['profile_admitted'],'candidate denominator')
    counts={'sqlite_compared':0,'surrogate_compared':0,'long_results_compared':0,'quotas':0,'cancelled':0}
    observed=[]
    for dialect in ('native','010','011'):
        for op in ('lower','upper'):
            low=rows[(dialect,op,'low')]
            require(low['status']=='error' and low['error']['code']=='QUOTA_EXCEEDED'
                    and low['error']['details']['budget']=='query_steps' and not low['execution_complete']
                    and low['workspace_after']==0,'quota terminal differs')
            counts['quotas']+=1
            for case in ('cancel_before','cancel_observed'):
                r=rows[(dialect,op,case)]
                error=r['error'] if case=='cancel_before' else r['result']['error']
                status=r['status'] if case=='cancel_before' else r['result']['status']
                release=r['workspace_after'] if case=='cancel_before' else r['used_workspace_after']
                require(status=='error' and error['code']=='CANCELLED' and not r['execution_complete']
                        and release==0,'cancel terminal differs')
                if case=='cancel_observed':
                    require(r['observed_steps_before_cancel']>5000,'scan steps not observed')
                    observed.append(r['observed_steps_before_cancel'])
                counts['cancelled']+=1
            for case in ('long_ok','ascii','empty','null','nul','non_ascii','non_scalar'):
                r=rows[(dialect,op,case)]
                require(r['status']=='ok' and r['calculation_complete'] and r['execution_complete']
                        and r['workspace_held']>0 and r['workspace_after_drop']==0,'success or release differs')
                require(len(r['rows'])==1 and len(r['rows'][0])==1,'row cardinality differs')
                cell=r['rows'][0][0]
                if case=='null':
                    require(cell=={'type':'null'} and refs['null'][op] is None,'NULL differs')
                    counts['sqlite_compared']+=1;continue
                require(cell['type']=='text' and cell['value']['original_mutf8'] is None,'text shape differs')
                units=cell['value']['utf16']
                if case=='long_ok':
                    wanted=ord('a' if op=='lower' else 'A')
                    require(len(units)==10_000 and all(unit==wanted for unit in units),'long output differs')
                    counts['long_results_compared']+=1
                elif case=='non_scalar':
                    wanted=([0x61,0,0xd800,0x61,0xdc00] if op=='lower' else [0x41,0,0xd800,0x41,0xdc00])
                    require(units==wanted,'non-scalar UTF16 differs');counts['surrogate_compared']+=1
                else:
                    require(text(units)==refs[case][op],'SQLite scalar differs: '+case)
                    counts['sqlite_compared']+=1
    require(counts=={'sqlite_compared':30,'surrogate_compared':6,'long_results_compared':6,'quotas':6,'cancelled':12},
            'count mismatch')
    result={'status':'passed-scoped','candidate_cases':60,**counts,'sqlite_version':sqlite3.sqlite_version,
            'minimum_observed_steps_before_cancel':min(observed),'source_sha256':sources,
            'candidate_stdout_sha256':sha(HERE/'probe-full/stdout.txt'),
            'sqlite_reference_sha256':sha(HERE/'sqlite-reference.json'),
            'binary_sha256':sha(ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-case-budget-independent.exe'),
            'a0_a1_started':False,'old_case_function_reference':'not located in existing completed evidence',
            'profile_admitted':False,'dto_equivalent':False,
            'scope':'synthetic real snapshot/session; observed query steps before cancel, not exact instruction phase',
            'limits':['SQLite and decoded parameter allocations are not budgeted here','not an RSS or transport proof',
                      'isolated surrogates checked as UTF16 units, not as SQLite UTF8 strings']}
    out=HERE/'qualification.json';require(out.is_file(),'qualification is absent')
    require(read(out)==result,'recomputed qualification differs')
    output={k:result[k] for k in ('candidate_cases','sqlite_compared','surrogate_compared',
                                 'long_results_compared','quotas','cancelled','profile_admitted')}
    output['status']='passed-readback-only'
    print(json.dumps(output))


if __name__=='__main__':main()
