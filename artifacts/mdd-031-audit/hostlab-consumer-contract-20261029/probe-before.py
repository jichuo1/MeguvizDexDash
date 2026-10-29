#!/usr/bin/env python3
"""Exercise frozen HostLab consumers with saved cells and explicitly synthetic envelopes.

No engine, network or APK is opened. This is not a production adapter or profile gate.
"""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[3]
FROZEN=ROOT/'conformance/corpus/hostlab/source-8782f43'
REFERENCE=ROOT/'artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z'
CANDIDATE=ROOT/'artifacts/mdd-031/integer-cast-20261029/runs/20261028T174502714475Z'
WRAPPER=ROOT/'artifacts/mdd-031-audit/hostlab-case-hex-independent-20261029'


def require(ok,why):
    if not ok: raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def saved_case(engine,kind,name):
    path=REFERENCE/(engine+'-'+kind)/(engine+'.observations.json')
    summary=json.loads((REFERENCE/'summary.json').read_text(encoding='utf8'))
    entry=next(x for x in summary['records'] if x['variant']==engine and x['kind']==kind)
    require(sha(path)==entry['observations_sha256'],'saved reference drift')
    data=json.loads(path.read_text(encoding='utf8'))
    item=next(x for x in data['cases'] if x['id']==name)
    require(item['close']['body']['closed'] is True,'dataset not closed')
    raw=item['statements'][0]['response']['body']
    statement=raw['statements'][0]
    require(statement['total_rows']==1 and not statement['truncated'] and statement['next_offset'] is None,'saved page incomplete')
    return raw,statement['rows'][0][0],path


def candidate_case(kind,name):
    path=CANDIDATE/'candidate/stdout.txt'
    rec=json.loads((CANDIDATE/'candidate/record.json').read_text(encoding='utf8'))
    require(rec['exit_code']==0 and sha(path)==rec['stdout_sha256'],'candidate raw drift')
    data=json.loads(path.read_text(encoding='utf8'))
    dialect=next(x for x in data['dialects'] if x['dialect']=='010')
    item=next(x for x in dialect['literal_cases' if kind=='literals' else 'dex_cases'] if x['id']==name)
    require(item['result']['calculation_complete'] and len(item['result']['rows'])==1,'candidate incomplete')
    return item['result']['rows'][0][0],path


def validated_wrapper():
    verify=json.loads((WRAPPER/'verify-run/record.json').read_text(encoding='utf8'))
    require(verify['exit_code']==0 and sha(WRAPPER/'verify-run/stdout.txt')==verify['stdout']['sha256'],
            'historical wrapper verification failed or changed')
    result=json.loads((WRAPPER/'verify-run/stdout.txt').read_text(encoding='utf8'))
    require(result['status']=='passed-scoped' and not result['profiles_admitted'],'historical wrapper scope')
    record=json.loads((WRAPPER/'probe/record.json').read_text(encoding='utf8'))
    path=WRAPPER/'probe/stdout.txt'
    require(record['exit_code']==0 and sha(path)==record['stdout_sha256'],'wrapper raw drift')
    data=json.loads(path.read_text(encoding='utf8'))
    result={}
    for d in ('NativeV1','DexSql010'):
        row=next(x for x in data['records'] if x['dialect']==d and x['case']=='wrapped')['output']
        require(row['status']=='ok' and row['result']['calculation_complete'],'wrapper incomplete')
        result[d]=[''.join(chr(u) for u in r[0]['value']['utf16']) for r in row['result']['rows']]
    require(result['NativeV1']==['N','','616C706861','410042','F09F9880','4E','EDA080'],'native wrapper rows')
    require(result['DexSql010']==['N','','616C706861','41C08042','EDA0BDEDB880','4E','EDA080'],'legacy wrapper rows')
    return result,path


async def batch_tests(batch,paging):
    class FakeSession(batch.Session):
        def __init__(self, raw):
            super().__init__(None,'dexsql',Path('synthetic.dex'),time.monotonic()+30)
            self.dataset=raw['dataset_id']; self.saved=raw
        async def call(self,name,**arguments):
            require(name=='query','unexpected call')
            return copy.deepcopy(self.saved)
    outcomes={}
    selected={}
    for kind,name in [('literals','null'),('literals','empty'),('dex','string_0')]:
        raw,old,refpath=saved_case('A0',kind,name)
        candidate,cpath=candidate_case(kind,name)
        selected[name]={'old':old,'candidate':candidate,'reference_sha256':sha(refpath),'candidate_sha256':sha(cpath)}
        sql=raw['statements'][0]['sql']
        response=await FakeSession(raw).sql(sql,1)
        require(response['rows']==[[old['value']]],'saved old consumer values')
        paging.statement(response)
        altered=copy.deepcopy(raw); altered['statements'][0]['rows'][0][0]=copy.deepcopy(candidate)
        try:
            new=await FakeSession(altered).sql(sql,1)
            paging.statement(new)
            outcomes[name]={'status':'ok','rows':new['rows'],'typed_cell':new['typed_result']['statements'][0]['rows'][0][0],
                            'old_typed_cell':old,'full_cell_equal':candidate==old}
        except Exception as exc:
            outcomes[name]={'status':'error','error_type':type(exc).__name__,'error_text':str(exc)}
        if name=='null':
            require(candidate=={'type':'null'} and old=={'type':'null','value':None},'actual null cells differ')
            require(outcomes[name]['status']=='error' and outcomes[name]['error_type']=='KeyError','null mismatch not reproduced')
            normalized=copy.deepcopy(altered)
            normalized['statements'][0]['rows'][0][0]['value']=None
            patched=await FakeSession(normalized).sql(sql,1)
            paging.statement(patched)
            require(patched['rows']==[[None]] and patched['typed_result']['statements'][0]['rows'][0][0]==old,
                    'minimal null normalization differs')
            outcomes['null_only_normalization']={'status':'ok','rows':patched['rows'],'cell_equal_to_saved':True}
    require(selected['empty']['candidate']==selected['string_0']['candidate']=={'type':'i64','value':'0'},'candidate counterexample')
    require(selected['empty']['old']=={'type':'uint64','value':'0'}
            and selected['string_0']['old']=={'type':'int64','value':'0'},'old origin-dependent type counterexample')
    require(outcomes['empty']['status']==outcomes['string_0']['status']=='ok'
            and not outcomes['empty']['full_cell_equal'] and not outcomes['string_0']['full_cell_equal'],
            'type mismatch unexpectedly accepted as equivalent')
    return outcomes,selected


def cli_tests(native_cli,wrapper):
    class FakeCli(native_cli.CliSession):
        def __init__(self,cell):
            self.cell=cell;self.queries=0;self.sql=[]
        def table(self,sql,*,expected=None):
            self.sql.append(sql)
            names=['val']
            if expected is not None: require(expected==names,'unexpected columns')
            yield names,None
            if 'hostlab_shape' not in sql: yield names,[self.cell]
    cases={'null':'N','empty':'','ascii':'616C706861','native_nul':wrapper['NativeV1'][3],
           'native_pair':wrapper['NativeV1'][4], 'legacy_nul':wrapper['DexSql010'][3],
           'legacy_pair':wrapper['DexSql010'][4], 'legacy_unpaired':wrapper['DexSql010'][6]}
    results={}
    for name,cell in cases.items():
        cli=FakeCli(cell)
        try:
            rows=list(cli.rows('SELECT val FROM sample ORDER BY id'))
            results[name]={'status':'ok','rows':rows,'queries':cli.queries,'executed_sql':cli.sql}
        except Exception as exc:
            results[name]={'status':'error','error_type':type(exc).__name__,'error_text':str(exc),'queries':cli.queries,'executed_sql':cli.sql}
    require(results['null']['rows']==[{'val':None}] and results['empty']['rows']==[{'val':''}]
            and results['ascii']['rows']==[{'val':'alpha'}] and results['native_nul']['rows']==[{'val':'A\0B'}]
            and results['native_pair']['rows']==[{'val':'😀'}],'valid scalar decoding')
    for name in ('legacy_nul','legacy_pair','legacy_unpaired'):
        require(results[name]['status']=='error' and results[name]['error_type']=='RuntimeError'
                and results[name]['error_text']=='native audit returned a malformed hex cell',name+' unexpected')
    return results


def main():
    manifest=json.loads((FROZEN/'manifest.json').read_text(encoding='utf8'))
    require(manifest['commit']=='8782f43d537c442905123e35af325c412caa5188','commit changed')
    checked={}
    for name in ('analysis_batch.py','analysis_paging.py','analysis_plan.py','native_cli.py','install_dexsql.py'):
        path=FROZEN/name; rel=path.relative_to(ROOT).as_posix()
        entry=next(x for x in manifest['files'] if x['path']==rel)
        require(sha(path)==entry['sha256'],'frozen source drift: '+name)
        checked[name]=sha(path)
    # Frozen source first; missing helper modules resolve from the read-only fixed checkout.
    sys.path.insert(0,str(ROOT/'artifacts/local/hostlab-reference/tools/hostlab'))
    sys.path.insert(0,str(FROZEN))
    import analysis_batch,analysis_paging,native_cli
    require(Path(analysis_batch.__file__).resolve()==(FROZEN/'analysis_batch.py').resolve(),'wrong batch module')
    require(Path(analysis_paging.__file__).resolve()==(FROZEN/'analysis_paging.py').resolve(),'wrong paging module')
    require(Path(native_cli.__file__).resolve()==(FROZEN/'native_cli.py').resolve(),'wrong cli module')
    batch,selected=asyncio.run(batch_tests(analysis_batch,analysis_paging))
    wrapper,wrapper_path=validated_wrapper()
    cli=cli_tests(native_cli,wrapper)
    print(json.dumps({'schema_version':'mdd.hostlab-consumer-boundary.v1','status':'observed-scoped',
      'frozen_source_sha256':checked,'batch':batch,'selected_cells':selected,'cli':cli,
      'wrapper_raw_sha256':sha(wrapper_path),'old_engine_started':False,'network_used':False,
      'profiles_admitted':False,'scope':'actual frozen consumer methods with synthetic envelopes and saved real cells; no full HostLab or production adapter',
      'limitations':['one-cell NULL normalization is a local probe, not implemented production code',
                     'cell-only integer tag mapping cannot distinguish same i64 zero from differing old uint64/int64 origins',
                     'value extraction and paging acceptance do not establish typed DTO equivalence',
                     'legacy HEX failures are direct decoder behavior, not new complete A0 runs']} ,ensure_ascii=True))


if __name__=='__main__':
    main()
