#!/usr/bin/env python3
"""Observe nonempty partial reference facts across duplicate source occurrences."""
import datetime
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('partial_reference_helper',ROOT/'tests/fixtures/field_type_boundary/verify.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
common=helper.common
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/partial-reference-audit'/STAMP;helper.OUT=OUT
FIXTURE='tests/fixtures/references/generated/classic-035.dex'
FIXTURE_SHA='076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'
COLS=['method','method_class','method_name','callee','callee_class','callee_name','file_id','class_idx','method_idx','callee_method_idx']


def validate(value,partial):
    common.require(value['operation_status']=='ok' and value['probe_complete'] is True and value['profile_admitted'] is False
                   and value['partial_index']==partial and value['full_index']==1-partial,'probe/source terminal differs')
    scope=value['scope'];source=value['partial_source']
    common.require(len(scope['dexes'])==2 and scope['covers_all_captured_sources'] is True
                   and scope['dexes'][partial]['dex_occurrence_id']==source['dex_occurrence_id']
                   and scope['dexes'][0]['dex_occurrence_id']!=scope['dexes'][1]['dex_occurrence_id']
                   and scope['dexes'][0]['content_id']==scope['dexes'][1]['content_id']=='sha256:'+FIXTURE_SHA,
                   'occurrence identity differs')
    partial_coverage=value['partial_coverage'];matches=value['partial_local_matches']
    common.require(partial_coverage['facts']=='partial' and partial_coverage['missing_method_indices']==[2]
                   and len(value['partial_sites'])==10 and matches['coverage']=='partial'
                   and len(matches['sites'])==2 and matches['absence_proven_within_encoded_operand_scope'] is False,
                   'nonempty partial evidence was hidden or promoted')
    common.require(all(x['caller_method_definition']['dex_occurrence_id']==source['dex_occurrence_id'] for x in matches['sites']),
                   'partial local source binding differs')
    for name in ['partial_rows_error','all_terminal','indexed_error','scalar_error']:
        common.require(value[name]['code']=='INCOMPLETE_FACTS','strict result became success or wrong error: '+name)
    report=value['all_coverage'];subset=value['complete_subset']
    common.require(report['input']=='complete' and report['facts']=='partial' and report['covers_all_captured_sources'] is True
                   and len(report['selected_dex_occurrences'])==2,'all-source coverage differs')
    common.require(any(x['blocking'] and x['occurrence']==source['dex_occurrence_id'] for x in report['issues']),
                   'partial source issue missing')
    common.require(subset['input']=='complete' and subset['facts']=='complete' and subset['covers_all_captured_sources'] is False
                   and len(subset['selected_dex_occurrences'])==1,'subset was promoted to full snapshot')


def main():
    path=ROOT/FIXTURE;common.require(common.digest(path)==FIXTURE_SHA and common.digest(common.A0)==common.A0_SHA,'fixture/reference identity differs')
    sources=['tests/fixtures/partial_reference_boundary/probe.rs','tests/fixtures/partial_reference_boundary/verify.py',
             'tests/fixtures/field_type_boundary/verify.py','tests/fixtures/references/oracle.py',
             'conformance/facts/verify_definition_projections.py','Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        sources.append(f'crates/{package}/Cargo.toml');sources += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities={p:common.digest(ROOT/p) for p in sources}
    Oracle=helper.oracle_type();oracle=Oracle(path.read_bytes());ref=oracle.read()
    caller=next(x for x in oracle.definitions if x[0]==0);target=next(x for x in oracle.definitions if x[0]==2)
    common.require(caller[3]==420 and target[3]==488 and len(ref['sites'])==10,'byte-level method offsets differ')
    libs={}
    for line in helper.run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact':
            files=[x for x in item.get('filenames',[]) if x.endswith('.rlib')]
            if len(files)==1:libs[item['target']['name']]=files[0]
    exe=OUT/'partial_reference_probe.exe';argv=['rustc','--edition=2024','--crate-name','mdd_partial_reference_probe',sources[0],'-L','dependency=target/debug/deps','-o',exe]
    for name in ['mdd_dex','mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing cargo library '+name);argv+=['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    cases=[]
    for partial in [0,1]:
        value=json.loads(helper.run('native-partial-'+str(partial),[exe,path,path,str(partial)]));validate(value,partial)
        sites=[{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in value['partial_sites']]
        common.require(sites==ref['sites'],'nonempty partial sites differ from independent bytes')
        common.require(value['full_method_rows']==[dict(row,file_id=1-partial) for row in ref['relations']['method_calls']],
                       'full sibling method rows differ')
        cases.append({'partial_index':partial,'nonempty_partial_sites':len(sites),
                      'partial_local_matches':len(value['partial_local_matches']['sites']),
                      'missing_method_indices':value['partial_coverage']['missing_method_indices'],
                      'all_input':value['all_coverage']['input'],'all_facts':value['all_coverage']['facts'],
                      'strict_query_error':value['indexed_error']['code'],'subset_covers_all':value['complete_subset']['covers_all_captured_sources']})
    expr=[f'''CASE WHEN "{c}" IS NULL THEN 'N' ELSE hex(CAST("{c}" AS TEXT)) END AS "{c}"''' for c in COLS]
    sql='SELECT '+','.join(expr)+' FROM method_calls'
    parsed=common.table(helper.run('a0-full-two-sources',[common.A0,'--threads','1','query','--input',path,'--input',path,'--sql',sql]),COLS)
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in parsed]
    wanted=[{k:str(dict(row,file_id=n)[k]) for k in COLS} for n in [0,1] for row in ref['relations']['method_calls']]
    helper.compare(actual,wanted)
    common.require(len(actual)==8,'A0 complete duplicate rows differ')
    common.require(all(common.digest(ROOT/p)==sha for p,sha in identities.items()) and common.digest(path)==FIXTURE_SHA
                   and common.digest(common.A0)==common.A0_SHA,'tested identity changed')
    result={'schema_version':'mdd.partial-reference-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-nonempty-partial-reference-scope','task_complete_proven':False,'profile_admitted':False,
            'fixture_sha256':FIXTURE_SHA,'a0_sha256':common.A0_SHA,'native_binary_sha256':common.digest(exe),'sources':identities,
            'independent_oracle':{'caller_code_offset':420,'missing_target_code_offset':488,'sites':10},
            'cases':cases,'a0_complete_duplicate_rows':8,
            'scope':'two duplicate synthetic DEX occurrences; one requested code subset is partial despite nonempty matches'}
    (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'cases':2,'partial_sites_each':10,
                      'a0_full_rows':8,'task_complete_proven':False}))


if __name__=='__main__':main()
