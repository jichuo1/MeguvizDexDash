#!/usr/bin/env python3
"""Independent bytes and A0 comparison for source-bound dynamic references."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
helper_path = ROOT/'tests/fixtures/field_type_boundary/verify.py'
spec = importlib.util.spec_from_file_location('dynamic_helper',helper_path)
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
common = helper.common
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT = ROOT/'artifacts/mdd-026/dynamic-source-audit'/STAMP
helper.OUT = OUT
FIXTURES = [
    ('tests/fixtures/references/generated/poly-custom-038.dex','25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425'),
    ('tests/fixtures/references/generated/handles-039.dex','1ef9feee89649371933005100ef2cc2878a581f9459233dcc1810881a9824c27'),
    ('tests/fixtures/references/generated/orphan-code-035.dex','be046c1bc2b7392257e174b5bac47c6cc9a141e8f4c9a9e839a1d7c5c01ba92f'),
    ('tests/fixtures/references/generated/poly-custom-038.dex','25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425'),
]
COLS = ['method','method_class','method_name','callee','callee_class','callee_name','file_id','class_idx','method_idx','callee_method_idx']


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA,'A0 identity differs')
    paths = [ROOT/path for path,_ in FIXTURES]
    for path,(_,sha) in zip(paths,FIXTURES):
        common.require(common.digest(path) == sha,'fixture identity differs')
    sources = ['tests/fixtures/dynamic_source_boundary/probe.rs','tests/fixtures/dynamic_source_boundary/verify.py',
               'tests/fixtures/field_type_boundary/verify.py','tests/fixtures/references/oracle.py',
               'conformance/facts/verify_definition_projections.py','Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        sources.append(f'crates/{package}/Cargo.toml')
        sources += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities = {path:common.digest(ROOT/path) for path in sources}
    libs = {}
    for line in helper.run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        item=json.loads(line)
        if item.get('reason') == 'compiler-artifact':
            files=[x for x in item.get('filenames',[]) if x.endswith('.rlib')]
            if len(files) == 1: libs[item['target']['name']]=files[0]
    exe=OUT/'dynamic_source_probe.exe'
    argv=['rustc','--edition=2024','--crate-name','mdd_dynamic_source_probe',sources[0],'-L','dependency=target/debug/deps','-o',exe]
    for name in ['mdd_dex','mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing cargo library '+name)
        argv += ['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    native=json.loads(helper.run('native',[exe,*paths]))
    common.require(native['operation_status'] == 'ok' and native['probe_complete'] and not native['profile_admitted']
                   and len(native['occurrences']) == 4,'native terminal incomplete')
    occ=native['occurrences']
    common.require([o['selected']['file_id'] for o in occ] == [0,1,2,3]
                   and len({o['source']['dex_occurrence_id'] for o in occ}) == 4,'occurrence identity collapsed')
    common.require(occ[0]['source']['content_id'] == occ[3]['source']['content_id']
                   and occ[0]['pool']['string_pool_id'] == occ[3]['pool']['string_pool_id'],
                   'repeated physical identity differs')
    common.require(native['foreign_call_site']['code'] == 'INVALID_ARGUMENT'
                   and all(e['code'] == 'QUOTA_EXCEEDED' for e in native['quota_errors']),
                   'foreign lookup or budget error changed')
    Oracle=helper.oracle_type()
    expected=[]; site_counts=[]
    for file_id,(path,item) in enumerate(zip(paths,occ)):
        oracle=Oracle(path.read_bytes()).read()
        sites=[{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in item['sites']]
        common.require(sites == oracle['sites'],'native exact reference sites differ from raw bytes')
        rows=[dict(row,file_id=file_id) for row in oracle['relations']['method_calls']]
        common.require(item['method_call_rows'] == rows,'native method rows differ from bytes')
        common.require(item['coverage']['unowned_physical_code_items'] == len(oracle['unowned_code_offsets']),
                       'unowned code coverage differs')
        expected.extend(rows); site_counts.append(len(sites))
        dynamic=item['dynamic_calls']
        common.require(len(dynamic) == len(oracle['dynamic_calls']),'dynamic call count differs')
        for actual,ref in zip(dynamic,oracle['dynamic_calls']):
            site=item['sites'][actual['site_ordinal']]
            common.require(site['caller_method_idx'] == ref['caller_method_idx'] and site['code_unit_pc'] == ref['pc']
                           and actual['call_site_idx'] == ref['call_site_idx']
                           and 'unknown_dynamic_target' in actual['runtime_target_status'],
                           'dynamic site identity or unknown target differs')
        common.require(all(row['callee_name'] != 'bootstrap' for row in item['method_call_rows']),
                       'bootstrap falsely became runtime callee')
    common.require(site_counts == [17,13,10,17] and [len(o['dynamic_calls']) for o in occ] == [2,0,0,2]
                   and [o['coverage']['unowned_physical_code_items'] for o in occ] == [0,0,1,0],
                   'handwritten site/dynamic/orphan expectations differ')
    handles=occ[1]['sites']
    common.require([s['code_unit_pc'] for s in handles if s['target_kind'] == 'method_handle'] == [24,26]
                   and len(occ[1]['method_call_rows']) == 4 and len(occ[1]['method_field_rows']) == 2,
                   'handle constant produced false calls or field accesses')
    expressions=[f'''CASE WHEN "{c}" IS NULL THEN 'N' ELSE hex(CAST("{c}" AS TEXT)) END AS "{c}"''' for c in COLS]
    sql='SELECT '+','.join(expressions)+' FROM method_calls'
    args=[arg for path in paths for arg in ['--input',path]]
    parsed=common.table(helper.run('a0-method-calls',[common.A0,'--threads','1','query',*args,'--sql',sql]),COLS)
    actual=[{k:None if v == 'N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in parsed]
    wanted=[{k:str(row[k]) for k in COLS} for row in expected]
    helper.compare(actual,wanted)
    controls=[]
    for label,changed in [('missing_occurrence',wanted[:-6]),('wrong_file',[dict(wanted[0],file_id='3'),*wanted[1:]]),
                          ('bootstrap_as_callee',[dict(wanted[0],callee_name='bootstrap'),*wanted[1:]])]:
        try: helper.compare(changed,wanted)
        except RuntimeError as error:
            common.require(str(error) == 'A0 field/type rows or multiplicity differ','unexpected negative terminal')
            controls.append(label)
        else: raise RuntimeError('negative accepted: '+label)
    common.require(all(common.digest(ROOT/path) == sha for path,sha in identities.items())
                   and common.digest(common.A0) == common.A0_SHA,'tested source or binary changed')
    report={'schema_version':'mdd.dynamic-source-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-scoped-dynamic-source-observation','task_complete_proven':False,'profile_admitted':False,
            'a0_sha256':common.A0_SHA,'native_binary_sha256':common.digest(exe),'sources':identities,
            'fixture_sha256':[sha for _,sha in FIXTURES],'source_occurrences':4,'site_counts':site_counts,
            'dynamic_counts':[2,0,0,2],'unowned_counts':[0,0,1,0],'a0_method_call_rows':len(actual),
            'negative_controls_rejected':controls,'quota_errors':4,'foreign_occurrence_error':'INVALID_ARGUMENT',
            'scope':'four synthetic occurrences; unknown runtime dynamic targets retained; not full profile or ART/device proof'}
    (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'sites':sum(site_counts),'dynamic_calls':4,
                      'unowned_code_items':1,'a0_rows':len(actual),'task_complete_proven':False}))


if __name__ == '__main__':
    main()
