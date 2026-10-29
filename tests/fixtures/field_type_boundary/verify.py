#!/usr/bin/env python3
"""Cross-source field and type sites: raw DEX bytes, indexed facts and fixed A0."""
import collections
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'conformance/facts'))
import verify_definition_projections as common

STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT = ROOT/'artifacts/mdd-026/field-type-audit'/STAMP
FIXTURES = [
    ('tests/fixtures/references/generated/classic-035.dex','076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'),
    ('tests/fixtures/references/generated/poly-custom-038.dex','25bc5a03641d31d87212a9a292d798e64c563e2666d03f579e7fc894ac8ee425'),
    ('tests/fixtures/references/generated/classic-035.dex','076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'),
]
COLUMNS = {
    'method_field_accesses':['method','method_class','method_name','field','field_class','field_name','field_type','using_type','file_id','class_idx','method_idx','field_idx'],
    'method_used_types':['method','method_class','method_name','type_descriptor','type_name','file_id','class_idx','method_idx','type_idx'],
}


def run(label,argv):
    folder = OUT/label
    folder.mkdir(parents=True,exist_ok=False)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    elapsed = time.monotonic()
    try:
        proc = subprocess.run([str(x) for x in argv],cwd=ROOT,capture_output=True,timeout=90)
        stdout,stderr,code,timed_out = proc.stdout,proc.stderr,proc.returncode,False
    except subprocess.TimeoutExpired as error:
        stdout,stderr,code,timed_out = error.stdout or b'',error.stderr or b'',None,True
    (folder/'stdout.txt').write_bytes(stdout)
    (folder/'stderr.txt').write_bytes(stderr)
    record = {'argv':[str(x) for x in argv], 'started_utc':start,
              'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'elapsed_seconds':time.monotonic()-elapsed, 'exit_code':code, 'timed_out':timed_out,
              'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
              'scope':'synthetic static reference test; no performance claim'}
    (folder/'record.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
    common.require(code == 0 and not timed_out,label+' failed or timed out; raw output retained')
    return stdout


def oracle_type():
    path = ROOT/'tests/fixtures/references/oracle.py'
    spec = importlib.util.spec_from_file_location('field_type_oracle',path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod.Oracle


def bag(rows):
    return collections.Counter(json.dumps(x,sort_keys=True,ensure_ascii=True,separators=(',',':')) for x in rows)


def compare(actual,expected):
    common.require(bag(actual) == bag(expected),'A0 field/type rows or multiplicity differ')


def main():
    common.require(common.A0.is_file() and common.digest(common.A0) == common.A0_SHA,'A0 identity differs')
    paths = [ROOT/p for p,_ in FIXTURES]
    for (name,sha),path in zip(FIXTURES,paths):
        common.require(common.digest(path) == sha,'input identity differs: '+name)
    sources = ['tests/fixtures/field_type_boundary/probe.rs','tests/fixtures/field_type_boundary/verify.py',
               'tests/fixtures/references/oracle.py','conformance/facts/verify_definition_projections.py',
               'Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        sources.append(f'crates/{package}/Cargo.toml')
        sources += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities = {p:common.digest(ROOT/p) for p in sources}
    libs = {}
    for line in run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact':
            files = [x for x in item.get('filenames',[]) if x.endswith('.rlib')]
            if len(files) == 1: libs[item['target']['name']] = files[0]
    binary = OUT/'field_type_probe.exe'
    argv = ['rustc','--edition=2024','--crate-name','mdd_field_type_probe',sources[0],'-L','dependency=target/debug/deps','-o',binary]
    for name in ['mdd_dex','mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing compiled crate '+name)
        argv += ['--extern',name+'='+libs[name]]
    run('compile',argv)
    native = json.loads(run('native',[binary,*paths]))
    common.require(native['operation_status'] == 'ok' and native['probe_complete'] is True
                   and native['profile_admitted'] is False and len(native['occurrences']) == 3,'native terminal differs')
    for key in ['foreign_field','foreign_type']:
        common.require(native[key]['code'] == 'INVALID_ARGUMENT' and native[key]['stage'] == 'facts.references','foreign source error differs')
    occ = native['occurrences']
    common.require([x['selected']['file_id'] for x in occ] == [0,1,2]
                   and len({x['source']['dex_occurrence_id'] for x in occ}) == 3,'occurrence identity collapsed')
    common.require([x['field_index'] for x in occ] == [0,1,0]
                   and [x['type_index'] for x in occ] == [4,5,4],'shifted local target indices differ')
    common.require(occ[0]['source']['content_id'] == occ[2]['source']['content_id'] != occ[1]['source']['content_id']
                   and occ[0]['pool']['string_pool_id'] == occ[2]['pool']['string_pool_id'] != occ[1]['pool']['string_pool_id'],
                   'physical content/pool identity differs')
    Oracle = oracle_type()
    expected = {name:[] for name in COLUMNS}
    total_sites = {'field':0,'type':0}
    for file_id,(path,item) in enumerate(zip(paths,occ)):
        oracle = Oracle(path.read_bytes()).read()
        raw_sites = [{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                      'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                      'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                      'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in item['sites']]
        common.require(raw_sites == oracle['sites'],'raw instruction site/order differs')
        for kind,target,output in [('field',item['field_index'],'field_local'),('type',item['type_index'],'type_local')]:
            sites = [s for s in oracle['sites'] if s['kind'] == kind and s['index'] == target]
            local = [{'caller_method_definition':{'dex_occurrence_id':item['source']['dex_occurrence_id'],
                      'kind':'method_definition','local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                      'code_unit_pc':s['pc'],'operand_kind':kind,'operand_ordinal':s['operand_ordinal']} for s in sites]
            common.require(item[output]['sites'] == local,'source bound local lookup differs: '+kind)
            total_sites[kind] += len(sites)
        for name,field in [('method_field_accesses','field_rows'),('method_used_types','type_rows')]:
            expected_rows = [dict(row,file_id=file_id) for row in oracle['relations'][name]]
            common.require(item[field] == expected_rows,'native relation/source order differs: '+name)
            expected[name].extend(expected_rows)
    args = [arg for path in paths for arg in ['--input',path]]
    counts = {}
    for name,columns in COLUMNS.items():
        expr = [f'''CASE WHEN "{c}" IS NULL THEN 'N' ELSE hex(CAST("{c}" AS TEXT)) END AS "{c}"''' for c in columns]
        sql = 'SELECT '+','.join(expr)+' FROM '+name
        rows = common.table(run('a0-'+name,[common.A0,'--threads','1','query',*args,'--sql',sql]),columns)
        actual = [{k:None if v == 'N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
        wanted = [{k:str(row[k]) for k in columns} for row in expected[name]]
        compare(actual,wanted)
        counts[name] = len(actual)
        if name == 'method_field_accesses':
            common.require(collections.Counter(row['using_type'] for row in actual) == collections.Counter({'get':4,'put':3}),
                           'get/put multiplicity differs')
        for altered in [wanted[:-1], [dict(wanted[0],file_id='2'),*wanted[1:]], [dict(wanted[0],method_idx='999'),*wanted[1:]]]:
            try: compare(altered,wanted)
            except RuntimeError as error: common.require(str(error) == 'A0 field/type rows or multiplicity differ','unexpected negative error')
            else: raise RuntimeError('negative mutation accepted')
    common.require(total_sites == {'field':6,'type':6},'target site multiplicity differs')
    common.require(all(common.digest(ROOT/p) == sha for p,sha in identities.items()) and common.digest(common.A0) == common.A0_SHA,
                   'tested source or A0 changed')
    report = {'schema_version':'mdd.field-type-multi-source.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status':'passed-scoped-field-type-observation','source_occurrences':3,'formats':['035','038','035'],
              'field_local_indices':[0,1,0],'type_local_indices':[4,5,4],'target_site_counts':total_sites,
              'a0_row_counts':counts,'foreign_errors':['INVALID_ARGUMENT','INVALID_ARGUMENT'],'negative_controls_rejected':6,
              'a0_sha256':common.A0_SHA,'native_binary_sha256':common.digest(binary),'sources':identities,
              'fixture_sha256':[sha for _,sha in FIXTURES],'task_complete_proven':False,'profile_admitted':False,
              'scope':'synthetic raw DEX reference sites; A0 rows compared as multisets; no runtime dispatch or full profile'}
    (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'field_sites':total_sites['field'],
                      'type_sites':total_sites['type'],'a0_rows':counts,'task_complete_proven':False}))


if __name__ == '__main__':
    main()
