#!/usr/bin/env python3
"""Compare immutable raw method facts across actual DEX file replacement."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('raw_generation_helper',ROOT/'tests/fixtures/field_type_boundary/verify.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
common=helper.common
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/raw-generation-audit'/STAMP;helper.OUT=OUT
DEX=ROOT/'tests/fixtures/references/generated/classic-035.dex'
DEX_SHA='076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'
COLS=['method_idx','code_off','insns_size','insns_off']


def generated():
    a=DEX.read_bytes();common.require(hashlib.sha256(a).hexdigest()==DEX_SHA,'DEX fixture changed')
    raw=bytearray(a);common.require(struct.unpack_from('<H',raw,438)[0]==10,'original operand changed')
    struct.pack_into('<H',raw,438,9)
    raw[12:32]=hashlib.sha1(raw[32:]).digest();struct.pack_into('<I',raw,8,zlib.adler32(raw[12:])&0xffffffff)
    return a,bytes(raw)


def oracle(data):
    common.require(data[:8]==b'dex\n035\0' and hashlib.sha1(data[32:]).digest()==data[12:32]
                   and zlib.adler32(data[12:])&0xffffffff==struct.unpack_from('<I',data,8)[0],'DEX signature/checksum differs')
    Reader=helper.oracle_type();reader=Reader(data);refs=reader.read();rows=[]
    for method,_,flags,offset,_ in reader.definitions:
        if offset:
            count=struct.unpack_from('<I',data,offset+12)[0];start=offset+16;body=data[start:start+count*2]
            common.require(len(body)==count*2,'body range exceeds source')
            rows.append({'method_idx':method,'code_off':offset,'insns_size':count,'insns_off':start,
                         'raw':list(body),'sha256':hashlib.sha256(body).hexdigest()})
        else:common.require(flags & 0x100,'unexpected no-body method')
    common.require([x['method_idx'] for x in rows]==[0,2] and len(refs['sites'])==10,'fixture layout differs')
    return {'methods':rows,'operand_at_438':next(x['index'] for x in refs['sites'] if x['byte_offset']==438)}


def validate(native,a,b,raw_a,raw_b):
    common.require(native['operation_status']=='ok' and native['profile_admitted'] is False
                   and native['disk_rewritten_between_captures'] is True,'terminal differs')
    snaps=[native['a_snapshot'],native['b_snapshot']];facts=[native['a_raw'],native['b_raw']]
    common.require(snaps[0]['snapshot_id']!=snaps[1]['snapshot_id']
        and snaps[0]['sources'][0]['occurrence_id']!=snaps[1]['sources'][0]['occurrence_id'],'generation identity collapsed')
    for snapshot,fact,ref,raw in zip(snaps,facts,[a,b],[raw_a,raw_b]):
        source=fact['source'];common.require(source['snapshot_id']==snapshot['snapshot_id']
            and source['source_occurrence_id']==snapshot['sources'][0]['occurrence_id']
            and source['content_id']=='sha256:'+hashlib.sha256(raw).hexdigest(),'source identity differs')
        methods={x['method']['local_index']:x for x in fact['methods']}
        common.require(set(methods)=={0,1,2} and methods[1]['body_kind']=='native_no_body'
                       and methods[1]['insns_range'] is None and methods[1]['sha256'] is None,'no-body semantics differ')
        for row in ref['methods']:
            value=methods[row['method_idx']]
            common.require(value['method']['snapshot_id']==snapshot['snapshot_id']
                and value['method']['dex_occurrence_id']==source['dex_occurrence_id']
                and int(value['code_item_byte_offset'])==row['code_off']
                and int(value['insns_range']['byte_offset'])==row['insns_off']
                and int(value['insns_range']['byte_length'])==row['insns_size']*2
                and value['sha256']==row['sha256'],'raw method identity/range/hash differs')
    common.require(native['old_caller_bytes']==a['methods'][0]['raw'] and native['new_caller_bytes']==b['methods'][0]['raw']
                   and native['old_native_is_none'] and native['new_native_is_none'],'captured bytes/no-body differ')
    common.require(native['old_recipe_sha256']==hashlib.sha256(b'caller\0'+bytes(a['methods'][0]['raw'])+b'native\0').hexdigest()
                   and native['new_recipe_sha256']==hashlib.sha256(b'caller\0'+bytes(b['methods'][0]['raw'])+b'native\0').hexdigest()
                   and native['old_recipe_sha256']!=native['new_recipe_sha256'],'ordered recipe differs')
    for key in ('foreign_a','foreign_b','mixed_a','mixed_b'):
        common.require(native[key]['code']=='INVALID_ARGUMENT','foreign identity accepted or error changed: '+key)


def a0_rows(raw):
    rows=common.table(raw,COLS)
    return [{key:int(bytes.fromhex(row[key]).decode('ascii')) for key in COLS} for row in rows]


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    raw_a,raw_b=generated();a,b=oracle(raw_a),oracle(raw_b)
    common.require(a['operand_at_438']==10 and b['operand_at_438']==9,'operand generation differs')
    common.require(common.digest(common.A0)==common.A0_SHA,'fixed A0 identity differs')
    local=ROOT/'artifacts/local/raw-generation-boundary'/STAMP;local.mkdir(parents=True,exist_ok=False)
    mutable=local/'mutable.dex';old=local/'old.dex';new=local/'new.dex'
    mutable.write_bytes(raw_a);old.write_bytes(raw_a);new.write_bytes(raw_b)
    paths=['tests/fixtures/raw_generation_boundary/probe.rs','tests/fixtures/raw_generation_boundary/verify.py',
           'tests/fixtures/references/oracle.py','tests/fixtures/field_type_boundary/verify.py',
           'conformance/facts/verify_definition_projections.py','Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        paths.append(f'crates/{package}/Cargo.toml');paths += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities={p:common.digest(ROOT/p) for p in paths};libs={}
    for line in helper.run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact':
            files=[x for x in item.get('filenames',[]) if x.endswith('.rlib')]
            if len(files)==1:libs[item['target']['name']]=files[0]
    binary=OUT/'raw_generation_probe.exe'
    argv=['rustc','--edition=2024','--crate-name','mdd_raw_generation_probe',paths[0],'-L','dependency=target/debug/deps','-o',binary]
    for name in ['mdd_dex','mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing compiled crate '+name);argv+=['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    native=json.loads(helper.run('native',[binary,mutable,new]));validate(native,a,b,raw_a,raw_b)
    common.require(mutable.read_bytes()==raw_b and old.read_bytes()==raw_a and new.read_bytes()==raw_b,'disk generation differs')
    sql='SELECT '+','.join(f'hex(CAST("{c}" AS TEXT)) AS "{c}"' for c in COLS)+' FROM code_items ORDER BY method_idx'
    for label,path,ref in [('a0-old',old,a),('a0-new',new,b)]:
        rows=a0_rows(helper.run(label,[common.A0,'--threads','1','query','--input',path,'--sql',sql]))
        wanted=[{k:x[k] for k in COLS} for x in ref['methods']]
        common.require(rows==wanted,'A0 code range/units differ: '+label)
    common.require(all(common.digest(ROOT/p)==sha for p,sha in identities.items()) and common.digest(common.A0)==common.A0_SHA,
                   'source or fixed reference changed')
    result={'schema_version':'mdd.raw-generation-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-synthetic-two-generation-raw-code','task_complete_proven':False,'profile_admitted':False,
            'generation_a_sha256':hashlib.sha256(raw_a).hexdigest(),'generation_b_sha256':hashlib.sha256(raw_b).hexdigest(),
            'oracle_a':a,'oracle_b':b,'a0_sha256':common.A0_SHA,'binary_sha256':common.digest(binary),'sources':identities,
            'scope':'two captures around actual DEX file replacement; raw methods/recipes and A0 code ranges only'}
    (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'generations':2,'a0_rows_each':2,'task_complete_proven':False}))


if __name__=='__main__':main()
