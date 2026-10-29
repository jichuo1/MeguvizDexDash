#!/usr/bin/env python3
"""Independently compare duplicated ZIP members and scoped resource evidence."""
import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('resource_scope_helper',ROOT/'tests/fixtures/field_type_boundary/verify.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
common=helper.common
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/resource-scope-audit'/STAMP;helper.OUT=OUT
DEX=ROOT/'tests/fixtures/references/generated/classic-035.dex'
DEX_SHA='076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'


def generated():
    common.require(common.digest(DEX)==DEX_SHA,'DEX fixture changed')
    data=io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_STORED) as z:
            for name,payload in [('classes.dex',DEX.read_bytes()),('res/x.xml',b'<a/>'),('res/x.xml',b'<b/>'),('res/y.xml',b'<a/>')]:
                info=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED
                z.writestr(info,payload)
    return data.getvalue()


def oracle(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        items=z.infolist();common.require(len(items)==4,'unexpected physical ZIP members')
        return [{'ordinal':i,'name':item.filename,'data':list(z.read(item)),
                 'sha256':hashlib.sha256(z.read(item)).hexdigest(),'crc32':item.CRC,
                 'size':item.file_size} for i,item in enumerate(items) if item.filename.startswith('res/')]


def validate(value,expected):
    common.require(value['operation_status']=='ok' and value['profile_admitted'] is False
                   and value['mutation_after_capture'] is True,'native terminal differs')
    actual=value['resources'];common.require(len(actual)==6 and len(value['scope']['inputs'])==2,'occurrence count differs')
    common.require(value['scope']['covers_all_captured_sources'] is True,'scope identity differs')
    common.require(len({x['member']['member_id'] for x in actual})==6,'member identity deduplicated')
    for occurrence in range(2):
        block=actual[occurrence*3:occurrence*3+3]
        source=value['scope']['inputs'][occurrence]['source_occurrence_id']
        for got,want in zip(block,expected):
            member=got['member']
            common.require(member['source_occurrence_id']==source and int(member['input_ordinal'])==occurrence
                and int(member['archive_member_ordinal'])==want['ordinal'] and bytes(member['raw_name']).decode('utf8')==want['name']
                and got['bytes']==want['data'] and got['sha256']==want['sha256']
                and got['content_id']=='sha256:'+want['sha256'] and member['crc32']==want['crc32']
                and int(member['declared_size'])==want['size'],'member order, source, bytes or fingerprint differs')
    common.require(actual[0]['sha256']==actual[2]['sha256']==actual[3]['sha256']
                   and actual[1]['sha256']!=actual[0]['sha256'],'physical/content identities not distinguished')
    before=value['before'];after=value['after'];subset=value['subset']
    common.require(before['input']=='complete' and before['facts']=='unknown' and len(before['issues'])==5,
                   'missing physical resources promoted to complete')
    common.require(after['input']=='complete' and after['facts']=='complete' and after['covers_all_captured_sources'] is True,
                   'full resource scope incomplete')
    common.require(subset['input']=='complete' and subset['facts']=='complete' and subset['covers_all_captured_sources'] is False,
                   'subset promoted to full scope')
    common.require(value['foreign_error']['code']=='INVALID_ARGUMENT','foreign occurrence not rejected')


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    raw=generated();expected=oracle(raw)
    local=ROOT/'artifacts/local/resource-scope-boundary'/STAMP;local.mkdir(parents=True,exist_ok=False)
    apk=local/'mutating-copy.apk';apk.write_bytes(raw)
    paths=['tests/fixtures/resource_scope_boundary/probe.rs','tests/fixtures/resource_scope_boundary/verify.py',
           'tests/fixtures/field_type_boundary/verify.py','conformance/facts/verify_definition_projections.py',
           'Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        paths.append(f'crates/{package}/Cargo.toml');paths += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    identities={p:common.digest(ROOT/p) for p in paths};libs={}
    for line in helper.run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact':
            files=[x for x in item.get('filenames',[]) if x.endswith('.rlib')]
            if len(files)==1:libs[item['target']['name']]=files[0]
    binary=OUT/'resource_scope_probe.exe'
    argv=['rustc','--edition=2024','--crate-name','mdd_resource_scope_probe',paths[0],'-L','dependency=target/debug/deps','-o',binary]
    for name in ['mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing compiled crate '+name);argv+=['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    result=json.loads(helper.run('native',[binary,apk]));validate(result,expected)
    common.require(apk.read_bytes()==b'mutation-after-capture','mutation did not occur')
    common.require(all(common.digest(ROOT/p)==sha for p,sha in identities.items()),'source identity changed')
    report={'schema_version':'mdd.resource-scope-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-synthetic-resource-scope','task_complete_proven':False,'profile_admitted':False,
            'fixture_sha256':hashlib.sha256(raw).hexdigest(),'fixture_bytes':len(raw),'fixture_recipe':'deterministic stored ZIP; duplicate res/x.xml',
            'oracle':expected,'source_occurrences':2,'resource_occurrences':6,'binary_sha256':common.digest(binary),'sources':identities,
            'scope':'central physical order, source occurrence, captured bytes and required-member coverage; no compatibility profile'}
    (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'resource_occurrences':6,'task_complete_proven':False}))


if __name__=='__main__':main()
