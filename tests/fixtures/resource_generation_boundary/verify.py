#!/usr/bin/env python3
"""Compare resource facts across two actual filesystem generations."""
import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('resource_generation_helper',ROOT/'tests/fixtures/field_type_boundary/verify.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
common=helper.common
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/resource-generation-audit'/STAMP;helper.OUT=OUT
DEX=ROOT/'tests/fixtures/references/generated/classic-035.dex'
DEX_SHA='076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8'


def generated(changed):
    common.require(common.digest(DEX)==DEX_SHA,'DEX fixture changed')
    data=io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_STORED) as z:
            entries=[('classes.dex',DEX.read_bytes()),('res/x.xml',b'<a/>'),
                     ('res/x.xml',b'<new-generation/>' if changed else b'<b/>'),('res/y.xml',b'<a/>')]
            for name,payload in entries:
                info=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED
                z.writestr(info,payload)
    return data.getvalue()


def oracle(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries=z.infolist();common.require(len(entries)==4,'ZIP member count differs')
        return [{'ordinal':i,'name':entry.filename,'data':list(z.read(entry)),
                 'sha256':hashlib.sha256(z.read(entry)).hexdigest(),'crc32':entry.CRC,
                 'size':entry.file_size} for i,entry in enumerate(entries) if entry.filename.startswith('res/')]


def validate(value,a,b,raw_a,raw_b):
    common.require(value['operation_status']=='ok' and value['profile_admitted'] is False
                   and value['disk_rewritten_between_captures'] is True,'native terminal differs')
    scopes=[value['a_scope'],value['b_scope']];blocks=[value['a_resources'],value['b_resources']]
    expected=[a,b];raws=[raw_a,raw_b]
    common.require(scopes[0]['snapshot_id']!=scopes[1]['snapshot_id']
                   and scopes[0]['inputs'][0]['source_occurrence_id']!=scopes[1]['inputs'][0]['source_occurrence_id'],
                   'snapshot/source generation collapsed')
    ids=[]
    for scope,block,wants,raw in zip(scopes,blocks,expected,raws):
        common.require(scope['inputs'][0]['content_id']=='sha256:'+hashlib.sha256(raw).hexdigest()
                       and len(block)==3 and scope['covers_all_captured_sources'] is True,'captured input differs')
        for got,want in zip(block,wants):
            member=got['member'];ids.append(member['member_id'])
            common.require(got['snapshot_id']==scope['snapshot_id']
                and member['source_occurrence_id']==scope['inputs'][0]['source_occurrence_id']
                and int(member['archive_member_ordinal'])==want['ordinal']
                and bytes(member['raw_name']).decode('utf8')==want['name']
                and got['bytes']==want['data'] and got['sha256']==want['sha256']
                and got['content_id']=='sha256:'+want['sha256'] and member['crc32']==want['crc32']
                and int(member['declared_size'])==want['size'],'generation/member/raw fingerprint differs')
    common.require(len(set(ids))==6 and blocks[0][0]['sha256']==blocks[1][0]['sha256']
                   and blocks[0][1]['sha256']!=blocks[1][1]['sha256']
                   and blocks[0][2]['sha256']==blocks[1][2]['sha256'],'physical/content generation identities differ')
    for prefix in ('a','b'):
        before=value[prefix+'_before'];rejected=value[prefix+'_rejected'];after=value[prefix+'_after']
        common.require(before['facts']=='unknown' and rejected['facts']=='unknown'
                       and before['input']=='complete' and rejected['input']=='complete'
                       and len(before['issues'])==len(rejected['issues'])==1
                       and before['issues'][0]['column']==rejected['issues'][0]['column'],
                       'foreign generation filled missing required member')
        common.require(after['facts']=='complete' and after['input']=='complete'
                       and after['snapshot_id']==value[prefix+'_scope']['snapshot_id'],'own generation incomplete')
        common.require(value['foreign_'+prefix]['code']=='INVALID_ARGUMENT','foreign generation error differs')


def main():
    OUT.mkdir(parents=True,exist_ok=False)
    raw_a,raw_b=generated(False),generated(True);a,b=oracle(raw_a),oracle(raw_b)
    local=ROOT/'artifacts/local/resource-generation-boundary'/STAMP;local.mkdir(parents=True,exist_ok=False)
    apk=local/'mutable.apk';replacement=local/'replacement.zip';apk.write_bytes(raw_a);replacement.write_bytes(raw_b)
    paths=['tests/fixtures/resource_generation_boundary/probe.rs','tests/fixtures/resource_generation_boundary/verify.py',
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
    binary=OUT/'resource_generation_probe.exe'
    argv=['rustc','--edition=2024','--crate-name','mdd_resource_generation_probe',paths[0],'-L','dependency=target/debug/deps','-o',binary]
    for name in ['mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing compiled crate '+name);argv+=['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    native=json.loads(helper.run('native',[binary,apk,replacement]));validate(native,a,b,raw_a,raw_b)
    common.require(apk.read_bytes()==raw_b and replacement.read_bytes()==raw_b,'actual disk rewrite differs')
    common.require(all(common.digest(ROOT/p)==sha for p,sha in identities.items()),'source identity changed')
    result={'schema_version':'mdd.resource-generation-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-synthetic-two-generation-resource-scope','task_complete_proven':False,'profile_admitted':False,
            'generation_a_sha256':hashlib.sha256(raw_a).hexdigest(),'generation_b_sha256':hashlib.sha256(raw_b).hexdigest(),
            'oracle_a':a,'oracle_b':b,'resource_occurrences':6,'binary_sha256':common.digest(binary),'sources':identities,
            'scope':'one rewritten synthetic APK, two snapshots and six physical resources; foreign-generation evidence rejected'}
    (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'generations':2,'resource_occurrences':6,'task_complete_proven':False}))


if __name__=='__main__':main()
