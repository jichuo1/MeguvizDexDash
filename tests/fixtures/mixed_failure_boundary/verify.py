#!/usr/bin/env python3
"""Check a real damaged DEX cannot be hidden by a valid source in coverage."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import time

ROOT=Path(__file__).resolve().parents[3]
helper_path=ROOT/'tests/fixtures/field_type_boundary/verify.py'
spec=importlib.util.spec_from_file_location('mixed_failure_helper',helper_path)
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
common=helper.common
STAMP=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
OUT=ROOT/'artifacts/mdd-026/mixed-failure-audit'/STAMP
helper.OUT=OUT
VALID=('tests/fixtures/references/generated/classic-035.dex','076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8')
BAD=('tests/fixtures/references/generated/bad-reference-index.dex','a08ae1ba17e56fabfde47b331dae64bc5de7715ececd74f552e0c663e421919f')
SDK=Path(r'C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools\37.0.0\dexdump.exe')
SDK_SHA='f870af85191214f8f59d78e6a27748f00e724bbcce362115347014419969bcce'
COLS=['method','method_class','method_name','callee','callee_class','callee_name','file_id','class_idx','method_idx','callee_method_idx']


def observe(label,argv):
    folder=OUT/label;folder.mkdir(parents=True,exist_ok=False)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();timer=time.monotonic()
    try:
        proc=subprocess.run([str(x) for x in argv],cwd=ROOT,capture_output=True,timeout=90)
        stdout,stderr,exit_code,timed_out=proc.stdout,proc.stderr,proc.returncode,False
    except subprocess.TimeoutExpired as error:
        stdout,stderr,exit_code,timed_out=error.stdout or b'',error.stderr or b'',None,True
    (folder/'stdout.txt').write_bytes(stdout);(folder/'stderr.txt').write_bytes(stderr)
    record={'argv':[str(x) for x in argv],'started_utc':start,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'elapsed_seconds':time.monotonic()-timer,'exit_code':exit_code,'timed_out':timed_out,
            'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
            'scope':'observed invalid synthetic input; no equivalence inferred'}
    (folder/'record.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
    return record


def validate(value,valid_index,bad_index,expected_digest):
    common.require(value['probe_complete'] is True and value['operation_status']=='ok' and value['profile_admitted'] is False,
                   'probe did not complete')
    common.require(value['valid_index']==valid_index and value['bad_index']==bad_index,'source order changed')
    source=value['all_scope']['dexes'][bad_index]
    error=value['original_error'];terminal=value['all_terminal']
    common.require(error['code']=='INVALID_INPUT' and error['stage']=='dex.code_layout'
                   and error['details']['reason']=='INSTRUCTION_REFERENCE_OUT_OF_RANGE'
                   and error['details']['local_index']==65535 and error['details']['table_count']==4
                   and error['details']['byte_offset']=='460' and error['details']['content_id']=='sha256:'+expected_digest
                   and error['details']['dex_occurrence_id']==source['dex_occurrence_id'],'original error identity or location differs')
    common.require(terminal['code']==error['code'] and terminal['stage']==error['stage']
                   and terminal['message']==error['message'] and all(terminal['details'].get(k)==v for k,v in error['details'].items()),
                   'real failure was wrapped or lost')
    report=value['all_coverage'];subset=value['valid_subset_coverage']
    common.require(report['input']=='complete' and report['facts']!='complete' and report['covers_all_captured_sources'] is True
                   and len(report['selected_dex_occurrences'])==2,'failed all-source coverage hidden')
    common.require(any(issue['blocking'] and issue['occurrence']==source['dex_occurrence_id']
                       and issue['error']==error for issue in report['issues']), 'blocking bad-source issue missing or rewritten')
    common.require(subset['input']=='complete' and subset['facts']=='complete'
                   and subset['covers_all_captured_sources'] is False and len(subset['selected_dex_occurrences'])==1,
                   'valid subset incorrectly covers all sources')
    common.require(value['overwrite_error']['code']=='INVALID_ARGUMENT'
                   and value['overwrite_error']['details']['reason']=='FAILURE_ALREADY_RECORDED',
                   'failure could be overwritten')


def main():
    common.require(common.digest(common.A0)==common.A0_SHA and common.digest(SDK)==SDK_SHA,'reference binaries changed')
    good,bad=ROOT/VALID[0],ROOT/BAD[0]
    common.require(common.digest(good)==VALID[1] and common.digest(bad)==BAD[1],'fixture identity differs')
    raw=bad.read_bytes();Oracle=helper.oracle_type()
    common.require(struct.unpack_from('<H',raw,462)[0]==65535 and struct.unpack_from('<I',raw,88)[0]==4,
                   'byte-level index evidence differs')
    try: Oracle(raw).read()
    except ValueError as error: common.require(str(error)=='invalid_code_operand','independent error differs')
    else: raise RuntimeError('independent oracle accepted corrupt operand')
    sources=['tests/fixtures/mixed_failure_boundary/probe.rs','tests/fixtures/mixed_failure_boundary/verify.py',
             'tests/fixtures/field_type_boundary/verify.py','tests/fixtures/references/oracle.py',
             'conformance/facts/verify_definition_projections.py','Cargo.toml','Cargo.lock','rust-toolchain.toml']
    for package in ['mdd-dex','mdd-input','mdd-types','mdd-facts']:
        sources.append(f'crates/{package}/Cargo.toml')
        sources += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'crates'/package/'src').rglob('*.rs'))]
    ids={p:common.digest(ROOT/p) for p in sources};libs={}
    for line in helper.run('build',['cargo','build','-p','mdd-facts','--lib','--jobs','1','--locked','--offline','--message-format=json']).splitlines():
        x=json.loads(line)
        if x.get('reason')=='compiler-artifact':
            files=[f for f in x.get('filenames',[]) if f.endswith('.rlib')]
            if len(files)==1:libs[x['target']['name']]=files[0]
    exe=OUT/'mixed_failure_probe.exe';argv=['rustc','--edition=2024','--crate-name','mdd_mixed_failure_probe',sources[0],'-L','dependency=target/debug/deps','-o',exe]
    for name in ['mdd_dex','mdd_facts','mdd_input','mdd_types','serde_json']:
        common.require(name in libs,'missing compiled crate '+name);argv+=['--extern',name+'='+libs[name]]
    helper.run('compile',argv)
    observations=[]
    for label,paths,valid_index,bad_index in [('valid-first',[good,bad],0,1),('bad-first',[bad,good],1,0)]:
        value=json.loads(helper.run('native-'+label,[exe,*paths]));validate(value,valid_index,bad_index,BAD[1])
        oracle=Oracle(good.read_bytes()).read();expected=[dict(row,file_id=valid_index) for row in oracle['relations']['method_calls']]
        common.require(value['valid_method_calls']==expected,'valid source facts changed by invalid sibling')
        common.require(len(value['valid_reference_sites'])==len(oracle['sites'])==10,'valid site count differs')
        observations.append({'case':label,'valid_index':valid_index,'bad_index':bad_index,
                             'coverage_input':value['all_coverage']['input'],'coverage_facts':value['all_coverage']['facts'],
                             'original_error':value['original_error'],'valid_subset_complete':True,'valid_subset_covers_all':False})
    expr=[f'''CASE WHEN "{c}" IS NULL THEN 'N' ELSE hex(CAST("{c}" AS TEXT)) END AS "{c}"''' for c in COLS]
    sql='SELECT '+','.join(expr)+' FROM method_calls';args=['--threads','1','query']
    raw_good=helper.run('a0-good',[common.A0,*args,'--input',good,'--sql',sql])
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in x.items()} for x in common.table(raw_good,COLS)]
    expected=[{k:str(row[k]) for k in COLS} for row in Oracle(good.read_bytes()).read()['relations']['method_calls']]
    helper.compare(actual,expected)
    sdk=observe('sdk-bad',[SDK,'-d',bad])
    a0=[observe('a0-valid-first',[common.A0,*args,'--input',good,'--input',bad,'--sql',sql]),
        observe('a0-bad-first',[common.A0,*args,'--input',bad,'--input',good,'--sql',sql])]
    sdk['bad_operand_placeholder_observed'] = (b'<method?>' in (OUT/'sdk-bad/stdout.txt').read_bytes()) if not sdk['timed_out'] else None
    a0_observed=[]
    for index,record in enumerate(a0):
        case=['a0-valid-first','a0-bad-first'][index]
        observation={'exit_code':record['exit_code'],'timed_out':record['timed_out'],'rows_by_file':None}
        if record['exit_code']==0 and not record['timed_out']:
            rows=common.table((OUT/case/'stdout.txt').read_bytes(),COLS)
            by_file={}
            for row in rows:
                file_id=int(bytes.fromhex(row['file_id']).decode('ascii'))
                by_file[str(file_id)]=by_file.get(str(file_id),0)+1
            observation['rows_by_file']=by_file
        a0_observed.append(observation)
    common.require(all(common.digest(ROOT/p)==sha for p,sha in ids.items()) and common.digest(common.A0)==common.A0_SHA,
                   'source or reference binary changed')
    result={'schema_version':'mdd.mixed-failure-boundary.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'status':'passed-scoped-native-failure-coverage','task_complete_proven':False,'profile_admitted':False,
            'a0_sha256':common.A0_SHA,'sdk_sha256':SDK_SHA,'native_binary_sha256':common.digest(exe),'sources':ids,
            'fixtures':[{'path':VALID[0],'sha256':VALID[1]},{'path':BAD[0],'sha256':BAD[1]}],
            'independent_byte_oracle':{'instruction_byte_offset':460,'operand_byte_offset':462,'operand_method_index':65535,'method_table_count':4,'error':'invalid_code_operand'},
            'scenarios':observations,'sdk_bad_observation':{'exit_code':sdk['exit_code'],'timed_out':sdk['timed_out'],
                 'bad_operand_placeholder_observed':sdk['bad_operand_placeholder_observed']},
            'a0_bad_observations':a0_observed,
            'valid_a0_rows':len(actual),'scope':'two source orders, native coverage and independent bad DEX bytes; A0 bad outcomes observational only'}
    (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'path':OUT.relative_to(ROOT).as_posix(),'cases':2,'valid_a0_rows':len(actual),
                      'a0_bad_observations':result['a0_bad_observations'],'task_complete_proven':False}))


if __name__=='__main__': main()
