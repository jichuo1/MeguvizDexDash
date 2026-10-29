#!/usr/bin/env python3
"""Append-only recheck of actual mixed-source invalid-input evidence."""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys
import verify


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    verify.common.require(len(sys.argv)==2,'expected one evidence path')
    base=(verify.ROOT/'artifacts/mdd-026/mixed-failure-audit').resolve();folder=(verify.ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder!=base,'path outside mixed failure evidence')
    result_path=folder/'result.json';result=json.loads(result_path.read_bytes())
    verify.common.require(result['status']=='passed-scoped-native-failure-coverage'
                          and result['task_complete_proven'] is False and result['profile_admitted'] is False,'scope overclaimed')
    for path,expected in result['sources'].items():
        verify.common.require(sha(verify.ROOT/path)==expected,'source changed: '+path)
    verify.common.require(sha(verify.common.A0)==result['a0_sha256']==verify.common.A0_SHA
                          and sha(verify.SDK)==result['sdk_sha256']==verify.SDK_SHA
                          and sha(folder/'mixed_failure_probe.exe')==result['native_binary_sha256'],'binary identity changed')
    labels=['build','compile','native-valid-first','native-bad-first','a0-good','sdk-bad','a0-valid-first','a0-bad-first']
    records={}
    for label in labels:
        path=folder/label;record=json.loads((path/'record.json').read_bytes());records[label]=record
        for stream in ['stdout','stderr']:
            verify.common.require(sha(path/(stream+'.txt'))==record[stream+'_sha256'],'raw stream changed: '+label)
        if label in ['build','compile','native-valid-first','native-bad-first','a0-good']:
            verify.common.require(record['exit_code']==0 and record['timed_out'] is False,'required process failed: '+label)
    for name,fixture in [('good',verify.VALID),('bad',verify.BAD)]:
        verify.common.require(sha(verify.ROOT/fixture[0])==fixture[1],'fixture identity differs: '+name)
    raw=(verify.ROOT/verify.BAD[0]).read_bytes()
    verify.common.require(struct.unpack_from('<H',raw,462)[0]==65535 and struct.unpack_from('<I',raw,88)[0]==4,
                          'bad operand byte evidence differs')
    Oracle=verify.helper.oracle_type()
    try: Oracle(raw).read()
    except ValueError as error: verify.common.require(str(error)=='invalid_code_operand','byte oracle terminal differs')
    else: raise RuntimeError('bad operand accepted by byte oracle')
    valid=Oracle((verify.ROOT/verify.VALID[0]).read_bytes()).read()
    for label,good,bad in [('valid-first',0,1),('bad-first',1,0)]:
        value=json.loads((folder/('native-'+label)/'stdout.txt').read_bytes())
        verify.validate(value,good,bad,verify.BAD[1])
        verify.common.require(value['valid_method_calls']==[dict(row,file_id=good) for row in valid['relations']['method_calls']]
                              and len(value['valid_reference_sites'])==len(valid['sites'])==10,'valid sibling facts differ')
    sdk=records['sdk-bad'];sdk_observation=result['sdk_bad_observation']
    verify.common.require(sdk['exit_code']==sdk_observation['exit_code'] and sdk['timed_out']==sdk_observation['timed_out']
                          and (b'<method?>' in (folder/'sdk-bad/stdout.txt').read_bytes())==sdk_observation['bad_operand_placeholder_observed'],
                          'SDK observation differs')
    for i,label in enumerate(['a0-valid-first','a0-bad-first']):
        record=records[label];observation=result['a0_bad_observations'][i]
        verify.common.require(record['exit_code']==observation['exit_code'] and record['timed_out']==observation['timed_out'],
                              'A0 actual terminal differs')
        if record['exit_code']==0 and not record['timed_out']:
            rows=verify.common.table((folder/label/'stdout.txt').read_bytes(),verify.COLS);counts={}
            for row in rows:
                file_id=str(int(bytes.fromhex(row['file_id']).decode('ascii')));counts[file_id]=counts.get(file_id,0)+1
            verify.common.require(counts==observation['rows_by_file'],'A0 observed source row counts differ')
    old=verify.ROOT/'artifacts/mdd-026/mixed-failure-audit'
    failures=[]
    for label in ['first-run-command','second-run-command','third-run-command']:
        path=old/label;record=json.loads((path/'record.json').read_bytes())
        verify.common.require(record['exit_code']!=0 and sha(path/'stdout.txt')==record['stdout']['sha256']
                              and sha(path/'stderr.txt')==record['stderr']['sha256'],'prior failure missing')
        failures.append({'path':(path/'record.json').relative_to(verify.ROOT).as_posix(),'sha256':sha(path/'record.json')})
    path=old/'negative-controls';record=json.loads((path/'record.json').read_bytes())
    verify.common.require(record['exit_code']==0 and sha(path/'stdout.txt')==record['stdout']['sha256']
                          and sha(path/'stderr.txt')==record['stderr']['sha256']
                          and b'7 mixed-failure evidence mutations rejected' in (path/'stdout.txt').read_bytes(),
                          'negative controls missing')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output=folder/'readbacks'/stamp;output.mkdir(parents=True,exist_ok=False)
    report={'status':'passed','result_sha256':sha(result_path),'readback_source_sha256':sha(Path(__file__)),
            'source_files_checked':len(result['sources']),'command_records_checked':8,'two_source_orders':True,
            'true_error':'INVALID_INPUT/dex.code_layout/INSTRUCTION_REFERENCE_OUT_OF_RANGE',
            'sdk_observation':sdk_observation,'a0_bad_observations':result['a0_bad_observations'],
            'prior_failures':failures,'negative_controls':7,'task_complete_proven':False,
            'scope':'actual corrupt synthetic DEX and valid sibling; A0/SDK bad-input success is observational, not valid input proof'}
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(report))


if __name__=='__main__': main()
