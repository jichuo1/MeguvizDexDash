#!/usr/bin/env python3
"""Append-only recheck of nonempty partial reference coverage evidence."""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import verify


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    verify.common.require(len(sys.argv)==2,'expected one evidence path')
    base=(verify.ROOT/'artifacts/mdd-026/partial-reference-audit').resolve();folder=(verify.ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder!=base,'path outside partial evidence')
    result_path=folder/'result.json';result=json.loads(result_path.read_bytes())
    verify.common.require(result['status']=='passed-nonempty-partial-reference-scope'
                          and result['task_complete_proven'] is False and result['profile_admitted'] is False,'scope overclaimed')
    for path,expected in result['sources'].items():verify.common.require(sha(verify.ROOT/path)==expected,'source changed: '+path)
    verify.common.require(sha(verify.common.A0)==result['a0_sha256']==verify.common.A0_SHA
                          and sha(folder/'partial_reference_probe.exe')==result['native_binary_sha256']
                          and sha(verify.ROOT/verify.FIXTURE)==result['fixture_sha256']==verify.FIXTURE_SHA,'binary/input identity changed')
    for label in ['build','compile','native-partial-0','native-partial-1','a0-full-two-sources']:
        path=folder/label;record=json.loads((path/'record.json').read_bytes())
        verify.common.require(record['exit_code']==0 and record['timed_out'] is False,'process failed: '+label)
        for stream in ['stdout','stderr']:
            verify.common.require(sha(path/(stream+'.txt'))==record[stream+'_sha256'],'raw stream changed: '+label)
    oracle=verify.helper.oracle_type()((verify.ROOT/verify.FIXTURE).read_bytes());ref=oracle.read()
    caller=next(x for x in oracle.definitions if x[0]==0);target=next(x for x in oracle.definitions if x[0]==2)
    verify.common.require(caller[3]==420 and target[3]==488 and len(ref['sites'])==10,'byte oracle offset differs')
    for partial in [0,1]:
        value=json.loads((folder/('native-partial-'+str(partial))/'stdout.txt').read_bytes());verify.validate(value,partial)
        sites=[{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in value['partial_sites']]
        verify.common.require(sites==ref['sites'] and value['full_method_rows']==[dict(x,file_id=1-partial) for x in ref['relations']['method_calls']],
                              'byte sites or full sibling differs')
    rows=verify.common.table((folder/'a0-full-two-sources/stdout.txt').read_bytes(),verify.COLS)
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
    wanted=[{k:str(dict(row,file_id=n)[k]) for k in verify.COLS} for n in [0,1] for row in ref['relations']['method_calls']]
    verify.helper.compare(actual,wanted);verify.common.require(len(actual)==result['a0_complete_duplicate_rows']==8,'A0 full rows differ')
    neg=verify.ROOT/'artifacts/mdd-026/partial-reference-audit/negative-controls';record=json.loads((neg/'record.json').read_bytes())
    verify.common.require(record['exit_code']==0 and sha(neg/'stdout.txt')==record['stdout']['sha256']
                          and sha(neg/'stderr.txt')==record['stderr']['sha256']
                          and b'8 partial-reference evidence mutations rejected' in (neg/'stdout.txt').read_bytes(),
                          'negative evidence differs')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');output=folder/'readbacks'/stamp
    output.mkdir(parents=True,exist_ok=False)
    report={'status':'passed','result_sha256':sha(result_path),'readback_source_sha256':sha(Path(__file__)),
            'source_files_checked':len(result['sources']),'command_records_checked':5,'partial_orders':2,
            'nonempty_partial_sites_each':10,'local_partial_matches_each':2,'a0_complete_rows':8,'negative_controls':8,
            'task_complete_proven':False,'scope':'synthetic nonempty partial references and A0 full source rows; not full profile'}
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n');print(json.dumps(report))


if __name__=='__main__':main()
