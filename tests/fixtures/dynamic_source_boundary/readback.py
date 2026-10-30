#!/usr/bin/env python3
"""Append-only recheck of dynamic, handle and orphan source evidence."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('dynamic_source_verify',HERE/'verify.py')
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    verify.common.require(len(sys.argv)==2,'expected one recorded run path')
    base=(ROOT/'artifacts/mdd-026/dynamic-source-audit').resolve()
    folder=(ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder!=base,'run path outside evidence')
    result_path=folder/'result.json';result=json.loads(result_path.read_bytes())
    verify.common.require(result['status']=='passed-scoped-dynamic-source-observation'
                          and result['task_complete_proven'] is False and result['profile_admitted'] is False,'scope overclaimed')
    for path,expected in result['sources'].items():
        verify.common.require(sha(ROOT/path)==expected,'source identity changed: '+path)
    verify.common.require(sha(verify.common.A0)==result['a0_sha256']==verify.common.A0_SHA
                          and sha(folder/'dynamic_source_probe.exe')==result['native_binary_sha256'],'binary identity changed')
    for label in ['build','compile','native','a0-method-calls']:
        path=folder/label;record=json.loads((path/'record.json').read_bytes())
        verify.common.require(record['exit_code']==0 and record['timed_out'] is False,'command failed: '+label)
        for stream in ['stdout','stderr']:
            verify.common.require(sha(path/(stream+'.txt'))==record[stream+'_sha256'],'raw stream changed: '+label)
    native=json.loads((folder/'native/stdout.txt').read_bytes());occ=native['occurrences']
    verify.common.require(native['operation_status']=='ok' and native['probe_complete'] is True
                          and len(occ)==4 and len({x['source']['dex_occurrence_id'] for x in occ})==4,
                          'native occurrence terminal differs')
    verify.common.require(native['foreign_call_site']['code']=='INVALID_ARGUMENT'
                          and len(native['quota_errors'])==4 and all(x['code']=='QUOTA_EXCEEDED' for x in native['quota_errors']),
                          'foreign lookup or budget terminal differs')
    verify.common.require(occ[0]['source']['content_id']==occ[3]['source']['content_id']
                          and occ[0]['pool']['string_pool_id']==occ[3]['pool']['string_pool_id'],'physical identity differs')
    Oracle=verify.helper.oracle_type();expected=[];counts=[]
    for n,((path,expected_sha),item) in enumerate(zip(verify.FIXTURES,occ)):
        raw=(ROOT/path).read_bytes()
        verify.common.require(hashlib.sha256(raw).hexdigest()==expected_sha==result['fixture_sha256'][n],'fixture changed')
        ref=Oracle(raw).read()
        sites=[{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in item['sites']]
        verify.common.require(sites==ref['sites'],'raw sites differ')
        rows=[dict(row,file_id=n) for row in ref['relations']['method_calls']]
        verify.common.require(item['method_call_rows']==rows,'native call rows differ')
        verify.common.require(item['coverage']['unowned_physical_code_items']==len(ref['unowned_code_offsets']),
                              'unowned coverage differs')
        expected.extend(rows);counts.append(len(sites))
        verify.common.require(len(item['dynamic_calls'])==len(ref['dynamic_calls']),'dynamic count differs')
        for observed,wanted in zip(item['dynamic_calls'],ref['dynamic_calls']):
            site=item['sites'][observed['site_ordinal']]
            verify.common.require(site['caller_method_idx']==wanted['caller_method_idx'] and site['code_unit_pc']==wanted['pc']
                                  and observed['call_site_idx']==wanted['call_site_idx']
                                  and 'unknown_dynamic_target' in observed['runtime_target_status'],'dynamic binding differs')
        checks=item['target_checks']
        verify.common.require(len(checks)==len(ref['sites']),'target checks incomplete')
        for check,site in zip(checks,ref['sites']):
            target=check['target'];kind=site['kind'];idx=site['index']
            verify.common.require(target['kind']==kind and target['local_index']==idx
                                  and target['dex_occurrence_id']==item['source']['dex_occurrence_id'],
                                  'target identity differs')
            matches=[{'caller_method_definition':{'dex_occurrence_id':item['source']['dex_occurrence_id'],
                      'kind':'method_definition','local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                      'code_unit_pc':s['pc'],'operand_kind':kind,'operand_ordinal':s['operand_ordinal']}
                     for s in ref['sites'] if s['kind']==kind and s['index']==idx]
            verify.common.require(check['matches']['sites']==matches,'indexed/scalar target sites differ')
    verify.common.require(counts==result['site_counts']==[17,13,10,17]
                          and [len(x['dynamic_calls']) for x in occ]==[2,0,0,2]
                          and [x['coverage']['unowned_physical_code_items'] for x in occ]==[0,0,1,0],
                          'dynamic/orphan counts differ')
    rows=verify.common.table((folder/'a0-method-calls/stdout.txt').read_bytes(),verify.COLS)
    actual=[{k:None if v=='N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
    wanted=[{k:str(row[k]) for k in verify.COLS} for row in expected]
    verify.helper.compare(actual,wanted)
    verify.common.require(len(actual)==result['a0_method_call_rows']==20,'A0 call multiplicity differs')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output=folder/'readbacks'/stamp;output.mkdir(parents=True,exist_ok=False)
    summary={'status':'passed','result_sha256':sha(result_path),'readback_source_sha256':sha(Path(__file__)),
             'source_files_checked':len(result['sources']),'command_records_checked':4,'source_occurrences':4,
             'reference_sites':57,'dynamic_calls':4,'unowned_code_items':1,'a0_call_rows':20,
             'quota_errors':4,'task_complete_proven':False,
             'scope':'synthetic encoded references, A0 call rows; dynamic runtime target remains unknown'}
    (output/'result.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
