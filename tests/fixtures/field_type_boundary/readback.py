#!/usr/bin/env python3
"""Append-only recheck of mixed field/type reference evidence."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('field_type_verify',HERE/'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    verify.common.require(len(sys.argv) == 2,'expected one evidence path')
    base = (ROOT/'artifacts/mdd-026/field-type-audit').resolve()
    folder = (ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder != base,'path outside field-type evidence')
    result_path = folder/'result.json'
    result = json.loads(result_path.read_bytes())
    verify.common.require(result['status'] == 'passed-scoped-field-type-observation'
                          and result['task_complete_proven'] is False and result['profile_admitted'] is False,
                          'scope overclaimed')
    for path,expected in result['sources'].items():
        verify.common.require(sha(ROOT/path) == expected,'source changed: '+path)
    verify.common.require(sha(verify.common.A0) == result['a0_sha256'] == verify.common.A0_SHA
                          and sha(folder/'field_type_probe.exe') == result['native_binary_sha256'], 'binary identity changed')
    for label in ['build','compile','native','a0-method_field_accesses','a0-method_used_types']:
        path = folder/label
        record = json.loads((path/'record.json').read_bytes())
        verify.common.require(record['exit_code'] == 0 and record['timed_out'] is False, 'command failed: '+label)
        for stream in ['stdout','stderr']:
            verify.common.require(sha(path/(stream+'.txt')) == record[stream+'_sha256'],'raw stream changed: '+label)
    native = json.loads((folder/'native/stdout.txt').read_bytes())
    occ = native['occurrences']
    verify.common.require(native['operation_status'] == 'ok' and native['probe_complete'] is True and len(occ) == 3
                          and len({x['source']['dex_occurrence_id'] for x in occ}) == 3,
                          'native occurrence terminal differs')
    verify.common.require([x['field_index'] for x in occ] == [0,1,0] and [x['type_index'] for x in occ] == [4,5,4],
                          'local target index differs')
    verify.common.require(occ[0]['pool']['string_pool_id'] == occ[2]['pool']['string_pool_id'] != occ[1]['pool']['string_pool_id']
                          and occ[0]['source']['content_id'] == occ[2]['source']['content_id'] != occ[1]['source']['content_id'],
                          'physical identity differs')
    for key in ['foreign_field','foreign_type']:
        verify.common.require(native[key]['code'] == 'INVALID_ARGUMENT' and native[key]['stage'] == 'facts.references',
                              'foreign source error differs')
    oracle_type = verify.oracle_type()
    expected = {name:[] for name in verify.COLUMNS}
    counts = {'field':0,'type':0}
    for i,((path,expected_sha),item) in enumerate(zip(verify.FIXTURES,occ)):
        raw = (ROOT/path).read_bytes()
        verify.common.require(hashlib.sha256(raw).hexdigest() == expected_sha == result['fixture_sha256'][i], 'fixture changed')
        oracle = oracle_type(raw).read()
        sites = [{'caller_method_idx':s['caller_method_idx'],'class_def_idx':s['class_def_idx'],'class_idx':s['class_idx'],
                  'pc':s['code_unit_pc'],'operand_ordinal':s['operand_ordinal'],'kind':s['target_kind'],
                  'index':s['target_local_index'],'byte_offset':int(s['operand_range']['byte_offset']),
                  'byte_length':int(s['operand_range']['byte_length']),'opcode':s['opcode']} for s in item['sites']]
        verify.common.require(sites == oracle['sites'],'source instruction sites differ')
        for kind,target,output in [('field',item['field_index'],'field_local'),('type',item['type_index'],'type_local')]:
            selected = [s for s in oracle['sites'] if s['kind'] == kind and s['index'] == target]
            wanted = [{'caller_method_definition':{'dex_occurrence_id':item['source']['dex_occurrence_id'],
                       'kind':'method_definition','local_index':s['caller_method_idx'],'snapshot_id':native['snapshot_id']},
                       'code_unit_pc':s['pc'],'operand_kind':kind,'operand_ordinal':s['operand_ordinal']} for s in selected]
            verify.common.require(item[output]['sites'] == wanted,'indexed source binding differs')
            counts[kind] += len(selected)
        for name,field in [('method_field_accesses','field_rows'),('method_used_types','type_rows')]:
            rows = [dict(row,file_id=i) for row in oracle['relations'][name]]
            verify.common.require(item[field] == rows,'native rows differ from oracle')
            expected[name].extend(rows)
    verify.common.require(counts == result['target_site_counts'] == {'field':6,'type':6}, 'site counts differ')
    for name,columns in verify.COLUMNS.items():
        rows = verify.common.table((folder/('a0-'+name)/'stdout.txt').read_bytes(),columns)
        observed = [{k:None if v == 'N' else bytes.fromhex(v).decode('utf8','strict') for k,v in row.items()} for row in rows]
        wanted = [{k:str(row[k]) for k in columns} for row in expected[name]]
        verify.compare(observed,wanted)
        verify.common.require(len(observed) == result['a0_row_counts'][name], 'A0 row count differs')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = folder/'readbacks'/stamp
    output.mkdir(parents=True,exist_ok=False)
    summary = {'status':'passed','result_sha256':sha(result_path),'readback_source_sha256':sha(Path(__file__)),
               'source_files_checked':len(result['sources']),'command_records_checked':5,'source_occurrences':3,
               'field_target_sites':6,'type_target_sites':6,'a0_field_rows':7,'a0_type_rows':6,
               'task_complete_proven':False,'scope':'synthetic field/type sites and A0 multisets; no full profile or runtime resolution'}
    (output/'result.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
