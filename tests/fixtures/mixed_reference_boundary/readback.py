#!/usr/bin/env python3
"""Append-only recheck of mixed-reference raw evidence; no task admission."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('mixed_reference_verify', HERE/'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    verify.common.require(len(sys.argv) == 2, 'expected one recorded run path')
    base = (ROOT/'artifacts/mdd-026/mixed-reference-audit').resolve()
    folder = (ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder != base, 'run outside evidence directory')
    raw = (folder/'result.json').read_bytes()
    report = json.loads(raw)
    verify.common.require(report['status'] == 'passed-scoped-mixed-reference-comparison'
                          and report['task_complete_proven'] is False and report['profile_admitted'] is False,
                          'scope overclaim')
    for name, sha in report['sources'].items():
        verify.common.require(digest(ROOT/name) == sha, 'tested source changed: '+name)
    verify.common.require(digest(verify.common.A0) == report['a0_sha256'] == verify.common.A0_SHA,
                          'A0 identity changed')
    verify.common.require(digest(folder/'mixed_reference_probe.exe') == report['probe_binary_sha256'],
                          'probe binary identity changed')
    for label in ['build', 'compile', 'native', 'a0-calls']:
        path = folder/label
        record = json.loads((path/'record.json').read_bytes())
        verify.common.require(record['exit_code'] == 0, 'command failed: '+label)
        for stream in ['stdout', 'stderr']:
            verify.common.require(digest(path/(stream+'.txt')) == record[stream+'_sha256'], 'raw stream changed: '+label)
    native = json.loads((folder/'native/stdout.txt').read_bytes())
    verify.common.require(native['operation_status'] == 'ok' and native['probe_complete'] is True
                          and native['cross_occurrence_error']['code'] == 'INVALID_ARGUMENT', 'native terminal differs')
    occurrences = native['occurrences']
    verify.common.require(len(occurrences) == 3 and len({o['source']['dex_occurrence_id'] for o in occurrences}) == 3,
                          'occurrences lost')
    manifest = json.loads((HERE/'manifest.json').read_bytes())
    entries = {x['id']:x for x in manifest['files']}
    Oracle = verify.oracle_type()
    expected_rows = []
    sites = []
    for index, (name, actual) in enumerate(zip(manifest['scenario'], occurrences)):
        fixture = HERE/entries[name]['path']
        verify.common.require(digest(fixture) == entries[name]['sha256'] == report['fixture_sha256'][index], 'fixture changed')
        independent = Oracle(fixture.read_bytes()).read()
        expected_rows.extend(dict(row, file_id=index) for row in independent['relations']['method_calls'])
        sites.extend(independent['sites'])
        verify.common.require(actual['method_call_rows'] == [dict(row, file_id=index) for row in independent['relations']['method_calls']],
                              'native relation differs from bytes')
        actual_sites = [{'caller_method_idx':s['caller_method_idx'], 'class_def_idx':s['class_def_idx'], 'class_idx':s['class_idx'],
                         'pc':s['code_unit_pc'], 'operand_ordinal':s['operand_ordinal'], 'kind':s['target_kind'],
                         'index':s['target_local_index'], 'byte_offset':int(s['operand_range']['byte_offset']),
                         'byte_length':int(s['operand_range']['byte_length']), 'opcode':s['opcode']} for s in actual['all_sites']]
        verify.common.require(actual_sites == independent['sites'], 'native site bytes/order differ')
    cols = ['file_id','method','method_class','method_name','class_idx','method_idx','callee','callee_class','callee_name','callee_method_idx']
    raw_rows = verify.common.table((folder/'a0-calls/stdout.txt').read_bytes(), cols)
    actual_rows = [{k:None if v == 'N' else bytes.fromhex(v).decode('utf8', 'strict') for k,v in row.items()} for row in raw_rows]
    key = lambda row:(int(row['file_id']), int(row['method_idx']), int(row['callee_method_idx']), row['callee'])
    expected = [{k:str(row[k]) for k in cols} for row in sorted(expected_rows, key=key)]
    verify.compare_rows(actual_rows, expected)
    verify.common.require(len(sites) == report['all_site_count'] == 40 and len(actual_rows) == report['a0_method_call_rows'] == 16,
                          'recorded counts differ')
    shared = [s for s in occurrences[1]['all_sites'] if s['target_kind'] == 'method'
              and s['target_local_index'] == occurrences[1]['target_index']]
    verify.common.require(len(shared) == 2 and {s['caller_method_idx'] for s in shared} == {0,1}
                          and len({s['code_item_byte_offset'] for s in shared}) == 1, 'shared owner evidence differs')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = folder/'readbacks'/stamp
    output.mkdir(parents=True, exist_ok=False)
    summary = {'status':'passed', 'result_sha256':hashlib.sha256(raw).hexdigest(), 'readback_source_sha256':digest(Path(__file__)),
               'source_files_checked':len(report['sources']), 'command_records_checked':4, 'source_occurrences':3,
               'site_count':40, 'a0_method_call_rows':16, 'shared_physical_code_owners':2,
               'task_complete_proven':False, 'scope':'synthetic byte oracle and recorded A0 rows; not complete HostLab or runtime dispatch'}
    (output/'result.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf8', newline='\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
