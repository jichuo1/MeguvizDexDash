#!/usr/bin/env python3
"""Compare supported min/max cases while retaining collation and DTO gaps."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
EXPLICIT={'nocase_left','nocase_right','binary_then_nocase','nocase_then_binary',
          'reversed_collations','column_explicit'}
COLUMNS={'column_binding','column_null','column_multirow'}


def require(ok,why):
    if not ok:raise RuntimeError(why)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):return json.loads(path.read_text(encoding='utf8'))


def candidate_cell(cell):
    kind=cell['type']
    if kind=='null':
        require('value' not in cell,'native NULL layout changed');return None
    if kind=='i64':return int(cell['value'])
    if kind=='u64':return int(cell['value'])
    if kind=='bytes':return bytes(cell['value'])
    if kind=='text':
        units=cell['value']['utf16'];raw=b''.join(int(v).to_bytes(2,'little') for v in units)
        return raw.decode('utf-16-le',errors='strict')
    raise RuntimeError('unexpected candidate cell: '+kind)


def sqlite_cell(cell):
    kind=cell['type']
    if kind=='null':return None
    if kind=='integer':return int(cell['value'])
    if kind=='text':return cell['value']
    if kind=='blob':return bytes.fromhex(cell['hex'])
    raise RuntimeError('unexpected SQLite cell: '+kind)


def main():
    for name in ('sqlite-run','sqlite-binary-run'):
        p=HERE/name;rec=read(p/'record.json');require(rec['exit_code']==0,'SQLite command failed')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==rec[stream]['sha256'],'SQLite stream changed')
    for name in ('build','probe'):
        p=HERE/name;rec=read(p/'record.json');job=read(p/'supervisor.json')
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified']
                and job['status']=='completed' and job['assigned_before_resume'] and job['tree_empty_verified'],
                name+' job incomplete')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],'supervisor changed')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],'job stream changed')
    sources=read(HERE/'source-before.json')
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'source changed: '+path)
    def external(path):
        return {(p['name'],p['version'],p.get('checksum'))
                for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(ROOT/'Cargo.lock'))==46 and external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock'),
            'external lock differs')
    reference=read(HERE/'sqlite-reference.json');binary=read(HERE/'sqlite-binary-columns.json')
    refs={x['case']:x for x in reference['records']};binary_refs={x['case']:x for x in binary['records']}
    data=read(HERE/'probe/stdout.txt');rows={(x['dialect'],x['case']):x for x in data['records']}
    require(len(refs)==23 and len(binary_refs)==4 and len(rows)==len(data['records'])==69
            and not data['profile_admitted'],'case denominator differs')
    counts={'value_matches':0,'invalid_arity':0,'explicit_collation_unsupported':0}
    for dialect in ('native','010','011'):
        for name,ref in refs.items():
            actual=rows[(dialect,name)];result=actual['result'];require(actual['sql']==ref['sql'],'SQL mismatch')
            if name in EXPLICIT:
                require(result['status']=='error' and result['error']['code']=='UNSUPPORTED_QUERY',
                        'explicit collation unexpectedly admitted: '+name)
                counts['explicit_collation_unsupported']+=1;continue
            if ref['status']=='error':
                require(name in ('zero_min','zero_max') and result['status']=='error'
                        and result['error']['code']=='INVALID_ARGUMENT','arity error mismatch')
                counts['invalid_arity']+=1;continue
            require(result['status']=='ok' and result['result']['calculation_complete'],'candidate incomplete: '+name)
            if name in COLUMNS:
                expected=binary_refs[name]['rows'];columns=binary_refs[name]['columns']
            else:
                expected=[[sqlite_cell(cell) for cell in row] for row in ref['rows']];columns=ref['columns']
            actual_values=[[candidate_cell(cell) for cell in row] for row in result['result']['rows']]
            require(result['result']['columns']==columns and actual_values==expected,
                    'value/column mismatch: '+dialect+'/'+name)
            counts['value_matches']+=1
    require(counts=={'value_matches':45,'invalid_arity':6,'explicit_collation_unsupported':18},'count differs')
    # Actual SQLite NOCASE and BINARY observations differ; provider has no collation field.
    nocase=[[sqlite_cell(c) for c in row] for row in refs['column_binding']['rows']]
    default=binary_refs['column_binding']['rows']
    require(nocase==[['a','B','B','a']] and default==[['B','a','B','a']], 'collation counterexample differs')
    out={'status':'passed-supported-subset','candidate_cases':69,**counts,'sqlite_version':reference['sqlite_version'],
         'source_sha256':sources,'candidate_stdout_sha256':sha(HERE/'probe/stdout.txt'),
         'sqlite_reference_sha256':sha(HERE/'sqlite-reference.json'),
         'sqlite_binary_sha256':sha(HERE/'sqlite-binary-columns.json'),
         'binary_sha256':sha(ROOT/'artifacts/local/like-independent-20261029-target/debug/mdd-multi-minmax-independent.exe'),
         'column_collation_counterexample':{'declared_nocase':nocase,'declared_binary':default},
         'a0_a1_started':False,'dto_equivalent':False,'profile_admitted':False,
         'scope':'small synthetic provider; 45 values compared to SQLite, 6 invalid arity and 18 unsupported collation',
         'limits':['explicit COLLATE not supported','provider has no per-column collation metadata',
                   'NOCASE column reference differs from BINARY and was not equated',
                   'native DTO labels/NULL layout not compared to old engines',
                   'no production fact adapter or full SQL profile qualification']}
    output=HERE/'qualification.json';require(not output.exists(),'do not overwrite qualification')
    output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({k:out[k] for k in ('status','candidate_cases','value_matches','invalid_arity',
                                        'explicit_collation_unsupported','a0_a1_started','profile_admitted')}))


if __name__=='__main__':main()
