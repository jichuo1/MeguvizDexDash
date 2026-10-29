#!/usr/bin/env python3
"""Read-only verification of the saved pre-fix Q09/BETWEEN counterexample."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def require(ok,why):
    if not ok:
        raise ValueError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cells(rows):
    out=[]
    for row in rows:
        values=[]
        for cell in row:
            if cell['type']=='null': values.append(None)
            elif cell['type'] in ('i64','u64'): values.append(int(cell['value']))
            else: raise ValueError('unexpected cell '+cell['type'])
        out.append(values)
    return out


def main():
    for phase in ('build2','probe'):
        p=HERE/phase; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream drift')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor drift')
    p=HERE/'sqlite-q09'; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
    require(rec['exit_code']==0,'sqlite reference failed')
    for stream in ('stdout','stderr'):
        require(sha(p/(stream+'.txt'))==rec[stream]['sha256'],'sqlite stream drift')
    refs=json.loads((p/'stdout.txt').read_text(encoding='utf8'))
    candidate=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(candidate['profiles_admitted'] is False and len(candidate['records'])==27,'candidate scope')
    by={(x['dialect'],x['case']):x for x in candidate['records']}
    require(len(by)==27,'duplicate case')
    errors=[]
    for d in ('NativeV1','DexSql010','DexSql011'):
        for name in ('q09_range','q09_empty','duplicates','null_projection','null_lower','null_upper'):
            record=by[d,name]; output=record['output']; expected=refs['results'][name]
            require(record['sql']==expected['sql'] and output['status']=='ok'
                    and output['result']['calculation_complete'] is True
                    and output['result']['columns']==expected['columns']
                    and cells(output['result']['rows'])==expected['rows'],d+' '+name+' differs')
        bad=by[d,'not_between']; require(bad['sql']==refs['results']['not_between']['sql'],'SQL changed')
        require(bad['output']['status']=='ok' and bad['output']['result']['calculation_complete'] is True
                and cells(bad['output']['result']['rows'])==[] and refs['results']['not_between']['rows']==[[9],[12]],
                d+' missing counterexample')
        for name in ('text_bounds','literal_mixed'):
            record=by[d,name]; require(record['sql']==refs['results'][name]['sql'],'SQL changed')
            require(record['output']['status']=='error' and record['output']['error']['code']=='UNSUPPORTED_QUERY',
                    d+' '+name+' expected unsupported')
        errors.append({'dialect':d,'actual_not_between':[],'sqlite_not_between':[[9],[12]],
                       'missing_rows':2,'successful_terminal':True})
    binary=ROOT/'artifacts/local/between-independent-binaries/q09-before.exe'
    require(sha(binary)=='f435071c6de5d91d8a7296f73e05342e2897c3179f70edb895d7454e2e50f5c9','binary drift')
    before=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    print(json.dumps({'status':'confirmed_pre_fix_silent_wrong_rows','sqlite_version':refs['sqlite_version'],
                      'cases':27,'matched_cases_per_dialect':6,'fail_closed_cases_per_dialect':2,
                      'counterexample':errors,'binary_sha256':sha(binary),
                      'source_identity_before_build':before['sha256'],
                      'candidate_stdout_sha256':sha(HERE/'probe/stdout.txt'),
                      'sqlite_stdout_sha256':sha(p/'stdout.txt'),
                      'profile_admitted':False,
                      'scope':'synthetic provider, Q09 literal range and related operators; no A0/A1 or production facts',
                      'limitations':['null method index is a deliberate synthetic boundary, not the frozen non-null schema',
                                     'text-bound affinity remains unsupported','source hash recorded before build, not rechecked immediately after']}))


if __name__=='__main__':
    main()
