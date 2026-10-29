#!/usr/bin/env python3
"""Read-only recheck of pre/post Q09 counterexample and SQLite reference."""
import hashlib
import json
from pathlib import Path
import tomllib
from before_readback import cells, require, sha

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def main():
    before=json.loads((HERE/'source-after-fix-before-build.json').read_text(encoding='utf8'))
    for path,expected in before['sha256'].items():
        require(sha(ROOT/path)==expected,'source drift: '+path)
    for phase in ('build3','probe2'):
        folder=HERE/phase
        rec=json.loads((folder/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'):
            require(sha(folder/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream changed')
        require(sha(folder/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor changed')
    def external(path):
        return sorted((p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source'))
    require(external(ROOT/'Cargo.lock')==external(HERE/'Cargo.lock') and len(external(HERE/'Cargo.lock'))==46,'external locks differ')
    refpath=HERE/'sqlite-q09/stdout.txt'; refrec=json.loads((HERE/'sqlite-q09/record.json').read_text(encoding='utf8'))
    require(refrec['exit_code']==0 and sha(refpath)==refrec['stdout']['sha256'],'sqlite reference drift')
    refs=json.loads(refpath.read_text(encoding='utf8'))['results']
    data=json.loads((HERE/'probe2/stdout.txt').read_text(encoding='utf8'))
    require(not data['profiles_admitted'] and len(data['records'])==27,'denominator')
    by={(x['dialect'],x['case']):x for x in data['records']}
    require(len(by)==27,'duplicate case')
    for dialect in ('NativeV1','DexSql010','DexSql011'):
        for name in ('q09_range','q09_empty','duplicates','null_projection','not_between','null_lower','null_upper'):
            row=by[dialect,name]; out=row['output']; ref=refs[name]
            require(row['sql']==ref['sql'] and out['status']=='ok' and out['result']['calculation_complete']
                    and out['result']['columns']==ref['columns'] and cells(out['result']['rows'])==ref['rows'],
                    dialect+' '+name+' mismatch')
        for name in ('text_bounds','literal_mixed'):
            row=by[dialect,name]; require(row['sql']==refs[name]['sql'] and row['output']['status']=='error'
                    and row['output']['error']['code']=='UNSUPPORTED_QUERY',dialect+' '+name+' expected unsupported')
    old=json.loads((HERE/'before-readback/stdout.txt').read_text(encoding='utf8'))
    require(old['status']=='confirmed_pre_fix_silent_wrong_rows' and len(old['counterexample'])==3,'pre-fix evidence')
    for x in old['counterexample']:
        require(x['actual_not_between']==[] and x['sqlite_not_between']==[[9],[12]],'pre-fix mismatch missing')
    binary=ROOT/'artifacts/local/between-independent-20261029-target/debug/mdd-between-independent.exe'
    print(json.dumps({'status':'passed-scoped','cases':27,'sqlite_matching_cases':21,'unsupported_cases':6,
                      'not_between_before':[],'not_between_after':[[9],[12]],
                      'not_between_reference':[[9],[12]],'source_before_after_equal':True,
                      'source_sha256':before['sha256'],'binary_sha256':sha(binary),
                      'old_evidence_sha256':sha(HERE/'before-readback/stdout.txt'),
                      'a0_a1_started':False,'profiles_admitted':False,
                      'limitations':['synthetic provider; production facts not connected','NULL index deliberately tests boundary outside frozen non-null schema',
                                     'text-bound and mixed literal affinity unsupported','no DTO or full query-profile qualification']}))


if __name__=='__main__':
    main()
