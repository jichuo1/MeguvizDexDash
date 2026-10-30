#!/usr/bin/env python3
"""Re-run the offline frozen-consumer boundary without writing older evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def require(ok,why):
    if not ok: raise ValueError(why)


def main():
    first=json.loads((HERE/'probe-run/record.json').read_text(encoding='utf8'))
    require(first['exit_code']!=0 and sha(HERE/'probe-run/stderr.txt')==first['stderr']['sha256']
            and "KeyError: 'path'" in (HERE/'probe-run/stderr.txt').read_text(encoding='utf8'),
            'first probe failure missing')
    record=json.loads((HERE/'probe2-run/record.json').read_text(encoding='utf8'))
    require(record['exit_code']==0,'corrected probe failed')
    for stream in ('stdout','stderr'):
        require(sha(HERE/'probe2-run'/(stream+'.txt'))==record[stream]['sha256'],'saved output drift')
    saved=json.loads((HERE/'probe2-run/stdout.txt').read_text(encoding='utf8'))
    require(saved['status']=='observed-scoped' and not saved['profiles_admitted']
            and not saved['old_engine_started'] and not saved['network_used'],'scope drift')
    runner=ROOT/'artifacts/local/baseline-venv/Scripts/python.exe'
    proc=subprocess.run([str(runner),'-O',str(HERE/'probe.py')],cwd=ROOT,capture_output=True,timeout=30)
    require(proc.returncode==0,'independent recomputation failed')
    computed=json.loads(proc.stdout)
    require(saved==computed,'recomputation differs')
    require(saved['batch']['null']['error_type']=='KeyError' and saved['batch']['null']['error_text']=="'value'",'NULL boundary')
    require(saved['batch']['null_only_normalization']['cell_equal_to_saved'] and saved['batch']['null_only_normalization']['rows']==[[None]],'NULL normalization')
    a=saved['selected_cells']['empty']; b=saved['selected_cells']['string_0']
    require(a['candidate']==b['candidate']=={'type':'i64','value':'0'}
            and a['old']=={'type':'uint64','value':'0'} and b['old']=={'type':'int64','value':'0'},'origin ambiguity')
    for name in ('legacy_nul','legacy_pair','legacy_unpaired'):
        require(saved['cli'][name]['status']=='error' and saved['cli'][name]['error_text']=='native audit returned a malformed hex cell','strict decoder')
    print(json.dumps({'status':'passed-readback-only','null_keyerror_reproduced':True,'local_null_normalization_passed':True,
      'identical_candidate_cell_distinct_old_tags':True,'old_engine_started':False,'legacy_strict_decoder_errors':3,
      'saved_probe_stdout_sha256':sha(HERE/'probe2-run/stdout.txt'),'probe_source_sha256':sha(HERE/'probe.py'),
      'profiles_admitted':False,'scope':'frozen consumer methods with controlled fake transport; not production adapter or HostLab full run'}))


if __name__=='__main__': main()
