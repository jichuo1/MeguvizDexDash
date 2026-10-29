#!/usr/bin/env python3
"""Append-only raw generation, fixed A0 and negative-control readback."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import verify


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    verify.common.require(len(sys.argv)==2,'expected recorded run directory')
    base=(verify.ROOT/'artifacts/mdd-026/raw-generation-audit').resolve();folder=(verify.ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder!=base,'run outside evidence directory')
    result_path=folder/'result.json';report=json.loads(result_path.read_bytes())
    verify.common.require(report['status']=='passed-synthetic-two-generation-raw-code'
                          and report['task_complete_proven'] is False and report['profile_admitted'] is False,'scope overclaimed')
    for path,want in report['sources'].items():verify.common.require(verify.common.digest(verify.ROOT/path)==want,'source drift: '+path)
    verify.common.require(verify.common.digest(folder/'raw_generation_probe.exe')==report['binary_sha256']
                          and verify.common.digest(verify.common.A0)==report['a0_sha256']==verify.common.A0_SHA,'binary changed')
    raw_a,raw_b=verify.generated();a,b=verify.oracle(raw_a),verify.oracle(raw_b)
    verify.common.require(sha(raw_a)==report['generation_a_sha256'] and sha(raw_b)==report['generation_b_sha256']
                          and a==report['oracle_a'] and b==report['oracle_b'],'fixture/oracle differs')
    for label in ('build','compile','native','a0-old','a0-new'):
        loc=folder/label;rec=json.loads((loc/'record.json').read_bytes())
        verify.common.require(rec['exit_code']==0 and rec['timed_out'] is False,'process failed: '+label)
        for name in ('stdout','stderr'):
            verify.common.require(sha((loc/(name+'.txt')).read_bytes())==rec[name+'_sha256'],'process output changed: '+label)
    verify.validate(json.loads((folder/'native/stdout.txt').read_bytes()),a,b,raw_a,raw_b)
    for label,ref in [('a0-old',a),('a0-new',b)]:
        rows=verify.a0_rows((folder/label/'stdout.txt').read_bytes())
        verify.common.require(rows==[{k:x[k] for k in verify.COLS} for x in ref['methods']],'A0 row readback differs: '+label)
    started=datetime.datetime.now(datetime.timezone.utc)
    out=folder/'readbacks'/started.strftime('%Y%m%dT%H%M%S%fZ');out.mkdir(parents=True,exist_ok=False)
    command=[sys.executable,'-O','tests/fixtures/raw_generation_boundary/test_failures.py',sys.argv[1]]
    proc=subprocess.run(command,cwd=verify.ROOT,capture_output=True,timeout=30)
    (out/'negative.stdout.txt').write_bytes(proc.stdout);(out/'negative.stderr.txt').write_bytes(proc.stderr)
    (out/'negative.record.json').write_text(json.dumps({'argv':command,'exit_code':proc.returncode,
        'stdout_sha256':sha(proc.stdout),'stderr_sha256':sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    verify.common.require(proc.returncode==0 and b'10 raw generation, no-body, source and error mutations rejected' in proc.stdout,
                          'negative controls failed')
    output={'status':'passed','result_sha256':verify.common.digest(result_path),
            'readback_source_sha256':verify.common.digest(Path(__file__)),'generations':2,'a0_rows_each':2,
            'negative_controls':10,'task_complete_proven':False,
            'scope':'actual DEX rewrite, raw method evidence and A0 ranges; no ART or full profile qualification'}
    (out/'result.json').write_text(json.dumps(output,indent=2)+'\n',encoding='utf8')
    print(json.dumps(output))


if __name__=='__main__':main()
