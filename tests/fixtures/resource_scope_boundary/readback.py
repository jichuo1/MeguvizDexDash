#!/usr/bin/env python3
"""Append a readback; verify original records and retain earlier runs."""
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
    base=(verify.ROOT/'artifacts/mdd-026/resource-scope-audit').resolve()
    folder=(verify.ROOT/sys.argv[1]).resolve()
    verify.common.require(folder.is_relative_to(base) and folder!=base,'run outside evidence directory')
    report=json.loads((folder/'result.json').read_bytes())
    verify.common.require(report['status']=='passed-synthetic-resource-scope' and report['task_complete_proven'] is False
                          and report['profile_admitted'] is False,'scope overclaimed')
    for path,want in report['sources'].items():verify.common.require(verify.common.digest(verify.ROOT/path)==want,'source drift: '+path)
    verify.common.require(verify.common.digest(folder/'resource_scope_probe.exe')==report['binary_sha256'],'binary changed')
    raw=verify.generated();expected=verify.oracle(raw)
    verify.common.require(sha(raw)==report['fixture_sha256'] and len(raw)==report['fixture_bytes'] and expected==report['oracle'],'fixture/oracle differs')
    for label in ('build','compile','native'):
        loc=folder/label;rec=json.loads((loc/'record.json').read_bytes())
        verify.common.require(rec['exit_code']==0 and rec['timed_out'] is False,'process failed: '+label)
        for name in ('stdout','stderr'):
            verify.common.require(sha((loc/(name+'.txt')).read_bytes())==rec[name+'_sha256'],'process output changed: '+label)
    verify.validate(json.loads((folder/'native/stdout.txt').read_bytes()),expected)
    started=datetime.datetime.now(datetime.timezone.utc)
    out=folder/'readbacks'/started.strftime('%Y%m%dT%H%M%S%fZ');out.mkdir(parents=True,exist_ok=False)
    command=[sys.executable,'-O','tests/fixtures/resource_scope_boundary/test_failures.py',sys.argv[1]]
    proc=subprocess.run(command,cwd=verify.ROOT,capture_output=True,timeout=30)
    (out/'negative.stdout.txt').write_bytes(proc.stdout);(out/'negative.stderr.txt').write_bytes(proc.stderr)
    (out/'negative.record.json').write_text(json.dumps({'argv':command,'exit_code':proc.returncode,
        'stdout_sha256':sha(proc.stdout),'stderr_sha256':sha(proc.stderr)},indent=2)+'\n',encoding='utf8')
    verify.common.require(proc.returncode==0 and b'7 resource identity, coverage and error mutations rejected' in proc.stdout,
                          'negative controls failed')
    result={'status':'passed','result_sha256':verify.common.digest(folder/'result.json'),
            'readback_source_sha256':verify.common.digest(Path(__file__)),'source_occurrences':2,
            'physical_resource_occurrences':6,'negative_controls':7,'task_complete_proven':False,
            'scope':'synthetic duplicate ZIP names and immutable resource snapshots only; no profile qualification'}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result))


if __name__=='__main__':main()
