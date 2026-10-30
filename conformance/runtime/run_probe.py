"""Bounded standalone probe recorder, never a benchmark or business runner."""
from datetime import datetime,timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--mode',choices=['sqlite','supervisor'],required=True);args=parser.parse_args()
    binary=args.binary.resolve(strict=True);out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    began=time.monotonic();started=datetime.now(timezone.utc).isoformat();timed_out=False
    try:
        result=subprocess.run([str(binary),'--'+args.mode],capture_output=True,timeout=6,env=dict(os.environ,CARGO_BUILD_JOBS='2'))
        stdout,stderr,code=result.stdout,result.stderr,result.returncode
    except subprocess.TimeoutExpired as error:
        # subprocess.run kills/reaps the owned direct probe. Its controlled worker
        # child also has a fixed 3-second self-exit bound; no arbitrary external PID is killed.
        timed_out=True;stdout=error.stdout or b'';stderr=error.stderr or b'';code=None
    record=dict(schema_version='mdd.runtime-probe-record.v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),seconds=time.monotonic()-began,command=[str(binary),'--'+args.mode],binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),exit_code=code,timed_out=timed_out,measurement_scope='bounded correctness conformance; no performance or private input',stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_sha256=hashlib.sha256(stderr).hexdigest())
    (out/'stdout.txt').write_bytes(stdout);(out/'stderr.txt').write_bytes(stderr);(out/'record.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8',newline='\n')
    if timed_out or code!=0:raise SystemExit(1)
    json.loads(stdout)
    print(json.dumps({'record':str(out/'record.json'),'exit_code':code,'seconds':record['seconds']}))


if __name__=='__main__':main()
