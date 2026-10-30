#!/usr/bin/env python3
"""Build and run the synthetic allocation probe from one recorded Cargo build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


def require(ok,message):
    if not ok:raise RuntimeError(message)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['red','red2','green','green-final'],required=True)
    args=parser.parse_args();build=HERE/(args.phase+'-build')
    rec=json.loads((build/'record.json').read_bytes());raw=(build/'stdout.txt').read_bytes()
    require(rec['exit_code']==0 and hashlib.sha256(raw).hexdigest()==rec['stdout']['sha256'],'Cargo build evidence differs')
    libraries={}
    for line in raw.splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact':
            files=[p for p in item.get('filenames',[]) if p.endswith('.rlib')]
            if len(files)==1:libraries[item['target']['name']]=files[0]
    names=['mdd_dex','mdd_facts','mdd_input','mdd_query','mdd_session','mdd_types','serde_json']
    require(all(name in libraries for name in names),'missing Cargo artifact')
    local=ROOT/'artifacts/local/streaming-json-20261029';local.mkdir(parents=True,exist_ok=True)
    binary=local/(args.phase+'-probe.exe')
    command=['rustc','--edition=2024','--crate-name','mdd_streaming_json_probe',str(HERE/'probe.rs'),
             '-L','dependency=target/debug/deps','-o',str(binary)]
    for name in names:command+=['--extern',name+'='+libraries[name]]
    for label,argv in [('compile',command),('run',[str(binary)])]:
        wrapper=[sys.executable,'-O','tools/record_command.py','--quiet','--output',str(HERE/(args.phase+'-'+label)),'--',*argv]
        proc=subprocess.run(wrapper,cwd=ROOT,capture_output=True,timeout=60)
        sys.stdout.buffer.write(proc.stdout);sys.stderr.buffer.write(proc.stderr)
        require(proc.returncode==0,label+' failed; raw record retained')
    print(json.dumps({'phase':args.phase,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))


if __name__=='__main__':main()
