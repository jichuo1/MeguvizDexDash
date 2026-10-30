#!/usr/bin/env python3
"""Independent real queue probe; never starts below the existing 3 GiB admission."""
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
TARGET=ROOT/'artifacts/local/streaming-json-independent-20261029-target'


class Memory(ctypes.Structure):
    _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(name,ctypes.c_uint64)
       for name in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('build4','probe4'): raise ValueError('expected build4 or probe4')
    phase=sys.argv[1];memory=Memory();memory.length=ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)): raise RuntimeError('cannot measure memory')
    minimum=3*1024**3; admission={'captured_utc':datetime.now(timezone.utc).isoformat(),
       'available_physical_bytes':str(memory.available),'minimum_bytes':str(minimum),'admitted':memory.available>=minimum,
       'scope':'existing 3 GiB independent Row admission unchanged; not performance'}
    ap=HERE/(phase+'-admission.json');ap.write_text(json.dumps(admission,indent=2)+'\n',encoding='utf8',newline='\n')
    if not admission['admitted']:
        print(json.dumps({'status':'blocked_by_memory','phase':phase,**admission}));return 2
    cargo=shutil.which('cargo')
    if not cargo: raise RuntimeError('cargo unavailable')
    argv=([cargo,'build','--locked','--offline','--jobs','1','--manifest-path',str(HERE/'Cargo.toml')]
          if phase.startswith('build') else [str(TARGET/'debug/mdd-streaming-json-independent.exe')])
    helper=ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py';spec=importlib.util.spec_from_file_location('stream_job',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    folder=HERE/phase;started=datetime.now(timezone.utc).isoformat();job=module.run_job(argv,folder,cwd=ROOT,env=dict(os.environ,CARGO_TARGET_DIR=str(TARGET)),timeout_seconds=180 if phase.startswith('build') else 90,memory_bytes=2*1024**3,affinity_mask=15,max_processes=16 if phase.startswith('build') else 1,max_log_bytes=8*1024**2)
    rec={'argv':argv,'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'exit_code':job['exit_code'],
         'timed_out':job['reason']=='timeout','tree_empty_verified':job['tree_empty_verified'],'job_status':job['status'],
         'admission_sha256':hashlib.sha256(ap.read_bytes()).hexdigest(),
         'stdout_sha256':hashlib.sha256((folder/'stdout.txt').read_bytes()).hexdigest(),
         'stderr_sha256':hashlib.sha256((folder/'stderr.txt').read_bytes()).hexdigest(),
         'supervisor_sha256':hashlib.sha256((folder/'supervisor.json').read_bytes()).hexdigest(),
         'scope':'independent static development check; no performance qualification'}
    (folder/'record.json').write_text(json.dumps(rec,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'phase':phase,'exit_code':rec['exit_code'],'tree_empty_verified':rec['tree_empty_verified'],
                      'available_physical_bytes':admission['available_physical_bytes']}))
    return 0 if rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'] else 1


if __name__=='__main__': raise SystemExit(main())
