#!/usr/bin/env python3
"""Run the small prototype only with 512 MiB headroom plus a 64 MiB Job cap."""
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent


class Memory(ctypes.Structure):
    _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(name,ctypes.c_uint64)
        for name in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]


def main():
    memory=Memory();memory.length=ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise RuntimeError('cannot measure available memory')
    cap=64*1024**2; margin=512*1024**2; accepted=memory.available>=cap+margin
    admission={'captured_utc':datetime.now(timezone.utc).isoformat(),'available_physical_bytes':str(memory.available),
               'job_cap_bytes':str(cap),'minimum_remaining_bytes':str(margin),'admitted':accepted,
               'scope':'100k-byte single-thread local prototype; unrelated 3GiB admission unchanged'}
    (HERE/'probe-admission.json').write_text(json.dumps(admission,indent=2)+'\n',encoding='utf8',newline='\n')
    if not accepted:
        print(json.dumps(admission));return 2
    helper=ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py'
    spec=importlib.util.spec_from_file_location('small_prototype_job',helper); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    executable=ROOT/'artifacts/local/json-count-prototype-20261029-target/debug/mdd-json-count-prototype.exe'
    folder=HERE/'probe'; started=datetime.now(timezone.utc).isoformat()
    result=module.run_job([str(executable)],folder,cwd=ROOT,env=dict(os.environ),timeout_seconds=15,
                          memory_bytes=cap,affinity_mask=1,max_processes=1,max_log_bytes=1024*1024)
    record={'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),
            'exit_code':result['exit_code'],'timed_out':result['reason']=='timeout','job_status':result['status'],
            'tree_empty_verified':result['tree_empty_verified'],'admission_sha256':hashlib.sha256((HERE/'probe-admission.json').read_bytes()).hexdigest(),
            'stdout_sha256':hashlib.sha256((folder/'stdout.txt').read_bytes()).hexdigest(),
            'stderr_sha256':hashlib.sha256((folder/'stderr.txt').read_bytes()).hexdigest(),
            'supervisor_sha256':hashlib.sha256((folder/'supervisor.json').read_bytes()).hexdigest(),
            'scope':'small synthetic prototype; not performance qualification'}
    (folder/'record.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'admission':admission,'exit_code':record['exit_code'],'tree_empty_verified':record['tree_empty_verified']}))
    return 0 if record['exit_code']==0 and not record['timed_out'] and record['tree_empty_verified'] else 1


if __name__=='__main__': raise SystemExit(main())
