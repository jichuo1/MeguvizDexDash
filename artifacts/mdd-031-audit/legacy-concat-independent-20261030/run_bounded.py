#!/usr/bin/env python3
"""Build and run an independent bridge probe under the established Windows Job limits."""
import ctypes
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
TARGET=ROOT/'artifacts/local/legacy-concat-independent-20261030-target'
MINIMUM=3*1024**3
ENGINES={
    'A0':(Path(r'D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe'),'f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448'),
    'A1':(ROOT/'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe','602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'),
}

class Memory(ctypes.Structure):
    _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(name,ctypes.c_uint64)
       for name in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def engine_identities():
    return {name:{'path':str(path),'sha256':sha(path),'expected':expected,'matches':sha(path)==expected} for name,(path,expected) in ENGINES.items()}
def identities():
    files=[ROOT/'Cargo.lock',ROOT/'Cargo.toml',HERE/'Cargo.toml',HERE/'Cargo.lock',HERE/'src/main.rs',Path(__file__),
           ROOT/'rust-toolchain.toml',ROOT/'tests/fixtures/generated/strings-mutf8-035.dex',ROOT/'artifacts/mdd-031-audit/legacy-concat-matrix-20261030/runs/20261030T021302616646Z/readback.json',ROOT/'artifacts/mdd-031-audit/legacy-concat-matrix-20261030/runs/20261030T021302616646Z/report.json',
           ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py']
    files += [p for p in (ROOT/'crates').rglob('*') if p.is_file() and p.suffix in ('.rs','.toml')]
    return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(files)}

def available():
    state=Memory();state.length=ctypes.sizeof(state)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):raise RuntimeError('memory observation failed')
    return state.available

def main():
    run=HERE/'runs'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ');run.mkdir(parents=True,exist_ok=False)
    report={'status':'starting','source_before':identities(),'engine_before':engine_identities(),'minimum_available_bytes':str(MINIMUM),
       'build_started':False,'probe_started':False,'profile_admitted':False,'task_complete_proven':False,
       'scope':'synthetic DEX public bridge, fixed legacy CLI observations; not worker, corpus or performance qualification'}
    def save(): (run/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    def admit(name):
        seen=available();report['memory_'+name]={'available_bytes':str(seen),'minimum_bytes':str(MINIMUM)}
        if seen<MINIMUM: report['status']='blocked_by_resource_window';save();return False
        return True
    try:
        if not all(value['matches'] for value in report['engine_before'].values()):
            report['status']='blocked_engine_identity';return 2
        if not admit('build'):return 2
        cargo=shutil.which('cargo')
        if not cargo:raise RuntimeError('cargo unavailable')
        spec=importlib.util.spec_from_file_location('owned_job',ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py')
        job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)
        env={k:v for k,v in os.environ.items() if not re.search(r'TOKEN|SECRET|PASSWORD|API_KEY',k,re.I)}
        env['CARGO_TARGET_DIR']=str(TARGET);env['CARGO_BUILD_JOBS']='1'
        report['build_started']=True;save()
        build=job.run_job([cargo,'build','--locked','--offline','--jobs','1','--manifest-path',str(HERE/'Cargo.toml')],
           run/'build',cwd=ROOT,env=env,timeout_seconds=180,memory_bytes=2*1024**3,affinity_mask=15,max_processes=16,max_log_bytes=8*1024**2)
        report['build']=build;save()
        if build['status']!='completed' or build['exit_code']!=0 or not build['tree_empty_verified']:
            report['status']='build_failed';return 1
        if identities()!=report['source_before']:report['status']='source_changed_after_build';return 1
        binary=TARGET/'debug/mdd-concat-independent.exe';report['binary_sha256']=sha(binary)
        if not admit('probe'):return 2
        report['probe_started']=True;save()
        probe=job.run_job([str(binary)],run/'probe',cwd=ROOT,env=env,timeout_seconds=90,
           memory_bytes=2*1024**3,affinity_mask=15,max_processes=4,max_log_bytes=8*1024**2)
        report['probe']=probe;report['source_after']=identities();report['source_unchanged']=report['source_before']==report['source_after'];report['engine_after']=engine_identities()
        report['status']='completed_observation' if probe['status']=='completed' and probe['exit_code']==0 and probe['tree_empty_verified'] and report['source_unchanged'] and report['engine_before']==report['engine_after'] else 'probe_failed_or_source_changed'
        return 0 if report['status']=='completed_observation' else 1
    except Exception as error:
        report['status']='runner_error';report['error']=type(error).__name__+': '+str(error);return 1
    finally:
        save();print(json.dumps({'status':report['status'],'path':run.relative_to(ROOT).as_posix(),'probe_started':report['probe_started']}))

if __name__=='__main__':raise SystemExit(main())
