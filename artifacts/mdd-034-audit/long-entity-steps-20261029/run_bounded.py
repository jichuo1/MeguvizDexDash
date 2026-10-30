#!/usr/bin/env python3
"""Admit each synthetic build/probe separately; never start below the registered 3 GiB window."""
import ctypes
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
MINIMUM=3*1024**3


class Memory(ctypes.Structure):
    _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(x,ctypes.c_uint64) for x in
        ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    start=datetime.now(timezone.utc);folder=HERE/'runs'/start.strftime('%Y%m%dT%H%M%S%fZ');folder.mkdir(parents=True,exist_ok=False)
    paths=['Cargo.lock','crates/mdd-query/src/budget.rs','crates/mdd-query/src/executor.rs',
           'crates/mdd-query/src/ir/mod.rs','crates/mdd-query/src/executor/runtime_tests.rs',
           'artifacts/mdd-034-audit/long-entity-steps-20261029/probe.rs']
    sources={p:digest(ROOT/p) for p in paths}
    report={'schema_version':'mdd.long-entity-steps-admission.v1','created_utc':start.isoformat(),
            'status':'starting','minimum_available_bytes':str(MINIMUM),'sources_before':sources,
            'build_started':False,'compile_started':False,'probe_started':False,
            'profile_admitted':False,'task_complete_proven':False,
            'scope':'synthetic provider; read-only evidence on current source, no private input or performance claim'}
    output=folder/'admission.json'
    def save():output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
    def admit(stage):
        mem=Memory();mem.length=ctypes.sizeof(mem)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):raise RuntimeError('memory observation failed')
        report['memory_'+stage]={'available_bytes':str(mem.available),'required_bytes':str(MINIMUM)}
        if mem.available<MINIMUM:
            report['status']='blocked_by_resource_window';report['blocked_stage']=stage;save();return False
        return True
    if not admit('build'):
        print(json.dumps({'path':output.relative_to(ROOT).as_posix(),'status':report['status'],'build_started':False}));return 2
    path=ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py'
    spec=importlib.util.spec_from_file_location('bounded_owned_job',path);job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)
    env={k:v for k,v in os.environ.items() if not re.search(r'TOKEN|SECRET|PASSWORD|API_KEY',k,re.I)}
    env['CARGO_BUILD_JOBS']='1';cargo=shutil.which('cargo');rustc=shutil.which('rustc')
    if not cargo or not rustc:raise RuntimeError('Rust tools unavailable')
    report['build_started']=True;save()
    build=job.run_job([cargo,'build','-p','mdd-query','--lib','--locked','--offline','--jobs','1','--message-format=json'],folder/'build',
        cwd=ROOT,env=env,timeout_seconds=180,memory_bytes=2*1024**3,affinity_mask=15,max_processes=16,max_log_bytes=8*1024**2)
    report['build']=build;save()
    if build['status']!='completed' or not build['tree_empty_verified']:report['status']='build_failed';save();return 1
    libraries={}
    for line in (folder/'build/stdout.txt').read_bytes().splitlines():
        item=json.loads(line)
        if item.get('reason')=='compiler-artifact':
            files=[p for p in item.get('filenames',[]) if p.endswith('.rlib')]
            if len(files)==1:libraries[item['target']['name']]=files[0]
    names=['mdd_dex','mdd_facts','mdd_input','mdd_query','mdd_session','mdd_types','serde_json']
    if not all(name in libraries for name in names):raise RuntimeError('missing Cargo artifact')
    if not admit('compile'):
        print(json.dumps({'path':output.relative_to(ROOT).as_posix(),'status':report['status'],'compile_started':False}));return 2
    local=ROOT/'artifacts/local/long-entity-steps'/start.strftime('%Y%m%dT%H%M%S%fZ');local.mkdir(parents=True,exist_ok=False)
    binary=local/'probe.exe';argv=[rustc,'--edition=2024','--crate-name','mdd_long_entity_steps',str(HERE/'probe.rs'),
        '-L','dependency=target/debug/deps','-o',str(binary)]
    for name in names:argv+=['--extern',name+'='+libraries[name]]
    report['compile_started']=True;save()
    compiled=job.run_job(argv,folder/'compile',cwd=ROOT,env=env,timeout_seconds=120,memory_bytes=2*1024**3,affinity_mask=15,max_processes=16,max_log_bytes=4*1024**2)
    report['compile']=compiled;save()
    if compiled['status']!='completed' or not compiled['tree_empty_verified']:report['status']='compile_failed';save();return 1
    report['binary_sha256']=digest(binary)
    if not admit('probe'):
        print(json.dumps({'path':output.relative_to(ROOT).as_posix(),'status':report['status'],'probe_started':False}));return 2
    report['probe_started']=True;save()
    probe=job.run_job([str(binary)],folder/'probe',cwd=ROOT,env=env,timeout_seconds=30,memory_bytes=2*1024**3,affinity_mask=15,max_processes=4,max_log_bytes=4*1024**2)
    report['probe']=probe;report['sources_after']={p:digest(ROOT/p) for p in paths}
    report['sources_unchanged']=report['sources_before']==report['sources_after']
    report['status']='completed_observation' if probe['status']=='completed' and probe['tree_empty_verified'] and report['sources_unchanged'] else 'probe_failed_or_source_changed'
    save();print(json.dumps({'path':output.relative_to(ROOT).as_posix(),'status':report['status'],'probe_started':True}))
    return 0 if report['status']=='completed_observation' else 1


if __name__=='__main__':raise SystemExit(main())
