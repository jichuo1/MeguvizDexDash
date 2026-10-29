#!/usr/bin/env python3
"""Run the probe in an owned bounded Windows Job and retain the original output."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/local/between-independent-20261029-target'


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('build2', 'build3', 'probe', 'probe2'):
        raise ValueError('expected build2, build3, probe or probe2')
    name = sys.argv[1]
    cargo = shutil.which('cargo')
    if not cargo:
        raise RuntimeError('cargo unavailable')
    argv = ([cargo, 'build', '--locked', '--offline', '--jobs', '1', '--manifest-path', str(HERE/'Cargo.toml')]
            if name.startswith('build') else [str(TARGET/'debug/mdd-between-independent.exe')])
    timeout = 180 if name.startswith('build') else 60
    helper = ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py'
    spec = importlib.util.spec_from_file_location('substring_job', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = HERE/name
    started = datetime.now(timezone.utc).isoformat()
    job = module.run_job(argv, directory, cwd=ROOT, env=dict(os.environ,CARGO_TARGET_DIR=str(TARGET)),
                         timeout_seconds=timeout, memory_bytes=2*1024**3, affinity_mask=15, max_processes=16)
    rec = {'argv':argv,'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),
           'exit_code':job['exit_code'],'job_status':job['status'],
           'timed_out':job['reason']=='timeout','tree_empty_verified':job['tree_empty_verified'],
           'stdout_sha256':hashlib.sha256((directory/'stdout.txt').read_bytes()).hexdigest(),
           'stderr_sha256':hashlib.sha256((directory/'stderr.txt').read_bytes()).hexdigest(),
           'supervisor_sha256':hashlib.sha256((directory/'supervisor.json').read_bytes()).hexdigest(),
           'scope':'independent synthetic validation; not performance qualification'}
    (directory/'record.json').write_text(json.dumps(rec,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps({'record':str(directory/'record.json'),'exit_code':rec['exit_code'],'tree_empty_verified':rec['tree_empty_verified']}))
    return 0 if rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
