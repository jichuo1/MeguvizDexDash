#!/usr/bin/env python3
"""Record a bounded local build or independent probe without overwriting evidence."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('build', 'probe'):
        raise SystemExit('expected build or probe')
    name = sys.argv[1]
    folder = HERE / name
    target = ROOT / 'artifacts/local/like-independent-20261029-target'
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    cargo = shutil.which('cargo')
    if not cargo:
        raise RuntimeError('cargo unavailable')
    argv = ([cargo, 'build', '--locked', '--offline', '--jobs', '1', '--manifest-path', str(HERE / 'Cargo.toml')]
            if name == 'build' else [str(target / 'debug/mdd-like-workspace-extras.exe')])
    timeout = 180 if name == 'build' else 30
    started = datetime.now(timezone.utc).isoformat()
    helper = ROOT / 'artifacts/mdd-005/preparation-20261028/windows_job.py'
    spec = importlib.util.spec_from_file_location('owned_job', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    job = module.run_job(argv, folder, cwd=ROOT, env=env, timeout_seconds=timeout,
                         memory_bytes=2 * 1024**3, affinity_mask=15, max_processes=16)
    stdout, stderr = (folder / 'stdout.txt').read_bytes(), (folder / 'stderr.txt').read_bytes()
    code, timed_out = job['exit_code'], job['reason'] == 'timeout'
    rec = {'argv':argv, 'started_utc':started, 'finished_utc':datetime.now(timezone.utc).isoformat(),
           'exit_code':code, 'timed_out':timed_out, 'timeout_seconds':timeout,
           'stdout_sha256':hashlib.sha256(stdout).hexdigest(), 'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
           'job_status':job['status'], 'tree_empty_verified':job['tree_empty_verified'],
           'supervisor_sha256':hashlib.sha256((folder / 'supervisor.json').read_bytes()).hexdigest(),
           'scope':'local independent test, no formal performance'}
    (folder / 'record.json').write_text(json.dumps(rec, indent=2) + '\n', encoding='utf8', newline='\n')
    print(json.dumps({'record':str(folder / 'record.json'), 'exit_code':code, 'timed_out':timed_out}))
    return 0 if code == 0 and not timed_out and job['tree_empty_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
