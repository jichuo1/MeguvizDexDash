#!/usr/bin/env python3
"""Bounded header/inventory development checks; never a full audit or benchmark."""
from datetime import datetime, timezone
from pathlib import Path
import ctypes
import hashlib
import importlib.util
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def identity(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return dict(bytes=path.stat().st_size, sha256=h.hexdigest())


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
                ('total', ctypes.c_ulonglong), ('available', ctypes.c_ulonglong),
                ('page_total', ctypes.c_ulonglong), ('page_available', ctypes.c_ulonglong),
                ('virtual_total', ctypes.c_ulonglong), ('virtual_available', ctypes.c_ulonglong),
                ('extended', ctypes.c_ulonglong)]


def main():
    require(os.name == 'nt', 'Windows Job containment required')
    module_path = ROOT / 'artifacts/mdd-005/preparation-20261028/windows_job.py'
    spec = importlib.util.spec_from_file_location('owned_job', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    binary = ROOT / 'target/debug/meguvizdexdash.exe'
    require(binary.is_file(), 'actual CLI absent')
    binary_id = identity(binary)
    version = subprocess.run([str(binary), 'version'], capture_output=True, check=True, timeout=10)
    build = json.loads(version.stdout)
    source = json.loads((ROOT / 'artifacts/bootstrap/20261028/private-input-acquisition.json').read_text())
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'artifacts/local/private-header-inspection' / stamp
    out.mkdir(parents=True, exist_ok=False)
    receipt = dict(schema_version='mdd.private-header-inspection.v1', run=stamp,
                   measurement_scope='development; owned job; not performance or full audit',
                   binary=dict(path=str(binary), **binary_id, version=build),
                   supervisor_source=identity(module_path), results=[], formal_performance_qualified=False,
                   full_audit_complete=False)
    for sample in source['inputs']:
        memory = Memory()
        memory.length = ctypes.sizeof(memory)
        require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'cannot measure available RAM')
        require(memory.available >= 3 * 1024**3, 'less than 3 GiB free for bounded 2 GiB development job')
        path = Path(sample['actual_path']).resolve(strict=True)
        before = path.stat()
        expected = dict(bytes=sample['bytes'], sha256=sample['sha256'])
        require(identity(path) == expected, 'authorized input identity changed')
        job_dir = out / sample['id']
        job = module.run_job([str(binary), 'inspect-apk', str(path)], job_dir, cwd=ROOT,
                             env=dict(os.environ), timeout_seconds=180, memory_bytes=2 * 1024**3,
                             affinity_mask=1, max_processes=1, max_log_bytes=16 * 1024**2)
        require(job['tree_empty_verified'], 'owned job cleanup not verified')
        require(job['status'] == 'completed', 'header inspection failed; original output retained: ' + str(job_dir))
        result = json.loads((job_dir / 'stdout.txt').read_bytes())
        require(result['operation'] == 'inspect_dex_headers' and result['operation_status'] == 'ok', 'wrong scope/status')
        require(result['coverage']['required_layers'] == ['inventory', 'dex_header'], 'scope expanded unexpectedly')
        require(result['coverage']['input'] == result['coverage']['facts'] == 'complete'
                and result['execution']['complete'] and not result['response']['truncated']
                and not result['response']['more_available'] and result['response']['next_cursor'] is None,
                'not a complete requested header result')
        rows = result['data']['rows']
        require(len(rows) == len(sample['dex_members']), 'selected DEX occurrence count differs')
        require(identity(path) == expected and path.stat().st_mtime_ns == before.st_mtime_ns, 'input changed during run')
        require(identity(binary) == binary_id, 'binary changed during run')
        receipt['results'].append(dict(input_id=sample['id'], input=expected, dex_headers=len(rows),
                                       available_physical_bytes=str(memory.available),
                                       header_versions=sorted({row['header']['version'] for row in rows}),
                                       snapshot_id=result['snapshot_id'], requested_scope_complete=True,
                                       stdout=identity(job_dir / 'stdout.txt'),
                                       private_raw_directory=job_dir.relative_to(ROOT).as_posix(),
                                       job_status=job['status'], job_tree_empty=job['tree_empty_verified'],
                                       peak_job_commit_bytes=job['peak_job_commit_bytes']))
    receipt['status'] = 'passed-header-inventory-scope-only'
    public = ROOT / 'artifacts/integration/20261028' / ('private-headers-' + stamp + '.json')
    public.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(receipt=str(public.relative_to(ROOT)), results=receipt['results']), ensure_ascii=False))


if __name__ == '__main__':
    main()
