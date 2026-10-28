#!/usr/bin/env python3
"""Capture non-secret local build identities and locked dependency licenses."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def command(args):
    p = subprocess.run(args, cwd=ROOT, capture_output=True, check=False)
    return {'command': args, 'exit_code': p.returncode,
            'stdout': p.stdout.decode('utf-8', errors='replace'),
            'stderr': p.stderr.decode('utf-8', errors='replace')}


def save(name, value):
    path = ROOT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')


def main():
    environment = {
        'schema_version': 'mdd.environment.v1',
        'captured_utc': datetime.now(timezone.utc).isoformat(),
        'user_timezone': 'Asia/Shanghai',
        'os': platform.platform(), 'machine': platform.machine(),
        'cpu_logical_count': os.cpu_count(),
        'memory_limits': None,
        'memory_limits_reason': 'not measured; logical CPU count is not an assigned CPU quota',
        'python': {'executable': sys.executable, 'version': sys.version},
        'tools': [command(args) for args in [
            ['rustc', '-Vv'], ['cargo', '-V'], ['rustup', 'show'],
            ['git', '--version'],
            ['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD'],
        ]],
        'build_scope': 'Windows x86_64 native only; Linux runtime pending',
        'historical_input_archive': {
            'name': 'MeguvizDexDash_Engineering_Kit_20261026.zip',
            'sha256': 'b5f2f3859a5a7753f83f8edc24c73ce15781075afb899e4e63b274fdcc161844',
        },
        'execution_issue': 'Windows isolated helper failed to start; authorized local commands ran with reviewed execution override',
    }
    save('artifacts/bootstrap/20261028/environment.json', environment)
    metadata_run = command(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'])
    if metadata_run['exit_code']:
        raise RuntimeError(metadata_run['stderr'])
    metadata = json.loads(metadata_run['stdout'])
    features = {n['id']: n['features'] for n in metadata['resolve']['nodes']}
    dependencies = []
    for package in metadata['packages']:
        if not package['source']:
            continue
        manifest = Path(package['manifest_path'])
        dependencies.append({
            'name': package['name'], 'version': package['version'],
            'source': package['source'], 'repository': package['repository'],
            'license': package['license'], 'license_file': package['license_file'],
            'features': features[package['id']],
            'cached_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'license_review': 'declared SPDX expression recorded; distribution notices must accompany a release',
        })
    save('conformance/manifests/dependencies.json', {
        'schema_version': 'mdd.dependencies.v1',
        'rust': '1.99.0', 'msrv': '1.99',
        'lock_sha256': hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest(),
        'approved_direct_dependencies': ['serde', 'serde_json', 'sha2', 'sha1', 'zip', 'rusqlite', 'getrandom', 'quick-xml'],
        'platform_validation': {'windows_x86_64': 'native build probe passed', 'linux_x86_64': 'prior checkpoint CI passed; this lock requires its own CI'},
        'sqlite_profile': 'bundled; no load_extension; vtab/functions/collation/hooks/limits',
        'zip_profile': 'no default features; DEFLATE zlib-rs only',
        'xml_profile': 'quick-xml 0.42.0; no default features; bounded synchronous text XML; DTD prohibited',
        'packages': sorted(dependencies, key=lambda x: x['name']),
        'project_distribution_license': 'not selected; private development repository only',
    })
    dev_names = ['attrs','jsonschema','jsonschema-specifications','referencing','rpds-py','typing-extensions']
    (ROOT/'requirements-dev.lock').write_text(''.join(
        f'{name}=={importlib.metadata.version(name)}\n' for name in dev_names), encoding='utf-8', newline='\n')
    print(f'captured environment and {len(dependencies)} locked dependency license declarations')


if __name__ == '__main__':
    main()
