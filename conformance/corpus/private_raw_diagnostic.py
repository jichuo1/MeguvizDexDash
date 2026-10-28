#!/usr/bin/env python3
"""Read fixed authorized APKs with a bounded binary built from an accepted immutable checkpoint."""
from datetime import datetime, timezone
from pathlib import Path
import ctypes
import json
import os
import runpy
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
COMMIT = 'e56db3e9380a60b117e9e65ec5ab3f76ffb61361'


def main():
    checks = runpy.run_path(str(ROOT / 'conformance/corpus/inspect_private_inputs.py'))
    require, identity, Memory = checks['require'], checks['identity'], checks['Memory']
    loader = runpy.run_path(str(ROOT / 'conformance/resources/private_manifest_comparison.py'))['load']
    supervisor = loader('raw_diagnostic_job', 'artifacts/mdd-005/preparation-20261028/windows_job.py')
    frozen = ROOT / 'handoff/checkpoint-030'
    git = ['git', '-c', 'safe.directory=' + str(ROOT)]
    paths = subprocess.run(git + ['ls-tree', '-r', '--name-only', COMMIT, '--', 'crates', 'Cargo.toml',
                                  'Cargo.lock', 'rust-toolchain.toml'], cwd=ROOT, capture_output=True, check=True).stdout.decode().splitlines()
    verified = 0
    for relative in paths:
        # Documentation is not part of the compiler source identity.
        if relative.startswith('crates/') and not relative.endswith(('.rs', '.toml')):
            continue
        original = subprocess.run(git + ['show', COMMIT + ':' + relative], cwd=ROOT, capture_output=True, check=True).stdout
        require((frozen / relative).read_bytes() == original, 'materialized compiler source differs: ' + relative)
        verified += 1
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'artifacts/local/private-raw-diagnostic' / stamp
    out.mkdir(parents=True, exist_ok=False)
    public = ROOT / 'artifacts/integration/20261028' / ('private-raw-diagnostic-' + stamp + '.json')
    report = dict(schema_version='mdd.private-raw-diagnostic.v1', source_commit=COMMIT,
                  materialized_source=frozen.relative_to(ROOT).as_posix(), source_files_verified=verified,
                  measurement_scope='bounded static input diagnosis; no full workflow or performance qualification',
                  results=[], status='running', full_audit_complete=False, formal_performance_qualified=False)

    def save():
        public.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')

    def memory_admit():
        memory = Memory()
        memory.length = ctypes.sizeof(memory)
        require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'cannot measure RAM')
        report['last_available_physical_bytes'] = str(memory.available)
        report['minimum_development_available_bytes'] = str(4 * 1024**3)
        require(memory.available >= 4 * 1024**3, 'below 4 GiB available for this bounded development task')
        return memory.available

    try:
        report['available_physical_before_build'] = str(memory_admit())
        cargo = shutil.which('cargo')
        require(cargo is not None, 'cargo absent')
        env = dict(os.environ, CARGO_BUILD_JOBS='2')
        built = supervisor.run_job([cargo, 'build', '--locked', '--offline', '--release', '-p', 'mdd-facts',
                                   '--example', 'raw_evidence_summary'], out / 'build', cwd=frozen, env=env,
                                  timeout_seconds=300, memory_bytes=2 * 1024**3, affinity_mask=15, max_processes=16)
        report['build'] = built
        save()
        require(built['status'] == 'completed' and built['tree_empty_verified'], 'bounded checkpoint build failed')
        binary = frozen / 'target/release/examples/raw_evidence_summary.exe'
        binary_id = identity(binary)
        report['binary'] = dict(path=str(binary), **binary_id)
        inputs = json.loads((ROOT / 'artifacts/bootstrap/20261028/private-input-acquisition.json').read_text())['inputs']
        failed = False
        for sample in inputs:
            record = dict(input_id=sample['id'], available_physical_before=str(memory_admit()))
            path = Path(sample['actual_path']).resolve(strict=True)
            before = path.stat()
            expected = dict(bytes=sample['bytes'], sha256=sample['sha256'])
            require(identity(path) == expected, 'input identity changed')
            result = supervisor.run_job([str(binary), str(path), sample['sha256']], out / sample['id'], cwd=frozen,
                                        env=dict(os.environ), timeout_seconds=600, memory_bytes=3 * 1024**3,
                                        affinity_mask=1, max_processes=1, max_log_bytes=32 * 1024**2)
            record.update(input=expected, job=result, private_raw_directory=(out / sample['id']).relative_to(ROOT).as_posix())
            if result['status'] == 'completed' and result['tree_empty_verified']:
                raw_path = out / sample['id'] / 'stdout.txt'
                data = json.loads(raw_path.read_bytes())
                require(data['operation_status'] == 'ok' and data['calculation_complete']
                        and not data['full_audit_complete'] and data['input_content_id'] == 'sha256:' + sample['sha256'],
                        'native result scope or identity differs')
                require(len(data['selected_dexes']) == len(sample['dex_members']), 'DEX coverage differs')
                record.update(status='native-raw-calculation-complete', stdout=identity(raw_path),
                              dex_occurrences=len(data['selected_dexes']),
                              method_records=sum(dex['method_count'] for dex in data['selected_dexes']),
                              class_records=sum(dex['class_count'] for dex in data['selected_dexes']),
                              resource_fingerprints=len(data['resource_fingerprints']))
            else:
                failed = True
                record['status'] = 'failed-native-raw-diagnosis'
            require(identity(path) == expected and path.stat().st_mtime_ns == before.st_mtime_ns, 'input changed during run')
            require(identity(binary) == binary_id, 'binary changed during run')
            report['results'].append(record)
            report['status'] = 'partial-or-failed' if failed else 'native-raw-calculation-complete-not-audit'
            save()
        print(json.dumps(dict(receipt=public.relative_to(ROOT).as_posix(), status=report['status'],
                              results=[{k: v for k, v in item.items() if k != 'job'} for item in report['results']])))
        return int(failed)
    except Exception as error:
        report['status'] = 'blocked-or-failed'
        report['failure'] = dict(type=type(error).__name__, reason=str(error))
        save()
        raise


if __name__ == '__main__':
    raise SystemExit(main())
