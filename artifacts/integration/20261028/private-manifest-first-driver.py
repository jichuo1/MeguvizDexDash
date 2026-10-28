#!/usr/bin/env python3
"""Bounded full Manifest-tree comparisons on the two already authorized inputs."""
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import os
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    checks = load('private_checks', 'conformance/corpus/inspect_private_inputs.py')
    job = load('private_job', 'artifacts/mdd-005/preparation-20261028/windows_job.py')
    oracle = load('manifest_oracle', 'artifacts/mdd-025/manifest/run_validation.py')
    native, aapt = oracle.NATIVE, oracle.AAPT
    require = checks.require
    require(native.is_file() and aapt.is_file(), 'actual native/AAPT2 binary missing')
    identities = dict(native=checks.identity(native), aapt2=checks.identity(aapt))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'artifacts/local/private-manifest' / stamp
    out.mkdir(parents=True, exist_ok=False)
    receipt = dict(schema_version='mdd.private-manifest-comparison.v1', run=stamp, binaries=identities,
                   measurement_scope='bounded development comparison; not full HostLab or performance',
                   results=[], full_audit_complete=False, formal_performance_qualified=False)
    public = ROOT / 'artifacts/integration/20261028' / ('private-manifest-' + stamp + '.json')
    source = json.loads((ROOT / 'artifacts/bootstrap/20261028/private-input-acquisition.json').read_text())
    failed = False
    for sample in source['inputs']:
        record = dict(input_id=sample['id'], status='running')
        try:
            path = Path(sample['actual_path']).resolve(strict=True)
            before = path.stat()
            expected = dict(bytes=sample['bytes'], sha256=sample['sha256'])
            require(checks.identity(path) == expected, 'input changed')
            commands = [('native', [str(native), str(path), sample['sha256']]),
                        ('aapt2', [str(aapt), 'dump', 'xmltree', '--file', 'AndroidManifest.xml', str(path)])]
            jobs = {}
            for name, argv in commands:
                directory = out / (sample['id'] + '-' + name)
                result = job.run_job(argv, directory, cwd=ROOT, env=dict(os.environ), timeout_seconds=180,
                                     memory_bytes=1024**3, affinity_mask=1, max_processes=1,
                                     max_log_bytes=4 * 1024**2)
                jobs[name] = dict(status=result['status'], tree_empty=result['tree_empty_verified'],
                                  peak_job_commit_bytes=result.get('peak_job_commit_bytes'),
                                  stdout=checks.identity(directory / 'stdout.txt'),
                                  raw_directory=directory.relative_to(ROOT).as_posix())
                require(result['status'] == 'completed' and result['tree_empty_verified'], 'bounded child failed: ' + name)
            document = json.loads((out / (sample['id'] + '-native') / 'stdout.txt').read_bytes())
            require(document['operation_status'] == 'ok' and document['calculation_complete']
                    and not document['full_audit_complete'] and document['manifest_occurrences'] == 1,
                    'not one complete Manifest scope')
            require(document['input_content_id'] == 'sha256:' + sample['sha256'], 'wrong source generation')
            require(document['manifests'][0]['source_byte_lease_shared'], 'Manifest lost immutable raw byte lease')
            tree = oracle.compare_public(document, (out / (sample['id'] + '-aapt2') / 'stdout.txt').read_text(encoding='utf-8'), path)
            require(checks.identity(path) == expected and path.stat().st_mtime_ns == before.st_mtime_ns, 'input changed during comparison')
            require(checks.identity(native) == identities['native'] and checks.identity(aapt) == identities['aapt2'], 'binary changed')
            record.update(status='passed-full-manifest-tree', input=expected, comparison=tree, jobs=jobs)
        except Exception as error:
            failed = True
            (out / (sample['id'] + '-failure.txt')).write_text(traceback.format_exc(), encoding='utf-8')
            record.update(status='failed', error_type=type(error).__name__,
                          diagnostic=(out / (sample['id'] + '-failure.txt')).relative_to(ROOT).as_posix())
        receipt['results'].append(record)
        receipt['status'] = 'failed' if failed else 'passed-required-manifest-scope'
        public.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(receipt=public.relative_to(ROOT).as_posix(), results=receipt['results'])))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
