#!/usr/bin/env python3
"""Recheck complete captured producer outputs; never reinterpret failed deliveries as success."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import copy
import json
import runpy

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    datetime.strptime(args.run, '%Y%m%dT%H%M%S%fZ')
    helpers = runpy.run_path(str(ROOT / 'conformance/resources/private_manifest_comparison.py'))
    checks = helpers['load']('captured_checks', 'conformance/corpus/inspect_private_inputs.py')
    oracle = helpers['load']('captured_oracle', 'artifacts/mdd-025/manifest/run_validation.py')
    trees = helpers['load']('captured_trees', 'conformance/resources/compare_manifest_trees.py')
    require = checks.require
    parent_path = ROOT / 'artifacts/integration/20261028' / ('private-manifest-' + args.run + '.json')
    parent = json.loads(parent_path.read_text())
    require(checks.identity(oracle.NATIVE) == parent['binaries']['native']
            and checks.identity(oracle.AAPT) == parent['binaries']['aapt2'], 'captured binary identity changed')
    inputs = json.loads((ROOT / 'artifacts/bootstrap/20261028/private-input-acquisition.json').read_text())['inputs']
    require(len(parent['results']) == len(inputs) == 2, 'authorized/captured input coverage differs')
    results = []
    negative_checks = 0
    for sample in inputs:
        record = next(item for item in parent['results'] if item['input_id'] == sample['id'])
        path = Path(sample['actual_path']).resolve(strict=True)
        expected = dict(bytes=sample['bytes'], sha256=sample['sha256'])
        require(checks.identity(path) == expected, 'input identity changed')
        streams = {}
        for name in ['native', 'aapt2']:
            job = record['jobs'][name]
            require(job['status'] == 'completed' and job['tree_empty'] and job['reason'] is None,
                    'failed/cancelled/truncated capture cannot be reused')
            raw_path = (ROOT / job['raw_directory'] / 'stdout.txt').resolve(strict=True)
            require(raw_path.is_relative_to(ROOT / 'artifacts/local'), 'capture path escaped private artifacts')
            require(checks.identity(raw_path) == job['stdout'], 'captured stdout changed')
            streams[name] = raw_path.read_bytes()
        native = json.loads(streams['native'])
        require(native['calculation_complete'] and not native['full_audit_complete']
                and native['operation_status'] == 'ok' and native['manifest_occurrences'] == 1
                and native['input_content_id'] == 'sha256:' + sample['sha256']
                and native['manifests'][0]['source_byte_lease_shared'], 'captured native scope incomplete')
        comparison = trees.compare(native, streams['aapt2'].decode('utf-8'), path, oracle)
        # Independent raw-attribute checks must reject a forged native bit pattern.
        altered = copy.deepcopy(native)
        attribute = next(node['attributes'][0] for node in altered['manifests'][0]['document']['nodes'] if node['attributes'])
        attribute['value']['raw_data'] ^= 1
        rejected = False
        try:
            trees.compare(altered, streams['aapt2'].decode('utf-8'), path, oracle)
        except RuntimeError:
            rejected = True
        require(rejected, 'changed raw typed bits were accepted')
        negative_checks += 1
        require(checks.identity(path) == expected, 'input changed during verification')
        results.append(dict(input_id=sample['id'], input=expected, comparison=comparison,
                            status='passed-captured-full-manifest-tree'))
    source_paths = ['conformance/resources/verify_captured_private_manifests.py',
                    'conformance/resources/compare_manifest_trees.py',
                    'artifacts/mdd-025/manifest/run_validation.py']
    report = dict(schema_version='mdd.captured-private-manifest-readback.v1',
                  captured_run=args.run, parent=dict(path=parent_path.relative_to(ROOT).as_posix(), **checks.identity(parent_path)),
                  sources=[dict(path=p, **checks.identity(ROOT / p)) for p in source_paths],
                  results=results, negative_raw_bit_checks=negative_checks,
                  status='passed-full-manifest-tree-and-raw-types', full_audit_complete=False,
                  formal_performance_qualified=False, previous_failed_deliveries_retained=True)
    output = ROOT / 'artifacts/integration/20261028/private-manifest-captured-conformance.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), results=results, negative_checks=negative_checks)))


if __name__ == '__main__':
    main()
