#!/usr/bin/env python3
"""Read back four completed local certificates without exporting private audit data."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / 'artifacts/local/baseline-runs'
DRIVER = ROOT / 'artifacts/mdd-005/preparation-20261028/baseline_driver.py'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    spec = importlib.util.spec_from_file_location('baseline_driver', DRIVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = []
    for sample in ('9161100', '9170100'):
        certs = []
        for variant in ('A0', 'A1'):
            name = f'qualification-20261029-{variant.lower()}-{sample}'
            directory = LOCAL / name
            receipt_path = directory / 'qualification-receipt.json'
            supervisor_path = directory / 'job/supervisor.json'
            certificate_path = directory / 'worker/certificate.json'
            evidence_path = directory / 'worker/evidence.json'
            receipt, supervisor, cert = map(read, (receipt_path, supervisor_path, certificate_path))
            require(receipt['complete'] is True and receipt['formal_performance_qualified'] is False,
                    f'{name}: incomplete receipt')
            require(supervisor['status'] == 'completed' and supervisor['exit_code'] == 0
                    and supervisor['tree_empty_verified'] is True and supervisor['assigned_before_resume'] is True,
                    f'{name}: incomplete supervisor')
            require(cert['variant'] == variant and cert['complete'] is True
                    and cert['fallback_count'] == 0 and cert['evidence_group_count'] == 20
                    and cert['feature_count'] == 27 and cert['output_fully_materialized'] is True
                    and cert['more_available'] is False and cert['truncated'] is False,
                    f'{name}: incomplete certificate')
            require(digest(evidence_path) == cert['evidence_sha256']
                    and module.canonical_groups(module.read(evidence_path)) == cert['groups'],
                    f'{name}: complete local evidence readback differs')
            certs.append(cert)
            records.append({
                'variant': variant, 'sample': sample,
                'input_sha256': cert['input_sha256'], 'engine_sha256': cert['engine_sha256'],
                'reference_source_commit': cert['reference_source_commit'],
                'receipt_sha256': digest(receipt_path), 'supervisor_sha256': digest(supervisor_path),
                'certificate_sha256': digest(certificate_path), 'complete_evidence_sha256': cert['evidence_sha256'],
                'business_exit_code': cert['business_exit_code'], 'feature_count': cert['feature_count'],
                'evidence_group_count': cert['evidence_group_count'],
                'zero_fallback': True, 'complete_output': True,
                'job_tree_empty_verified': True,
                'raw_local_directory': str(directory.relative_to(ROOT)).replace('\\', '/'),
            })
        actual = module.compare_certificates(*certs)
        saved = read(LOCAL / f'comparison-20261029-{sample}.json')
        require(actual == saved and actual['all_equal'] is True and actual['group_count'] == 20,
                f'{sample}: stored comparison differs or fails')
    report = {
        'schema_version': 'mdd.static-baseline-readback.v1', 'task': 'MDD-005',
        'captured_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'four_complete_static_qualifications_two_equal_pairs', 'runs': records,
        'comparisons': [{'sample': sample, 'all_20_groups_equal': True,
                         'local_comparison_sha256': digest(LOCAL / f'comparison-20261029-{sample}.json')}
                        for sample in ('9161100', '9170100')],
        'scope': 'A0/A1 complete fixed HostLab static consumer only; private raw outputs stay local',
        'resource_window': 'project agents paused; OS and unrelated applications were not isolated',
        'performance_qualified': False, 'formal_performance_runs': 0,
        'not_qualified': ['A2 full transport', 'MeguvizDexDash substitution',
                          'formal paired performance and MDD-082', 'device or runtime behavior'],
        'driver_sha256': digest(DRIVER),
    }
    output = ROOT / 'artifacts/mdd-005/static-qualification-20261029.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'runs': len(records), 'equal_pairs': 2, 'performance_qualified': False}))


if __name__ == '__main__':
    main()
