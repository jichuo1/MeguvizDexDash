#!/usr/bin/env python3
"""Combine executed MDD-025 component evidence without admitting a product profile."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import gzip
import json

ROOT = Path(__file__).resolve().parents[2]


def read(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(relative):
    data = (ROOT / relative).read_bytes()
    return dict(path=relative, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    base = 'artifacts/mdd-025/raw-fingerprints/'
    commands = ['final-unit', 'final-clippy', 'final-format-fixed', 'public-newpipe', 'public-class-recipes',
                'final-example-build', 'final-public']
    for name in commands:
        record = read(base + name + '/record.json')
        require(record['exit_code'] == 0, 'failed command: ' + name)
        for stream in ['stdout', 'stderr']:
            actual = identity(base + name + '/' + stream + '.txt')
            require(all(actual[key] == record[stream][key] for key in ['bytes', 'sha256']),
                    'changed command output: ' + name)
    manifest_path = 'artifacts/mdd-025/manifest/qualification.json'
    manifest = read(manifest_path)
    require(manifest['production_source_frozen'], 'Manifest source not frozen')
    for source in manifest['sources']:
        require(identity(source['path']) == source, 'Manifest source differs: ' + source['path'])
    validation = manifest['validation']
    require(validation['failed'] == validation['ignored'] == 0, 'Manifest tests incomplete')
    require(validation['public_full_tree']['equal'] and validation['fixed_A0_summary']['all_fields_equal']
            and validation['fixed_A0_summary']['terminal_page_consumed']
            and validation['fixed_A0_summary']['dataset_closed'], 'Manifest oracle not fully consumed')
    raw_path = base + 'independent-public/comparison.json'
    raw = read(raw_path)
    require(raw['all_byte_projections_equal'] and raw['raw_resource_equal'], 'raw evidence differs')
    require(raw['native_summary_sha256'] == identity(base + 'public-newpipe/stdout.txt')['sha256'],
            'raw comparison source changed')
    recipe_path = base + 'legacy-class-recipes/comparison.json'
    recipe = read(recipe_path)
    require(all(check['equal'] for check in recipe['checks']), 'legacy class recipe differs')
    require(recipe['native_summary_sha256'] == identity(base + 'public-class-recipes/stdout.txt')['sha256'],
            'recipe comparison source changed')
    archive_path = base + 'legacy-class-recipes/reference-stdout.txt.archive.json'
    archive = read(archive_path)
    require(identity(archive['archive']['path']) == archive['archive'], 'raw stdout archive changed')
    with gzip.open(ROOT / archive['archive']['path'], 'rb') as stream:
        digest, length = hashlib.sha256(), 0
        while block := stream.read(1024 * 1024):
            digest.update(block)
            length += len(block)
    require(length == archive['original']['bytes'] and digest.hexdigest() == archive['original']['sha256'],
            'raw stdout archive is not lossless')
    native = read(base + 'public-class-recipes/stdout.txt')
    require(native['calculation_complete'] and not native['full_audit_complete'], 'wrong native completion scope')
    final = read(base + 'final-public/stdout.txt')
    require(final['calculation_complete'] and not final['full_audit_complete'], 'final run incomplete')
    require(final['input_content_id'] == native['input_content_id']
            and final['resource_fingerprints'] == native['resource_fingerprints'], 'final resources changed')
    keys = ['content_id', 'method_count', 'class_count', 'canonical_method_evidence_sha256',
            'legacy_class_recipe_sha256']
    require([{key: item[key] for key in keys} for item in final['selected_dexes']]
            == [{key: item[key] for key in keys} for item in native['selected_dexes']],
            'final full method/class projection changed')
    sources = ['crates/mdd-facts/src/raw_fingerprints.rs',
               'crates/mdd-facts/examples/raw_evidence_summary.rs',
               'tests/fixtures/raw_fingerprints/expected.json',
               'conformance/resources/compare_raw_evidence.py',
               'conformance/resources/compare_legacy_class_recipes.py',
               'conformance/resources/qualify_raw_evidence.py', 'Cargo.lock']
    result = dict(schema_version='mdd.raw-evidence-conformance.v1', task='MDD-025',
                  created_utc=datetime.now(timezone.utc).isoformat(),
                  status='passed-required-component-scope',
                  sources=[identity(path) for path in sources],
                  actual_binary=identity('target/debug/examples/raw_evidence_summary.exe'),
                  final_run=identity(base + 'final-public/record.json'),
                  evidence=[identity(path) for path in [manifest_path, raw_path, recipe_path, archive_path]],
                  validation=dict(raw_unit_tests=4, raw_tests_failed=0, manifest_vectors=manifest['fixtures'],
                                  method_rows=raw['complete_method_rows'], resource_entries=raw['resource_entries'],
                                  class_recipes=sum(item['class_count'] for item in recipe['checks']),
                                  independent_oracles=['handwritten bytes plus Python SHA-256',
                                                       'fixed A0 raw ranges plus Python ZIP bytes',
                                                       'unchanged frozen HostLab resource and class recipe',
                                                       'AAPT2 complete trees and fixed A0 Manifest pages']),
                  semantics=dict(no_body='None; present empty insns retain Some(empty) and SHA-256(empty)',
                                 resource_bytes='exact decompressed physical member, CRC checked',
                                 manifest='same immutable Arc as resource evidence',
                                 source_mutation='capture then rewrite/rename/drop owner actual test passed',
                                 class_order='explicit caller recipe; business ordering outside core',
                                 bad_input='error, never empty success'),
                  not_qualified=['full ART verification', 'private full HostLab workflow',
                                 'MCP/SQL/QueryIR integration', 'MDD-072 ARSC and full resource tools',
                                 'performance', 'product profiles', 'this checkpoint Linux until CI readback'],
                  rollback='Revert only the review branch implementation commit; preserve original handoff and failure evidence. No default/backend/deployment switch occurred.')
    output = ROOT / 'artifacts/mdd-025/raw-evidence-conformance.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result['validation'], ensure_ascii=False))


if __name__ == '__main__':
    main()
