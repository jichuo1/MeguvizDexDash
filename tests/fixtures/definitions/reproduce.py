"""Reproduce fixture bytes in memory without replacing any committed evidence."""
from pathlib import Path
import hashlib
import importlib.util
import json

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('mdd_definition_fixture_encoder', HERE / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = json.loads((HERE / 'manifest.json').read_text())
    records = []
    for item in manifest['files']:
        current = (HERE / item['path']).read_bytes()
        reproduced, layout = module.build(item['id'])
        digest = hashlib.sha256(reproduced).hexdigest()
        if current != reproduced or digest != item['sha256'] or len(reproduced) != item['bytes'] or layout != item['layout']:
            raise ValueError('definition fixture is not reproducible: ' + item['id'])
        records.append({'id': item['id'], 'bytes': len(reproduced), 'sha256': digest})
    print(json.dumps({'schema_version': 'mdd.definition-fixture-reproduction.v1', 'complete': True, 'fixtures': records,
                      'generator_sha256': hashlib.sha256((HERE / 'generate.py').read_bytes()).hexdigest(),
                      'limits': 'byte reproduction only; no ART runtime or engine compatibility qualification'}, indent=2))


if __name__ == '__main__':
    main()
