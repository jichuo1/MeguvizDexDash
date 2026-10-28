#!/usr/bin/env python3
"""Check actual package dependency direction and lock resolution."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    process = subprocess.run(['cargo','metadata','--locked','--offline','--format-version','1'],
                             cwd=ROOT, check=True, capture_output=True)
    metadata = json.loads(process.stdout)
    errors = []
    members = set(metadata['workspace_members'])
    for package in metadata['packages']:
        if package['id'] not in members:
            continue
        path = Path(package['manifest_path']).resolve()
        if not path.is_relative_to(ROOT):
            errors.append('workspace member outside independent project: '+package['name'])
        if package['name'].startswith('mdd-') and package['name'] not in ['mdd-cli','mdd-build-probe']:
            for dependency in package['dependencies']:
                if dependency.get('path'):
                    target = Path(dependency['path']).resolve()
                    if not target.is_relative_to(ROOT/'crates') or dependency['name'] in ['mdd-cli','mdd-worker','mdd-mcp']:
                        errors.append('reverse/external core dependency: '+package['name']+' -> '+dependency['name'])
    if errors:
        raise ValueError('\n'.join(errors))
    print(f'Workspace boundary check passed: {len(members)} real packages, no external project/provider dependency')


if __name__ == '__main__':
    main()
