#!/usr/bin/env python3
"""Index actual development evidence bytes without granting qualifications."""
import hashlib
import json
import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-index', action='store_true', help='Index exact staged Git blobs for a coherent checkpoint')
    args = parser.parse_args()
    path = ROOT/'artifacts/index.json'
    index = json.loads(path.read_text(encoding='utf-8'))
    prior_paths = {item['path'] for item in index.get('development_records', [])}
    tasks = json.loads((ROOT/'tasks/backlog.json').read_text(encoding='utf-8'))['tasks']
    task_status = {task['id'].lower():task['status'] for task in tasks}
    records = []
    if args.from_index:
        listing = subprocess.run(['git','-c','safe.directory='+str(ROOT),'ls-files','--stage','-z','--','artifacts'],cwd=ROOT,check=True,capture_output=True).stdout
        entries = []
        for entry in listing.split(b'\0'):
            if not entry: continue
            attributes, name = entry.split(b'\t',1)
            _, object_id, stage = attributes.split()
            relative = name.decode('utf-8')
            if stage != b'0': raise ValueError('unmerged artifact in index: '+relative)
            if relative == 'artifacts/index.json' or relative.startswith('artifacts/local/'): continue
            if Path(relative).suffix.lower() in ['.exe','.dll','.pdb','.obj','.lib']: continue
            entries.append((relative,object_id))
        objects = subprocess.run(['git','-c','safe.directory='+str(ROOT),'cat-file','--batch'],cwd=ROOT,input=b''.join(oid+b'\n' for _,oid in entries),check=True,capture_output=True).stdout
        position = 0
        for relative, _ in entries:
            newline = objects.index(b'\n',position)
            header = objects[position:newline].split()
            if len(header)!=3 or header[1]!=b'blob': raise ValueError('artifact is not a blob')
            size=int(header[2]); start=newline+1; data=objects[start:start+size]
            if len(data)!=size or objects[start+size:start+size+1]!=b'\n': raise ValueError('invalid object stream')
            position=start+size+1
            records.append({'path':relative,'bytes':size,'sha256':hashlib.sha256(data).hexdigest()})
    for candidate in ([] if args.from_index else sorted((ROOT/'artifacts').rglob('*'))):
        if not candidate.is_file() or candidate == path or candidate.is_relative_to(ROOT/'artifacts/local'):
            continue
        if candidate.suffix.lower() in ['.exe', '.dll', '.pdb', '.obj', '.lib']:
            continue
        relative = candidate.relative_to(ROOT).as_posix()
        task_directory = candidate.relative_to(ROOT).parts[1] if len(candidate.relative_to(ROOT).parts) > 1 else ''
        if task_directory in task_status and task_status[task_directory] not in ['done','blocked'] and relative not in prior_paths:
            continue
        data = candidate.read_bytes()
        records.append({'path':relative,
                        'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()})
    index['implementation_state'] = 'in_progress'
    index['development_records'] = records
    index['note'] = 'Actual development records; no HostLab, full-format or performance qualification is implied.'
    path.write_text(json.dumps(index, ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(f'Indexed {len(records)} actual artifact files; qualifications unchanged')


if __name__ == '__main__':
    main()
