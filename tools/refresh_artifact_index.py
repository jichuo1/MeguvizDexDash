#!/usr/bin/env python3
"""Index actual development evidence bytes without granting qualifications."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    path = ROOT/'artifacts/index.json'
    index = json.loads(path.read_text(encoding='utf-8'))
    prior_paths = {item['path'] for item in index.get('development_records', [])}
    tasks = json.loads((ROOT/'tasks/backlog.json').read_text(encoding='utf-8'))['tasks']
    task_status = {task['id'].lower():task['status'] for task in tasks}
    records = []
    for candidate in sorted((ROOT/'artifacts').rglob('*')):
        if not candidate.is_file() or candidate == path or 'local' in candidate.parts:
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
