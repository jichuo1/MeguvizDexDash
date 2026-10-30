#!/usr/bin/env python3
"""Recheck bounded legacy CLI receipts without granting a compatibility profile."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    require(len(sys.argv) == 2, 'usage: readback.py RUN_NAME')
    run = (HERE / 'runs' / sys.argv[1]).resolve()
    require(run.parent == (HERE / 'runs').resolve(), 'invalid run name')
    report_path = run / 'report.json'
    report = json.loads(report_path.read_text(encoding='utf8'))
    require(report['status'] == 'observed_all' and report['identities_unchanged'], 'run incomplete')
    require(not report['profile_admitted'] and not report['task_complete_proven'], 'scope overstated')
    require(sha(HERE / 'run.py') == report['script_sha256'], 'runner changed')
    require(sha(ROOT / 'artifacts/mdd-005/preparation-20261028/windows_job.py') == report['supervisor_sha256'], 'supervisor changed')
    require(report['identities_before'] == report['identities_after'], 'identity drift')
    for name, item in report['identities_before'].items():
        require(item['matches'] and sha(Path(item['path'])) == item['sha256'] == item['expected_sha256'], name + ' identity')
    expected = {
        'concat_nul': {'result_type': 'text', 'result_hex': '41C0804243'},
        'concat_non_utf8': {'result_type': 'text', 'result_hex': 'EFBFBD41'},
        'dangling_like': {'result': '0'}, 'dangling_not_like': {'result': '1'},
        'escaped_literal': {'result': '1'}, 'null_like': {'result': 'NULL'},
    }
    seen = set()
    for item in report['cases']:
        key = (item['engine'], item['case'])
        require(key not in seen and key[0] in ('A0', 'A1') and key[1] in expected, 'unexpected case')
        seen.add(key)
        require(item['status'] == 'observed' and int(item['available_physical_bytes']) >= 3 * 1024 ** 3, str(key) + ' admission')
        folder = run / (key[0] + '-' + key[1])
        for name in ('stdout', 'stderr', 'supervisor'):
            suffix = '.json' if name == 'supervisor' else '.txt'
            require(sha(folder / (name + suffix)) == item[name + '_sha256'], str(key) + ' ' + name)
        job = json.loads((folder / 'supervisor.json').read_text(encoding='utf8'))
        require(job == item['job'] and job['status'] == 'completed' and job['exit_code'] == 0
                and job['tree_empty_verified'] and job['assigned_before_resume'], str(key) + ' job')
        require(job['limits']['memory_commit_bytes'] == str(2 * 1024 ** 3)
                and job['limits']['timeout_seconds'] == 90 and job['limits']['affinity_mask'] == '15', str(key) + ' limits')
        lines = [line for line in (folder / 'stdout.txt').read_text(encoding='utf8').splitlines() if line.startswith('|')]
        rows = [[cell.strip() for cell in line.strip('|').split('|')] for line in lines]
        columns = list(expected[key[1]])
        require(len(rows) == 2 and rows[0] == columns and len(rows[1]) == len(columns), str(key) + ' table shape')
        cells = dict(zip(columns, rows[1]))
        require(cells == expected[key[1]] and item['table'] == {'status': 'one_row', 'cells': cells}, str(key) + ' values')
    require(seen == {(engine, case) for engine in ('A0', 'A1') for case in expected}, 'matrix incomplete')
    result = {'status': 'passed_scoped_readback', 'cases': len(seen),
              'report_sha256': sha(report_path), 'runner_sha256': sha(HERE / 'run.py'),
              'readback_sha256': sha(Path(__file__)), 'observed_values': expected,
              'profile_admitted': False, 'task_complete_proven': False,
              'scope': 'fixed A0/A1 CLI observations on one synthetic DEX; not complete dialect or performance qualification'}
    (run / 'readback.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8', newline='\n')
    print(json.dumps({'status': result['status'], 'cases': result['cases']}))


if __name__ == '__main__':
    main()
