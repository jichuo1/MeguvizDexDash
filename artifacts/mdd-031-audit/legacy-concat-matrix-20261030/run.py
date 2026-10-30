#!/usr/bin/env python3
"""Record fixed legacy CLI observations; no compatibility qualification is implied."""
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
INPUT = ROOT / 'tests/fixtures/generated/strings-mutf8-035.dex'
INPUT_SHA = '4deab5f75b23c118b170005d89a6ebc0d18d894383280253e70de0507d260f35'
ENGINES = {
    'A0': (Path(r'D:\Bilibili_Innocent_Lab\tools\hostlab\vendor\dexsql\0.1.0\dexsql-windows-amd64.exe'),
           'f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448'),
    'A1': (ROOT / 'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe',
           '602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'),
}
CASES = [
    ('ascii', "SELECT typeof(x'41'||x'42') AS result_type,hex(x'41'||x'42') AS result_hex"),
    ('valid_utf8', "SELECT typeof(x'C3A9'||x'41') AS result_type,hex(x'C3A9'||x'41') AS result_hex"),
    ('split_utf8', "SELECT typeof(x'C3'||x'A9') AS result_type,hex(x'C3'||x'A9') AS result_hex"),
    ('split_supplementary', "SELECT typeof(x'F09F'||x'9880') AS result_type,hex(x'F09F'||x'9880') AS result_hex"),
    ('truncated_prefix', "SELECT typeof(x'E282'||x'41') AS result_type,hex(x'E282'||x'41') AS result_hex"),
    ('invalid_continuation', "SELECT typeof(x'C341'||x'42') AS result_type,hex(x'C341'||x'42') AS result_hex"),
    ('two_invalid', "SELECT typeof(x'FF'||x'FF') AS result_type,hex(x'FF'||x'FF') AS result_hex"),
    ('overlong_nul', "SELECT typeof(x'C080'||x'41') AS result_type,hex(x'C080'||x'41') AS result_hex"),
    ('blob_text', "SELECT typeof(x'41'||'B') AS result_type,hex(x'41'||'B') AS result_hex"),
    ('text_blob', "SELECT typeof('B'||x'41') AS result_type,hex('B'||x'41') AS result_hex"),
    ('blob_unicode_text', "SELECT typeof(x'41'||'中') AS result_type,hex(x'41'||'中') AS result_hex"),
    ('null_right', "SELECT typeof(x'41'||NULL) AS result_type,hex(x'41'||NULL) AS result_hex"),
    ('null_left', "SELECT typeof(NULL||x'41') AS result_type,hex(NULL||x'41') AS result_hex"),
    ('source_nul', "SELECT typeof(s.value||x'41') AS result_type,hex(s.value||x'41') AS result_hex FROM strings AS s WHERE s.string_idx=1"),
    ('source_surrogate', "SELECT typeof(s.value||x'41') AS result_type,hex(s.value||x'41') AS result_hex FROM strings AS s WHERE s.string_idx=4"),
    ('source_pair', "SELECT typeof(s.value||x'41') AS result_type,hex(s.value||x'41') AS result_hex FROM strings AS s WHERE s.string_idx=5"),
]

MINIMUM = 3 * 1024 ** 3


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in (
            'total', 'available', 'page_total', 'page_available',
            'virtual_total', 'virtual_available', 'extended')]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity():
    paths = {'fixture': (INPUT, INPUT_SHA), **ENGINES}
    return {name: {'path': str(path), 'sha256': sha(path), 'expected_sha256': expected,
                   'matches': sha(path) == expected} for name, (path, expected) in paths.items()}


def available():
    state = Memory()
    state.length = ctypes.sizeof(state)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
        raise RuntimeError('cannot observe physical memory')
    return state.available


def table(stdout, expected_columns):
    try:
        text = stdout.decode('utf8')
    except UnicodeDecodeError:
        return {'status': 'unparsed_non_utf8'}
    lines = [line for line in text.splitlines() if line.startswith('|')]
    rows = [[cell.strip() for cell in line.strip('|').split('|')] for line in lines]
    if len(rows) != 2 or rows[0] != expected_columns or len(rows[1]) != len(expected_columns):
        return {'status': 'unparsed_table', 'table_line_count': len(rows)}
    return {'status': 'one_row', 'cells': dict(zip(expected_columns, rows[1]))}


def main():
    if os.name != 'nt':
        raise RuntimeError('Windows Job supervision is required')
    run = HERE / 'runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    run.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 'mdd.legacy-sql-boundary-observation.v1',
              'status': 'starting', 'profile_admitted': False, 'task_complete_proven': False,
              'minimum_available_bytes': str(MINIMUM), 'cases': [],
              'scope': 'fixed legacy CLI on synthetic DEX; no complete dialect, transport, release or performance claim'}

    def save():
        (run / 'report.json').write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n',
                                         encoding='utf8', newline='\n')

    try:
        report['identities_before'] = identity()
        if not all(v['matches'] for v in report['identities_before'].values()):
            report['status'] = 'blocked_identity_mismatch'
            return 2
        helper = ROOT / 'artifacts/mdd-005/preparation-20261028/windows_job.py'
        report['supervisor_sha256'] = sha(helper)
        report['script_sha256'] = sha(Path(__file__))
        spec = importlib.util.spec_from_file_location('mdd_owned_job', helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        env = {key: value for key, value in os.environ.items()
               if not re.search(r'TOKEN|SECRET|PASSWORD|API_KEY', key, re.I)}
        stop = False
        for name, (binary, _) in ENGINES.items():
            for case, sql in CASES:
                item = {'engine': name, 'case': case, 'sql': sql, 'status': 'not_started'}
                report['cases'].append(item)
                if stop:
                    item['status'] = 'not_run_after_prior_failure'
                    continue
                memory = available()
                item['available_physical_bytes'] = str(memory)
                if memory < MINIMUM:
                    item['status'] = 'blocked_by_resource_window'
                    stop = True
                    save()
                    continue
                if not all(v['matches'] for v in identity().values()):
                    item['status'] = 'blocked_identity_changed'
                    stop = True
                    save()
                    continue
                folder = run / (name + '-' + case)
                item['status'] = 'starting'
                save()
                result = module.run_job(
                    [str(binary), '--threads', '1', 'query', '--input', str(INPUT), '--sql', sql],
                    folder, cwd=ROOT, env=env, timeout_seconds=90, memory_bytes=2 * 1024 ** 3,
                    affinity_mask=15, max_processes=16, max_log_bytes=8 * 1024 ** 2)
                item['job'] = result
                item['stdout_sha256'] = sha(folder / 'stdout.txt')
                item['stderr_sha256'] = sha(folder / 'stderr.txt')
                item['supervisor_sha256'] = sha(folder / 'supervisor.json')
                if result['status'] != 'completed' or result['exit_code'] != 0 or not result['tree_empty_verified']:
                    item['status'] = 'command_failed_or_incomplete'
                    stop = True
                else:
                    columns = ['result_type', 'result_hex']
                    item['table'] = table((folder / 'stdout.txt').read_bytes(), columns)
                    item['status'] = 'observed' if item['table']['status'] == 'one_row' else 'output_unparsed'
                    if item['status'] != 'observed':
                        stop = True
                save()
        report['identities_after'] = identity()
        report['identities_unchanged'] = report['identities_before'] == report['identities_after']
        report['status'] = 'observed_all' if not stop and report['identities_unchanged'] else 'partial_or_failed'
        return 0 if report['status'] == 'observed_all' else 1
    except Exception as error:
        report['status'] = 'runner_error'
        report['error'] = type(error).__name__ + ': ' + str(error)
        return 1
    finally:
        save()
        print(json.dumps({'status': report['status'], 'path': str(run.relative_to(ROOT)),
                          'cases_recorded': len(report['cases']), 'profile_admitted': False}))


if __name__ == '__main__':
    raise SystemExit(main())
