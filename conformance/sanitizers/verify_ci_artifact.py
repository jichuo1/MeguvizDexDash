#!/usr/bin/env python3
"""Read the immutable Linux CI artifact, including ASan positive control and actual counters."""
from pathlib import Path
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]
RUN = 40692557250
SHA = 'b29933d489d945b91f8becf62d34af6b69288978'
ZIP_SHA = '0322c81be925db13e30aab81f7919cb3b191bb260cd6e95e84462f9e7788c473'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    path = ROOT / f'artifacts/conformance/parser-safety/ci-{RUN}.zip'
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == ZIP_SHA, 'GitHub archive digest differs')
    with zipfile.ZipFile(path) as archive:
        summary = json.loads(archive.read('summary.json'))
        require(summary['status'] == 'bounded-smoke-passed' and not summary['private_inputs'], 'CI scope/status differs')
        runs = summary['runs']
        require(len(runs) == 11, 'missing actual commands')
        targets = []
        for run in runs:
            name = run['name']
            record = json.loads(archive.read(name + '/record.json'))
            require(not record['timed_out'], 'hard timeout: ' + name)
            for stream in ['stdout', 'stderr']:
                raw = archive.read(name + '/' + stream + '.txt')
                require(hashlib.sha256(raw).hexdigest() == record[stream + '_sha256'], 'raw output changed: ' + name)
            error = archive.read(name + '/stderr.txt')
            if name == 'asan-detection-control':
                require(record['exit_code'] != 0 and b'ERROR: AddressSanitizer: heap-buffer-overflow' in error,
                        'real ASan positive control absent')
                require('-Zsanitizer=address' in record['rustflags'], 'control is not instrumented')
                continue
            require(record['exit_code'] == 0, 'nonzero command: ' + name)
            if not name.startswith('fuzz-'):
                continue
            text = error.decode('utf-8', errors='strict')
            units = re.findall(r'stat::number_of_executed_units:\s*(\d+)', text)
            counters = re.findall(r'cov:\s*(\d+)\s+ft:\s*(\d+)', text)
            require(units and counters, 'missing libFuzzer metrics: ' + name)
            require(int(units[-1]) == run['executions'] > 0 and
                    tuple(map(int, counters[-1])) == (run['coverage_counters'], run['features']),
                    'summary/log metrics disagree: ' + name)
            require(run['crash_files'] == 0 and not any(name.startswith('crashes/' + run['name'][5:] + '/')
                    and not name.endswith('/') for name in archive.namelist()), 'crash artifacts present')
            targets.append({key: run[key] for key in ['name', 'executions', 'coverage_counters',
                            'initial_coverage_counters', 'features', 'seed', 'crash_files']})
        require(len(targets) == 6, 'missing target')
        child = [json.loads(line) for line in archive.read('cargo-child-commands.jsonl').splitlines()]
        require(child, 'child compiler invocations absent')
        for invocation in child:
            args = invocation['args']
            cargo_args = args[:args.index('--')] if '--' in args else args
            if cargo_args[0] in ['build', 'check', 'fetch', 'metadata', 'run', 'test']:
                require('--locked' in cargo_args or '--frozen' in cargo_args, 'child compiler was not locked')
    report = dict(schema_version='mdd.parser-safety-ci-readback.v1', head_sha=SHA, run_id=RUN,
                  run_url=f'https://github.com/jichuo1/MeguvizDexDash/actions/runs/{RUN}',
                  artifact_id=12817673629, artifact_bytes=len(data), artifact_sha256=ZIP_SHA,
                  archive=path.relative_to(ROOT).as_posix(), status='bounded-rust-asan-fuzz-passed',
                  positive_control='actual nonzero heap-buffer-overflow diagnostic under ASan',
                  targets=targets, total_fuzzer_executions=sum(run['executions'] for run in targets),
                  actual_locked_child_compiler_calls=len(child), coverage_percent=None,
                  limitations=['finite six-target smoke, no proof of complete format/absence of UB',
                               'no SQLite/FFI UBSan or TSan', 'no AXML/ARSC/QueryIR/paging/cancel fuzz',
                               'does not grant full G1, MDD-026, HostLab, performance or release qualification'])
    output = ROOT / 'artifacts/conformance/parser-safety/ci-readback.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(status=report['status'], total_executions=report['total_fuzzer_executions'],
                          targets=6, locked_child_compiler_calls=len(child))))


if __name__ == '__main__':
    main()
