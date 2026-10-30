#!/usr/bin/env python3
"""Qualify executed MDD-034 mechanisms without claiming the later wire/runtime integration."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = 'artifacts/mdd-034/'


def read(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def identity(path):
    data = (ROOT / path).read_bytes()
    return dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command_record(name, probe=False):
    path = BASE + name + '/record.json'
    record = read(path)
    require(record['exit_code'] == 0 and not record.get('timed_out', False), 'failed gate: ' + name)
    for stream in ['stdout', 'stderr']:
        actual = identity(BASE + name + '/' + stream + '.txt')
        expected = record[stream + '_sha256'] if probe else record[stream]['sha256']
        require(actual['sha256'] == expected, 'changed raw stream: ' + name)
    return identity(path)


def main():
    evidence = [command_record(name) for name in ['root-final-units', 'root-final-clippy', 'root-final-runtime-build']]
    evidence += [command_record(name, True) for name in ['root-final-sqlite', 'root-final-supervisor']]
    text = (ROOT / (BASE + 'root-final-units/stdout.txt')).read_text(encoding='utf-8')
    counts = [int(value) for value in re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;', text)]
    require(counts == [27, 10, 7, 2, 0, 0], 'unit/doc gate counts differ')
    sql = read(BASE + 'root-final-sqlite/stdout.txt')
    require(sql['a_error'] == 'OperationInterrupted' and sql['b_sum'] == '20000100000'
            and sql['connection_reuse_values'] == [7, 7] and not sql['watchdog_fired'],
            'two-connection evidence incomplete')
    worker = read(BASE + 'root-final-supervisor/stdout.txt')
    end = worker['termination']
    require(end['cause'] == 'worker_deadline' and end['direct_child_reaped']
            and end['process_tree_isolated'] is False and len(end['affected_requests']) == 2,
            'actual worker evidence differs')
    require(worker['computing_query']['phase'] == worker['unconsumed_spool_query']['phase'] == 'failed'
            and worker['unconsumed_spool_query']['execution_complete']
            and not worker['unconsumed_spool_query']['delivery_complete']
            and worker['prior_complete_query']['phase'] == 'completed', 'unfinished worker scope was washed')
    before = read(BASE + 'root-counter-before-fix/record.json')
    require(before['exit_code'] != 0, 'counter regression must retain its actual prior failure')
    owned = ['crates/mdd-query/src/budget.rs', 'crates/mdd-query/src/budget/imports.rs',
             'crates/mdd-query/src/budget/imports/tests.rs', 'crates/mdd-query/src/budget/tests.rs',
             'crates/mdd-query/src/executor.rs', 'crates/mdd-query/src/executor/runtime_tests.rs',
             'crates/mdd-session/src/cancellation.rs', 'crates/mdd-session/src/lib.rs',
             'crates/mdd-types/src/result.rs', 'crates/mdd-types/src/lib.rs',
             'crates/mdd-input/src/archive/mod.rs', 'conformance/runtime/src/main.rs',
             'conformance/runtime/run_probe.py', 'conformance/runtime/Cargo.lock',
             'Cargo.lock', 'crates/mdd-query/Cargo.toml']
    head = subprocess.run(['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD'],
                          cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    report = dict(schema_version='mdd.budget-terminal-conformance.v1', task='MDD-034',
                  created_utc=datetime.now(timezone.utc).isoformat(),
                  status='passed-scoped-budget-cancel-terminal-mechanisms', checkout_head=head,
                  source_identity_observed_at_readback=True, sources=[identity(path) for path in owned],
                  binary=identity('conformance/runtime/target/debug/mdd-runtime-conformance.exe'),
                  validation=dict(query_tests=27, session_tests=10, types_tests=7, compile_fail_docs=2,
                                  strict_clippy='passed all targets for the three affected packages',
                                  sqlite_version=sql['sqlite_version'], two_live_connections=True,
                                  actual_owned_worker_deadline_ms=250, unfinished_queries_failed=2,
                                  process_tree_isolated=False), evidence=evidence,
                  mechanisms=['nineteen named resource dimensions; hierarchy only tightens limits',
                              'atomic parent reservations, absolute deadlines, bounded owner/ticket metadata',
                              'real allocation identity and retained owner charge once; descendants admit per object',
                              'capture and selected expansion admitted before allocation, native error codes retained',
                              'pending sends own memory; dequeue payload keeps its lease; producer EOF is not success',
                              'actual query/session/worker/manifest/epoch/plan/schema binding before one execution claim',
                              'partial rows followed by explicit error terminal; protocol faults stay failed',
                              'coverage, computation and delivery independently recorded',
                              'only three permitted fallback codes under explicit equivalence; never qualifying fallback'],
                  explicit_limits=['byte reservations are logical/conservative declared allocation bounds, not OS RSS',
                                   'borrowed shared objects use per-object admission, not a query aggregate resident claim',
                                   'owner/ticket metadata cap is 10000 for one budget tree lifetime',
                                   'legacy low-level reader APIs keep their own limits; use imports adapters for pooled operations',
                                   'trusted fact builders must honor supplied limits and declared workspace/ready upper bounds',
                                   'direct child deadline/reap demonstrated; process tree isolation remains false',
                                   'SQLite probe is connection-level; SQL bridge session runtime integration qualified separately',
                                   'public worker/MCP/FFI enforcement and cross-process consumption await later task gates',
                                   'current-source Linux execution pending immutable feature-branch CI'],
                  profiles_admitted=False, private_inputs=False, formal_performance_runs=0,
                  retained_failures=[BASE + 'root-counter-before-fix/record.json',
                                     BASE + 'root-four-boundaries/record.json',
                                     BASE + 'root-first-integrated-check/record.json',
                                     BASE + 'subagent-interruption.json'],
                  rollback='Scoped revert on review branch, keeping original handoff and failures; no default backend or deployment switched.')
    out = ROOT / (BASE + 'budget-and-terminal-states.json')
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(status=report['status'], tests=sum(counts), profiles_admitted=False)))


if __name__ == '__main__':
    main()
