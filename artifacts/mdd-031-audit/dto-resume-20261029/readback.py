#!/usr/bin/env python3
"""Read-only verification of SQLite receipt and preexisting typed reference records."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OLD = ROOT / 'artifacts/mdd-031-audit/dto-type-observations'
REF = ROOT / 'artifacts/mdd-031-audit/integer-cast-observations/run-20261028T174032300709Z'
ORIGIN = ROOT / 'artifacts/mdd-031/dto-origin-20261029/observation.json'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read(p):
    return json.loads(p.read_text(encoding='utf-8'))


def main():
    record = read(HERE / 'run/record.json')
    result = read(HERE / 'sqlite-corrected.json')
    require(record['exit_code'] == 0 and result['status'] == 'sqlite-only-passed', 'SQLite command failed')
    for stream in ('stdout', 'stderr'):
        require(sha(HERE / ('run/' + stream + '.txt')) == record[stream]['sha256'], 'command stream changed')
    require(sha(HERE / 'verify_sqlite_literals.py') == result['source_sha256']['this_script'], 'probe source changed')
    require(sha(OLD / 'reference.py') == result['source_sha256']['reference_source']
            and sha(OLD / 'sqlite-literals.json') == result['source_sha256']['previous_sqlite_observation']
            and sha(ORIGIN) == result['source_sha256']['dto_origin'], 'prior evidence changed')
    require(len(result['records']) == 6 and all(row['rows'] for row in result['records'])
            and result['dto_equivalent'] is False and result['profile_admitted'] is False,
            'SQLite cases missing or overclaimed')
    origin = read(ORIGIN)
    summary = read(REF / 'summary.json')
    require(sha(REF / 'summary.json') == origin['source_sha256']['reference_summary'], 'reference summary changed')
    observed = {}
    for entry in summary['records']:
        engine, kind = entry['variant'], entry['kind']
        path = REF / (engine + '-' + kind) / (engine + '.observations.json')
        data = read(path)
        require(sha(path) == entry['observations_sha256'] and len(data['cases']) == entry['cases'], 'reference identity/count')
        end = data['active_dataset_after_all_cases']['body']
        require(data['client_context_exited'] is True and end['datasets'] == []
                and end['running_requests'] == 0 and end['admitted_requests'] == 0
                and end['usage']['datasets'] == 0 and end['usage']['input_bytes'] == 0,
                'reference terminal not complete')
        require(all(c['close']['body']['closed'] is True for c in data['cases']), 'reference dataset was not closed')
        observed[(engine, kind)] = data
    require(set(observed) == {(v, k) for v in ('A0', 'A1') for k in ('literals', 'dex')}, 'reference denominator')
    for engine in ('A0', 'A1'):
        examples = {x['id']: x for x in origin['examples'] if x['engine'] == engine}
        for kind, case_id in (('literals', 'empty'), ('dex', 'string_0'), ('literals', 'null')):
            case = next(c for c in observed[(engine, kind)]['cases'] if c['id'] == case_id)
            statement = case['statements'][0]['response']['body']['statements'][0]
            require(statement['total_rows'] == 1 and statement['next_offset'] is None
                    and statement['truncated'] is False and statement['rows'][0][0] == examples[case_id]['reference_cell'],
                    'reference cell or delivery differs')
        null = examples['null']
        require('value' in null['reference_cell'] and null['reference_cell']['value'] is None
                and 'value' not in null['candidate_cell'], 'NULL distinction lost')
    for stamp in ('run-20261028T175409892480Z', 'run-20261028T175454131286Z'):
        path = OLD / stamp / 'A0.observations.json'
        data = read(path)
        transcript = OLD / stamp / 'A0.sdk-transcript.jsonl'
        events = [json.loads(line) for line in transcript.read_text(encoding='utf-8').splitlines()]
        require(data['cases'] == [] and data['final'] is None and sha(transcript) == data['transcript_sha256']
                and len(events) == 2 and events[0]['tool'] == 'open_dataset'
                and events[1]['result']['body']['error']['kind'] == 'timeout', 'timeout evidence differs')
    print(json.dumps({'status': 'passed-readback-only', 'sqlite_cases': 6,
                      'old_reference_cases': 54, 'observed_dto_type_differences': 30,
                      'reference_timeouts_before_queries': 2, 'reference_engines_started': 0,
                      'dto_equivalent': False, 'profile_admitted': False}))


if __name__ == '__main__':
    main()
