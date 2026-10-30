#!/usr/bin/env python3
"""Read-only recheck of the bounded JSON count/Base64 prototype observation."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SNAP=ROOT/'handoff/concat-3c334c5-20261029'


def require(ok,why):
    if not ok: raise ValueError(why)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before=json.loads((HERE/'source-before.json').read_text(encoding='utf8'))
    after=json.loads((HERE/'source-after.json').read_text(encoding='utf8'))
    snapref=ROOT/'artifacts/mdd-031-audit/concat-independent-20261029/snapshot-before.json'
    snapshot=json.loads(snapref.read_text(encoding='utf8'))
    require(before['base_commit']=='3c334c5d365126268dd0d5488ab33c4d2dd23173'
            and before['snapshot_sources']==94 and after['all_snapshot_equal'] and after['all_probe_files_equal']
            and before['snapshot_before_sha256']==sha(snapref) and after['source_before_sha256']==sha(HERE/'source-before.json'),
            'snapshot receipt')
    for name,digest in snapshot['files_sha256'].items(): require(sha(SNAP/name)==digest,'snapshot drift '+name)
    for name,digest in before['probe_files_sha256'].items(): require(sha(HERE/name)==digest,'probe drift '+name)
    require(sha(HERE/'run_small_probe.py')==after['small_probe_runner_sha256'],'small runner drift')
    def external(path):
        return {(p['name'],p['version'],p.get('checksum')) for p in tomllib.loads(path.read_text(encoding='utf8'))['package'] if p.get('source')}
    require(len(external(HERE/'Cargo.lock'))==33 and external(HERE/'Cargo.lock')<=external(SNAP/'Cargo.lock'),'lock differs')
    for phase in ('build','probe'):
        p=HERE/phase; rec=json.loads((p/'record.json').read_text(encoding='utf8'))
        require(rec['exit_code']==0 and not rec['timed_out'] and rec['tree_empty_verified'],phase+' terminal')
        for stream in ('stdout','stderr'): require(sha(p/(stream+'.txt'))==rec[stream+'_sha256'],phase+' stream')
        require(sha(p/'supervisor.json')==rec['supervisor_sha256'],phase+' supervisor')
    admission=json.loads((HERE/'probe-admission.json').read_text(encoding='utf8'))
    rec=json.loads((HERE/'probe/record.json').read_text(encoding='utf8'))
    require(sha(HERE/'probe-admission.json')==rec['admission_sha256'] and admission['admitted']
            and int(admission['available_physical_bytes'])>=int(admission['job_cap_bytes'])+int(admission['minimum_remaining_bytes'])
            and int(admission['job_cap_bytes'])==64*1024**2 and int(admission['minimum_remaining_bytes'])==512*1024**2,
            'low-memory admission')
    job=json.loads((HERE/'probe/supervisor.json').read_text(encoding='utf8'))
    require(job['limits']['memory_commit_bytes']==str(64*1024**2) and job['limits']['timeout_seconds']==15
            and job['assigned_before_resume'] and job['tree_empty_verified'],'probe limits')
    x=json.loads((HERE/'probe/stdout.txt').read_text(encoding='utf8'))
    require(not x['profile_admitted'] and len(x['cases'])==12 and [c['case'] for c in x['cases']]==list(range(12)),
            'case denominator')
    require(x['exact_length']==398 and x['limit_completed']==397 and x['limit_class']=='output_limit'
            and x['overflow_class']=='overflow' and x['cancel_class']=='cancelled'
            and x['real_serializer_error']=='synthetic encoding failure','failure classification')
    require(x['large_encoded_bytes']==133365 and x['old_peak_bytes']==262144 and x['new_peak_bytes']==0,
            'allocator observation changed')
    binary=ROOT/'artifacts/local/json-count-prototype-20261029-target/debug/mdd-json-count-prototype.exe'
    require(sha(binary)==after['binary_sha256'],'binary drift')
    registry=Path('C:/Users/Administrator/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.151/src')
    for name,digest in after['serde_json_writer_and_value_source_sha256'].items():
        require(sha(registry/name)==digest,'serde source drift '+name)
    writer=(registry/'ser.rs').read_text(encoding='utf8'); value=(registry/'value/ser.rs').read_text(encoding='utf8')
    require('format_escaped_str_contents(self.writer, self.formatter, s)' in writer
            and 'Ok(Value::String(value.to_string()))' in value,'serde serializer behavior changed')
    print(json.dumps({'status':'passed-prototype-only','json_byte_equal_cases':12,'exact_length':398,
                      'quota_stopped_after':397,'error_classes':['output_limit','overflow','cancelled','real_serializer_error'],
                      'measured_bytes_input':100000,'old_peak_allocated':262144,'streaming_peak_allocated':0,
                      'encoded_bytes':133365,'available_before_bytes':admission['available_physical_bytes'],
                      'job_peak_commit_bytes':job['peak_job_commit_bytes'],'snapshot_sources':94,
                      'old_value_sha256':snapshot['files_sha256']['crates/mdd-query/src/ir/mod.rs'],
                      'source_before_after_equal':True,'binary_sha256':sha(binary),'profiles_admitted':False,
                      'scope':'single-thread locked serde_json writer prototype; not production implementation or performance',
                      'limitations':['tracked allocations are only those made while test flag is enabled, not RSS',
                                     'serde_json Value serializer allocates; other serializers are unqualified',
                                     'quota/cancellation were injected writer sentinels, not live RuntimeBudget',
                                     'aborted count is partial and not an exact full encoded length',
                                     'provider construction, SQLite, allocator overhead and transport remain separate']}))


if __name__=='__main__': main()
