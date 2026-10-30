#!/usr/bin/env python3
"""Read back a blocked independent probe without converting it to a pass."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    if len(sys.argv)!=2:raise ValueError('usage: verify-blocked.py RUN_NAME')
    run=(HERE/'runs'/sys.argv[1]).resolve()
    if run.parent!=(HERE/'runs').resolve():raise ValueError('invalid run')
    report=json.loads((run/'report.json').read_text(encoding='utf8'))
    job=json.loads((run/'build/supervisor.json').read_text(encoding='utf8'))
    binary=ROOT/'artifacts/local/legacy-concat-independent-20261030-target/debug/mdd-concat-independent.exe'
    drift=[name for name,digest in report['source_before'].items() if not (ROOT/name).is_file() or sha(ROOT/name)!=digest]
    engines={name:item['matches'] and sha(Path(item['path']))==item['sha256']==item['expected'] for name,item in report['engine_before'].items()}
    checks={'probe_blocked':report['status']=='blocked_by_resource_window' and report['probe_started'] is False and not (run/'probe').exists(),
       'original_memory_threshold':int(report['memory_probe']['minimum_bytes'])==3*1024**3 and int(report['memory_probe']['available_bytes'])<3*1024**3,
       'build_success_and_tree_empty':job==report['build'] and job['status']=='completed' and job['exit_code']==0 and job['tree_empty_verified'] and job['assigned_before_resume'],
       'original_job_limits':job['limits']['memory_commit_bytes']==str(2*1024**3) and job['limits']['timeout_seconds']==180,
       'candidate_binary_identity':binary.is_file() and sha(binary)==report['binary_sha256'],
       'source_unchanged_now':not drift,'legacy_engines_unchanged':all(engines.values()),
       'no_qualification':not report['profile_admitted'] and not report['task_complete_proven']}
    result={'status':'blocked_verified' if all(checks.values()) else 'blocked_evidence_mismatch','checks':checks,'source_drift':drift,'legacy_engine_checks':engines,
      'report_sha256':sha(run/'report.json'),'stdout_sha256':sha(run/'build/stdout.txt'),'stderr_sha256':sha(run/'build/stderr.txt'),'supervisor_sha256':sha(run/'build/supervisor.json'),
      'readback_sha256':sha(Path(__file__)),'candidate_binary_sha256':report['binary_sha256'],
      'scope':'build only; no probe started and no SQL result or qualification claim'}
    (run/'blocked-readback.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(result,indent=2));return 0 if all(checks.values()) else 1
if __name__=='__main__':raise SystemExit(main())
