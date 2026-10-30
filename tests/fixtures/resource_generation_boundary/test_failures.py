#!/usr/bin/env python3
"""Reject cross-generation identity, byte and coverage mutations."""
import copy
import json
from pathlib import Path
import sys
import verify


def main():
    verify.common.require(len(sys.argv)==2,'expected recorded run directory')
    folder=verify.ROOT/Path(sys.argv[1]);value=json.loads((folder/'native/stdout.txt').read_bytes())
    raw_a,raw_b=verify.generated(False),verify.generated(True);a,b=verify.oracle(raw_a),verify.oracle(raw_b)
    verify.validate(value,a,b,raw_a,raw_b)
    checks=[
        lambda x:x['a_scope'].__setitem__('snapshot_id',x['b_scope']['snapshot_id']),
        lambda x:x['a_resources'][1].__setitem__('bytes',x['b_resources'][1]['bytes']),
        lambda x:x['b_resources'][1]['member'].__setitem__('source_occurrence_id',x['a_scope']['inputs'][0]['source_occurrence_id']),
        lambda x:x['a_resources'][1]['member'].__setitem__('member_id',x['a_resources'][0]['member']['member_id']),
        lambda x:x['a_rejected'].__setitem__('facts','complete'),
        lambda x:x['b_before'].__setitem__('issues',[]),
        lambda x:x['foreign_a'].__setitem__('code','UNSUPPORTED_QUERY'),
        lambda x:x['a_scope']['inputs'][0].__setitem__('content_id',x['b_scope']['inputs'][0]['content_id']),
        lambda x:x['b_after'].__setitem__('facts','partial'),
    ]
    for mutate in checks:
        changed=copy.deepcopy(value);mutate(changed)
        try:verify.validate(changed,a,b,raw_a,raw_b)
        except RuntimeError:continue
        raise RuntimeError('altered generation evidence accepted')
    print('9 cross-generation identity, bytes, coverage and error mutations rejected; no task gate issued')


if __name__=='__main__':main()
