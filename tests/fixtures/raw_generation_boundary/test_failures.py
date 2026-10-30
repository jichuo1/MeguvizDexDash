#!/usr/bin/env python3
"""Reject mutations to cross-generation raw facts and identities."""
import copy
import json
from pathlib import Path
import sys
import verify


def main():
    verify.common.require(len(sys.argv)==2,'expected recorded run directory')
    folder=verify.ROOT/Path(sys.argv[1]);value=json.loads((folder/'native/stdout.txt').read_bytes())
    raw_a,raw_b=verify.generated();a,b=verify.oracle(raw_a),verify.oracle(raw_b)
    verify.validate(value,a,b,raw_a,raw_b)
    checks=[
        lambda x:x['a_snapshot'].__setitem__('snapshot_id',x['b_snapshot']['snapshot_id']),
        lambda x:x['a_raw']['source'].__setitem__('content_id',x['b_raw']['source']['content_id']),
        lambda x:x.__setitem__('old_caller_bytes',x['new_caller_bytes']),
        lambda x:x['a_raw']['methods'][0].__setitem__('sha256','0'*64),
        lambda x:x['a_raw']['methods'][0]['insns_range'].__setitem__('byte_length','1'),
        lambda x:x.__setitem__('new_recipe_sha256',x['old_recipe_sha256']),
        lambda x:x['a_raw']['methods'][1].__setitem__('sha256','0'*64),
        lambda x:x.__setitem__('old_native_is_none',False),
        lambda x:x['foreign_a'].__setitem__('code','UNSUPPORTED_QUERY'),
        lambda x:x['mixed_b'].__setitem__('code','UNSUPPORTED_QUERY'),
    ]
    for mutate in checks:
        changed=copy.deepcopy(value);mutate(changed)
        try:verify.validate(changed,a,b,raw_a,raw_b)
        except RuntimeError:continue
        raise RuntimeError('altered raw generation evidence accepted')
    print('10 raw generation, no-body, source and error mutations rejected; no task gate issued')


if __name__=='__main__':main()
