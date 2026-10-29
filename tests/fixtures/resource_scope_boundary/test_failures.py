#!/usr/bin/env python3
"""Reject evidence mutations without changing recorded output."""
import copy
import json
from pathlib import Path
import sys
import verify


def main():
    verify.common.require(len(sys.argv)==2,'expected recorded run directory')
    folder=verify.ROOT/Path(sys.argv[1]);value=json.loads((folder/'native/stdout.txt').read_bytes())
    expected=verify.oracle(verify.generated());verify.validate(value,expected)
    checks=[
        lambda x:x['resources'][1]['member'].__setitem__('member_id',x['resources'][0]['member']['member_id']),
        lambda x:x['resources'][1]['member'].__setitem__('archive_member_ordinal','1'),
        lambda x:x['resources'][3]['member'].__setitem__('source_occurrence_id',x['resources'][0]['member']['source_occurrence_id']),
        lambda x:x['resources'][1].__setitem__('bytes',x['resources'][0]['bytes']),
        lambda x:x['before'].__setitem__('facts','complete'),
        lambda x:x['subset'].__setitem__('covers_all_captured_sources',True),
        lambda x:x['foreign_error'].__setitem__('code','UNSUPPORTED_QUERY'),
    ]
    for mutate in checks:
        changed=copy.deepcopy(value);mutate(changed)
        try:verify.validate(changed,expected)
        except RuntimeError:continue
        raise RuntimeError('altered resource evidence accepted')
    print('7 resource identity, coverage and error mutations rejected; no task gate issued')


if __name__=='__main__':main()
