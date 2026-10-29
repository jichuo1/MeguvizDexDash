#!/usr/bin/env python3
"""Negative controls for mixed-source corruption coverage evidence."""
import copy
import json
from pathlib import Path
import verify


def reject(action):
    try: action()
    except (ValueError,RuntimeError): return
    raise RuntimeError('tampered mixed-failure evidence accepted')


def main():
    folder=verify.ROOT/'artifacts/mdd-026/mixed-failure-audit/20261029T015522772300Z'
    good=json.loads((folder/'native-valid-first/stdout.txt').read_bytes())
    verify.validate(good,0,1,verify.BAD[1])
    mutations=[]
    x=copy.deepcopy(good);x['original_error']['code']='UNSUPPORTED_CAPABILITY';mutations.append(x)
    x=copy.deepcopy(good);x['all_terminal']['code']='UNSUPPORTED_QUERY';mutations.append(x)
    x=copy.deepcopy(good);x['all_coverage']['facts']='complete';mutations.append(x)
    x=copy.deepcopy(good);x['all_coverage']['issues']=[];mutations.append(x)
    x=copy.deepcopy(good);x['valid_subset_coverage']['covers_all_captured_sources']=True;mutations.append(x)
    x=copy.deepcopy(good);x['overwrite_error']['code']='UNSUPPORTED_CAPABILITY';mutations.append(x)
    x=copy.deepcopy(good);x['original_error']['details']['byte_offset']='462';mutations.append(x)
    for changed in mutations: reject(lambda:verify.validate(changed,0,1,verify.BAD[1]))
    print('7 mixed-failure evidence mutations rejected; no task qualification issued')


if __name__=='__main__': main()
