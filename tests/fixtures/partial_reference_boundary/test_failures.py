#!/usr/bin/env python3
"""Negative controls for nonempty partial reference coverage."""
import copy
import json
import verify


def reject(fn):
    try: fn()
    except (ValueError,RuntimeError): return
    raise RuntimeError('tampered partial reference evidence accepted')


def main():
    path=verify.ROOT/'artifacts/mdd-026/partial-reference-audit/20261029T021708996807Z/native-partial-0/stdout.txt'
    original=json.loads(path.read_bytes());verify.validate(original,0);cases=[]
    x=copy.deepcopy(original);x['partial_coverage']['facts']='complete';cases.append(x)
    x=copy.deepcopy(original);x['partial_coverage']['missing_method_indices']=[];cases.append(x)
    x=copy.deepcopy(original);x['partial_local_matches']['coverage']='complete';cases.append(x)
    x=copy.deepcopy(original);x['partial_local_matches']['absence_proven_within_encoded_operand_scope']=True;cases.append(x)
    x=copy.deepcopy(original);x['all_coverage']['facts']='complete';cases.append(x)
    x=copy.deepcopy(original);x['all_coverage']['issues']=[];cases.append(x)
    x=copy.deepcopy(original);x['indexed_error']['code']='UNSUPPORTED_QUERY';cases.append(x)
    x=copy.deepcopy(original);x['complete_subset']['covers_all_captured_sources']=True;cases.append(x)
    for item in cases:reject(lambda:verify.validate(item,0))
    print('8 partial-reference evidence mutations rejected; no qualification issued')


if __name__=='__main__':main()
