#!/usr/bin/env python3
"""Tamper controls for corrupt-sibling coverage and observed reference outcomes."""
import copy
import compile_column_ledger_v6 as audit


def reject(fn):
    try: fn()
    except (ValueError,RuntimeError): return
    raise RuntimeError('tampered corrupt-sibling evidence accepted')


def mutated(path_to_change,mutate):
    original=audit.load
    def replacement(path):
        obj=original(path)
        if path==path_to_change: mutate(obj)
        return obj
    audit.load=replacement
    try: reject(audit.inspect_failure)
    finally: audit.load=original


def main():
    native=audit.SOURCE+'/native-valid-first/stdout.txt'
    mutated(native,lambda x:x['original_error'].__setitem__('code','UNSUPPORTED_CAPABILITY'))
    mutated(native,lambda x:x['all_terminal'].__setitem__('code','UNSUPPORTED_QUERY'))
    mutated(native,lambda x:x['all_coverage'].__setitem__('facts','complete'))
    mutated(native,lambda x:x['all_coverage'].__setitem__('issues',[]))
    mutated(native,lambda x:x['valid_subset_coverage'].__setitem__('covers_all_captured_sources',True))
    mutated(native,lambda x:x['overwrite_error'].__setitem__('code','UNSUPPORTED_QUERY'))
    mutated(native,lambda x:x['original_error']['details'].__setitem__('byte_offset','462'))
    mutated(audit.SOURCE+'/result.json',lambda x:x['sdk_bad_observation'].__setitem__('exit_code',1))
    mutated(audit.SOURCE+'/result.json',lambda x:x['a0_bad_observations'][0].__setitem__('exit_code',1))
    mutated(audit.ROOT_DIR+'/first-run-command/record.json',lambda x:x.__setitem__('exit_code',0))
    original=audit.base.verify_receipt
    def corrupt(record,stdout,stderr,failed):original(record,stdout+b'tampered',stderr,failed)
    audit.base.verify_receipt=corrupt
    try: reject(audit.inspect_failure)
    finally: audit.base.verify_receipt=original
    print('11 corrupt-sibling evidence mutations rejected; no qualification issued')


if __name__=='__main__': main()
