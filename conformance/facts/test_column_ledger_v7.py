#!/usr/bin/env python3
"""Negative controls for nonempty partial-reference evidence."""
import compile_column_ledger_v7 as audit


def reject(fn):
    try:fn()
    except (ValueError,RuntimeError):return
    raise RuntimeError('tampered partial-reference evidence accepted')


def mutated(path_to_change,mutate):
    original=audit.load
    def replacement(path):
        obj=original(path)
        if path==path_to_change:mutate(obj)
        return obj
    audit.load=replacement
    try:reject(audit.inspect_partial)
    finally:audit.load=original


def main():
    path=audit.SOURCE+'/native-partial-0/stdout.txt'
    mutated(path,lambda x:x['partial_coverage'].__setitem__('facts','complete'))
    mutated(path,lambda x:x['partial_coverage'].__setitem__('missing_method_indices',[]))
    mutated(path,lambda x:x['partial_local_matches'].__setitem__('absence_proven_within_encoded_operand_scope',True))
    mutated(path,lambda x:x['all_coverage'].__setitem__('facts','complete'))
    mutated(path,lambda x:x['all_coverage'].__setitem__('issues',[]))
    mutated(path,lambda x:x['complete_subset'].__setitem__('covers_all_captured_sources',True))
    mutated(path,lambda x:x['partial_rows_error'].__setitem__('code','UNSUPPORTED_QUERY'))
    mutated(path,lambda x:x['indexed_error'].__setitem__('code','UNSUPPORTED_QUERY'))
    mutated(path,lambda x:x['partial_local_target'].__setitem__('dex_occurrence_id','wrong-source'))
    mutated(audit.SOURCE+'/result.json',lambda x:x.__setitem__('task_complete_proven',True))
    original=audit.base.verify_receipt
    def corrupt(record,stdout,stderr,failed):original(record,stdout+b'tampered',stderr,failed)
    audit.base.verify_receipt=corrupt
    try:reject(audit.inspect_partial)
    finally:audit.base.verify_receipt=original
    print('11 nonempty-partial evidence mutations rejected; no qualification issued')


if __name__=='__main__':main()
