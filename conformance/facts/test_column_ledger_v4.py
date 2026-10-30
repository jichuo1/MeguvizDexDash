#!/usr/bin/env python3
"""Negative controls for the mixed-source reference evidence inventory."""
import copy
import compile_column_ledger_v4 as audit


def reject(fn):
    try:
        fn()
    except (ValueError,RuntimeError):
        return
    raise RuntimeError('tampered mixed-source evidence was accepted')


def main():
    result = audit.load(audit.SOURCE+'/result.json')
    native = audit.load(audit.SOURCE+'/native/stdout.txt')
    audit.validate_scope(result,native)
    changed = copy.deepcopy(result); changed['task_complete_proven'] = True
    reject(lambda:audit.validate_scope(changed,native))
    changed = copy.deepcopy(result); changed['target_local_indices'] = [2,2,2]
    reject(lambda:audit.validate_scope(changed,native))
    changed = copy.deepcopy(result); changed['all_site_count'] = 39
    reject(lambda:audit.validate_scope(changed,native))
    changed = copy.deepcopy(native); changed['cross_occurrence_error']['code'] = 'UNSUPPORTED_QUERY'
    reject(lambda:audit.validate_scope(result,changed))
    original_load = audit.load
    def missing_site(path):
        obj = original_load(path)
        if path == audit.SOURCE+'/native/stdout.txt':
            obj['global_indexed']['sites'].pop()
        return obj
    audit.load = missing_site
    reject(audit.inspect_mixed)
    audit.load = original_load
    def wrong_shared_offset(path):
        obj = original_load(path)
        if path == audit.SOURCE+'/native/stdout.txt':
            for site in obj['occurrences'][1]['all_sites']:
                if site['target_kind'] == 'method' and site['target_local_index'] == 3 and site['caller_method_idx'] == 1:
                    site['code_item_byte_offset'] = '999'
        return obj
    audit.load = wrong_shared_offset
    reject(audit.inspect_mixed)
    audit.load = original_load
    original_receipt = audit.base.verify_receipt
    def tampered_stdout(record,stdout,stderr,failed):
        original_receipt(record,stdout+b'tampered',stderr,failed)
    audit.base.verify_receipt = tampered_stdout
    reject(audit.inspect_mixed)
    audit.base.verify_receipt = original_receipt
    print('7 mixed-source evidence mutations rejected; no qualification issued')


if __name__ == '__main__':
    main()
