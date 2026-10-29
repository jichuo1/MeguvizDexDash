#!/usr/bin/env python3
"""Negative controls for field/type and dynamic source evidence."""
import copy
import compile_column_ledger_v5 as audit


def reject(fn):
    try: fn()
    except (ValueError,RuntimeError): return
    raise RuntimeError('tampered v5 evidence accepted')


def main():
    field=audit.load(audit.FIELD+'/result.json');native_field=audit.load(audit.FIELD+'/native/stdout.txt')
    dynamic=audit.load(audit.DYNAMIC+'/result.json');native_dynamic=audit.load(audit.DYNAMIC+'/native/stdout.txt')
    audit.check_terminal('field',field,native_field);audit.check_terminal('dynamic',dynamic,native_dynamic)
    changed=copy.deepcopy(field);changed['task_complete_proven']=True
    reject(lambda:audit.check_terminal('field',changed,native_field))
    changed=copy.deepcopy(field);changed['field_local_indices']=[0,0,0]
    reject(lambda:audit.check_terminal('field',changed,native_field))
    changed=copy.deepcopy(native_field);changed['foreign_field']['code']='UNSUPPORTED_QUERY'
    reject(lambda:audit.check_terminal('field',field,changed))
    changed=copy.deepcopy(native_dynamic);changed['quota_errors'][0]['code']='UNSUPPORTED_QUERY'
    reject(lambda:audit.check_terminal('dynamic',dynamic,changed))
    changed=copy.deepcopy(dynamic);changed['dynamic_counts']=[0,0,0,0]
    reject(lambda:audit.check_terminal('dynamic',changed,native_dynamic))
    original=audit.load
    def wrong_dynamic(path):
        value=original(path)
        if path == audit.DYNAMIC+'/native/stdout.txt': value['occurrences'][0]['dynamic_calls'][0]['runtime_target_status']='known_bootstrap'
        return value
    audit.load=wrong_dynamic;reject(lambda:audit.inspect('dynamic'));audit.load=original
    def wrong_owner(path):
        value=original(path)
        if path == audit.DYNAMIC+'/native/stdout.txt': value['occurrences'][2]['coverage']['unowned_physical_code_items']=0
        return value
    audit.load=wrong_owner;reject(lambda:audit.inspect('dynamic'));audit.load=original
    def wrong_field_site(path):
        value=original(path)
        if path == audit.FIELD+'/native/stdout.txt': value['occurrences'][1]['sites'][0]['code_unit_pc']=999
        return value
    audit.load=wrong_field_site;reject(lambda:audit.inspect('field'));audit.load=original
    original_receipt=audit.base.verify_receipt
    def corrupt(record,stdout,stderr,failed): original_receipt(record,stdout+b'tampered',stderr,failed)
    audit.base.verify_receipt=corrupt;reject(lambda:audit.inspect('field'));audit.base.verify_receipt=original_receipt
    print('9 field-type and dynamic-source evidence mutations rejected; no qualification issued')


if __name__ == '__main__':
    main()
