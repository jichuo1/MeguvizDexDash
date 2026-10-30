#!/usr/bin/env python3
"""Negative controls for two-generation resource evidence."""
import compile_column_ledger_v9 as audit


def reject(path,mutate):
    original=audit.load
    previous_original=audit.previous.load
    def changed(current):
        result=original(current)
        if current==path:mutate(result)
        return result
    audit.load=changed
    audit.previous.load=changed
    try:
        try:audit.inspect_generation()
        except (ValueError,RuntimeError):return
        raise RuntimeError('tampered generation evidence accepted: '+path)
    finally:
        audit.load=original
        audit.previous.load=previous_original


def main():
    result=audit.SOURCE+'/result.json';native=audit.SOURCE+'/native/stdout.txt'
    reject(result,lambda x:x.__setitem__('profile_admitted',True))
    reject(result,lambda x:x.__setitem__('generation_a_sha256','0'*64))
    reject(result,lambda x:x.__setitem__('resource_occurrences',3))
    reject(native,lambda x:x['a_scope'].__setitem__('snapshot_id',x['b_scope']['snapshot_id']))
    reject(native,lambda x:x['a_resources'][1].__setitem__('bytes',x['b_resources'][1]['bytes']))
    reject(native,lambda x:x['a_rejected'].__setitem__('facts','complete'))
    reject(native,lambda x:x['b_before'].__setitem__('issues',[]))
    reject(native,lambda x:x['foreign_a'].__setitem__('code','UNSUPPORTED_QUERY'))
    reject(native,lambda x:x.__setitem__('disk_rewritten_between_captures',False))
    reject(audit.SOURCE+'/native/record.json',lambda x:x.__setitem__('exit_code',1))
    print('10 resource-generation evidence mutations rejected; no task gate issued')


if __name__=='__main__':main()
