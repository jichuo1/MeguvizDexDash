#!/usr/bin/env python3
"""Negative controls for resource-member evidence."""
import compile_column_ledger_v8 as audit


def reject(path,mutate):
    original=audit.load
    def changed(current):
        result=original(current)
        if current==path:mutate(result)
        return result
    audit.load=changed
    try:
        try:audit.inspect_resource()
        except (ValueError,RuntimeError):return
        raise RuntimeError('tampered resource evidence accepted: '+path)
    finally:audit.load=original


def main():
    result=audit.SOURCE+'/result.json';native=audit.SOURCE+'/native/stdout.txt'
    reject(result,lambda x:x.__setitem__('profile_admitted',True))
    reject(result,lambda x:x.__setitem__('fixture_sha256','0'*64))
    reject(result,lambda x:x.__setitem__('source_occurrences',1))
    reject(native,lambda x:x['resources'][1]['member'].__setitem__('member_id',x['resources'][0]['member']['member_id']))
    reject(native,lambda x:x['resources'][1].__setitem__('bytes',x['resources'][0]['bytes']))
    reject(native,lambda x:x['before'].__setitem__('facts','complete'))
    reject(native,lambda x:x['subset'].__setitem__('covers_all_captured_sources',True))
    reject(native,lambda x:x['foreign_error'].__setitem__('code','UNSUPPORTED_QUERY'))
    reject(audit.SOURCE+'/native/record.json',lambda x:x.__setitem__('exit_code',1))
    print('9 resource-scope evidence mutations rejected; no task gate issued')


if __name__=='__main__':main()
