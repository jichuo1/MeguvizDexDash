#!/usr/bin/env python3
"""Check malformed-handler evidence cannot be silently promoted or dropped."""
import copy
import compile_column_ledger_v2 as audit


def reject(call):
    try:
        call()
    except ValueError:
        return
    raise RuntimeError("negative evidence mutation was accepted")


def main():
    report = audit.load(audit.OWNED + "/result.json")
    native = audit.load(audit.OWNED + "/native-bad/stdout.txt")
    sdk = (audit.ROOT / audit.OWNED / "sdk-bad/stderr.txt").read_bytes()
    a0 = (audit.ROOT / audit.OWNED / "a0-bad/stdout.txt").read_bytes()
    audit.verify_bad_terminals(report, native, sdk, a0)
    incorrect_native = copy.deepcopy(native)
    incorrect_native["error"]["code"] = "UNSUPPORTED_CAPABILITY"
    reject(lambda:audit.verify_bad_terminals(report, incorrect_native, sdk, a0))
    reject(lambda:audit.verify_bad_terminals(report, native, b"", a0))
    reject(lambda:audit.verify_bad_terminals(report, native, sdk, b""))
    incorrect_report = copy.deepcopy(report)
    incorrect_report["bad_handler"]["a0_exit_observed"] = 1
    reject(lambda:audit.verify_bad_terminals(incorrect_report, native, sdk, a0))
    print("4 malformed-handler evidence mutations rejected; no qualification issued")


if __name__ == "__main__":
    main()
