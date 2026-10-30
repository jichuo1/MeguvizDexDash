#!/usr/bin/env python3
"""Negative controls for retained bad source-index and non-scalar observations."""
import copy
import importlib.util
import compile_column_ledger_v3 as audit


def reject(function):
    try:
        function()
    except (ValueError,RuntimeError):
        return
    raise RuntimeError("invalid source evidence was accepted")


def main():
    report = audit.load(audit.SOURCE+"/result.json")
    native = audit.load(audit.SOURCE+"/native-bad/stdout.txt")
    sdk = (audit.ROOT/audit.SOURCE/"sdk-bad/stderr.txt").read_bytes()
    path = audit.ROOT/"tests/fixtures/class_source_boundary/verify.py"
    spec = importlib.util.spec_from_file_location("mdd_class_source_v3_test",path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    a0 = verifier.common.table((audit.ROOT/audit.SOURCE/"a0-bad/stdout.txt").read_bytes(),verifier.COLUMNS)
    audit.verify_bad_terminal(report,native,sdk,a0)
    wrong = copy.deepcopy(native)
    wrong["error"]["code"] = "UNSUPPORTED_CAPABILITY"
    reject(lambda:audit.verify_bad_terminal(report,wrong,sdk,a0))
    reject(lambda:audit.verify_bad_terminal(report,native,b"",a0))
    changed = copy.deepcopy(a0)
    changed[0]["source_file"] = ""
    reject(lambda:audit.verify_bad_terminal(report,native,sdk,changed))
    incorrect = copy.deepcopy(report)
    incorrect["bad_source_index"]["a0_exit_observed"] = 1
    reject(lambda:audit.verify_bad_terminal(incorrect,native,sdk,a0))
    surrogate = next(x["oracle"] for x in report["fixtures"] if x["id"] == "surrogate-source")
    expected = [verifier.a0_row(surrogate)]
    changed = copy.deepcopy(expected)
    changed[0]["source_file"] = "EFBFBD"
    reject(lambda:verifier.compare(changed,expected))
    print("5 class-source evidence mutations rejected; no qualification issued")


if __name__ == "__main__":
    main()
