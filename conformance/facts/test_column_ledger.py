#!/usr/bin/env python3
"""Failure controls for the scoped evidence inventory; never an acceptance gate."""
import compile_column_ledger as ledger


def reject(function, needle):
    try:
        function()
    except ValueError as error:
        if needle in str(error):
            return
        raise RuntimeError("unexpected error: " + str(error)) from error
    raise RuntimeError("invalid evidence accepted: " + needle)


def main():
    stdout, stderr = b"successful evidence\n", b""
    good = {"exit_code":0, "stdout_sha256":ledger.sha(stdout), "stderr_sha256":ledger.sha(stderr)}
    ledger.verify_receipt(good, stdout, stderr, False)
    reject(lambda:ledger.verify_receipt(good, stdout + b"tampered", stderr, False), "command stream hash mismatch")
    reject(lambda:ledger.verify_receipt(dict(good, exit_code=1), stdout, stderr, False), "unexpected command terminal")
    result = b'{"scope":"small"}'
    readback = {"status":"passed", "result_sha256":ledger.sha(result), "task_complete_proven":False}
    ledger.verify_readback(result, readback)
    reject(lambda:ledger.verify_readback(result + b" ", readback), "result/readback identity mismatch")
    reject(lambda:ledger.verify_readback(result, dict(readback, task_complete_proven=True)), "readback overclaims task")
    print("4 negative controls rejected; no task gate issued")


if __name__ == "__main__":
    main()
