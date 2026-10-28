"""Small independent gate orchestration, preserving every subprocess terminal."""
import json
import sys
from run_probe import command, require

def main():
    for label, script in [("final/native", "conformance/facts/run_probe.py"),
                          ("final/differential", "conformance/facts/verify.py"),
                          ("final/column-matrix", "conformance/facts/build_matrix.py")]:
        result = command(label, [sys.executable, "-O", script])
        require(result.returncode == 0, "small fact gate failed: " + label)
    print(json.dumps({"small_fact_gate_complete":True,"subprocesses":3,"task_026_complete":False,
                      "remaining":"production lazy/index/coverage scope validation belongs to its implementation owner"}))

if __name__ == "__main__": main()
