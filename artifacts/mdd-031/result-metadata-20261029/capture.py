"""Capture the later zero-row metadata admission validation separately."""
import importlib.util
import json
from pathlib import Path

out = Path(__file__).resolve().parent
previous = out.parent / "result-workspace-20261029" / "capture.py"
spec = importlib.util.spec_from_file_location("mdd_prior_capture", previous)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.OUT = out
module.main()
record_path = out / "record.json"
record = json.loads(record_path.read_text(encoding="utf-8"))
record["zero_row_regression"] = {
    "pre_fix_independent_evidence": "artifacts/mdd-031-audit/result-memory-probe/before-fix-reproduced.json",
    "post_fix_unit": "runtime_tests::zero_rows_still_reserve_result_schema_and_identity",
    "scope": "result-owned schema, identity, and row storage; downstream clones and SQLite internal allocations are outside the reservation",
}
record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
