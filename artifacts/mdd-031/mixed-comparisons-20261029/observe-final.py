"""Capture the final literal, CAST and derived-IN boundary in a new run."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mdd_mixed_observer", here / "observe.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
observer.OUT = here / "runs" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
observer.CASES = dict(observer.CASES)
observer.CASES.update({
    "signed_literal":"SELECT -1<'1' AS v",
    "legacy_text_arithmetic":"SELECT 1+'a' AS v",
    "cast_bad":"SELECT CAST('bad' AS INTEGER) AS v",
    "cast_prefix":"SELECT CAST('123tail' AS INTEGER) AS v",
    "literal_in":"SELECT 1 IN ('1') AS v",
    "cast_in":"SELECT CAST('01' AS INTEGER) IN ('1') AS v",
    "derived_in":"SELECT d.string_idx IN (1) AS v FROM (SELECT CAST('1' AS TEXT) AS string_idx) d",
    "derived_not_in":"SELECT d.string_idx NOT IN (1) AS v FROM (SELECT CAST('1' AS TEXT) AS string_idx) d",
})
observer.main()
(observer.OUT / "wrapper-identity.json").write_text(json.dumps({"wrapper_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "observer_sha256":hashlib.sha256((here / "observe.py").read_bytes()).hexdigest()},indent=2)+"\n",encoding="utf-8")
