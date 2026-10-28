"""Record fixed-engine text-to-integer cast behavior in a distinct run."""
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
observer.CASES = {
    "invalid_integer_cast_compare": "SELECT CAST('bad' AS INTEGER)='1' AS v",
    "invalid_integer_cast": "SELECT CAST('bad' AS INTEGER) AS v",
    "prefix_integer_cast": "SELECT CAST('123tail' AS INTEGER) AS v",
}
observer.main()
(observer.OUT / "wrapper-identity.json").write_text(json.dumps({"wrapper_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "observer_sha256":hashlib.sha256((here / "observe.py").read_bytes()).hexdigest()},indent=2)+"\n",encoding="utf-8")
