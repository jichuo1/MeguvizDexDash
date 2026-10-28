"""Capture final signed-literal checks without overwriting the earlier checks."""
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mdd_mixed_checks", here / "capture-checks.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.OUT = here / "checks-signed-20261029"
module.OUT.mkdir(exist_ok=True)
module.main()
