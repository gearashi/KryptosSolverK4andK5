"""Run the available unit suite and retain a machine-readable outcome."""
import argparse
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if args.output.exists():
    parser.error("output already exists")
started = time.perf_counter()
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
record = {"tests_run": result.testsRun, "successful": result.wasSuccessful(),
          "failures": [{"test": str(test), "traceback": detail} for test, detail in result.failures],
          "errors": [{"test": str(test), "traceback": detail} for test, detail in result.errors],
          "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
          "runtime_seconds": time.perf_counter() - started,
          "scope": "Available unit suite only; no dashboard/browser/BOINC/GPU load test."}
args.output.parent.mkdir(parents=True, exist_ok=True)
with args.output.open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, allow_nan=False)
sys.exit(0 if result.wasSuccessful() else 1)
