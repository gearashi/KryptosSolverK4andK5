"""Declare final validation inputs without running or changing experiments."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
code = {p.relative_to(ROOT).as_posix() for p in (ROOT / "kryptos").glob("*.py")}
geometry = {"research/sculpture_layout.json","research/source_snapshots/sculpture-J/dunin_transcript.html.txt",
            "research/source_snapshots/sculpture-J/cia_sculpture.html.txt"}
model = {"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"}
old = set(json.loads((ROOT / "research/unit-suite-002-contract.json").read_text())["execution_artifacts"])
tests = {p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").glob("test_*.py")}
suite = sorted(code | geometry | model | old | tests | {"research/geometry_benchmarks.py","research/recovery_benchmarks.py"})
examples = {"examples/columns-ragged.json","examples/general-five-stages.json","examples/alphabet-cycle.json","examples/optimize-small.json"}
cli = sorted(code | geometry | model | examples | {"research/verify_J_cli.py"})

for name, paths, assertion, bounds, random in (
    ("unit",suite,"All164 available unit tests pass for the pinned source revision, including exact-family, ambiguity, budget and replay regressions.",{"workers":1,"wall_seconds":30,"expected_tests":164},True),
    ("cli",cli,"Six saved command invocations produce the expected results and every saved complete candidate independently replays to its input ciphertext.",{"workers":1,"commands":6,"per_command_timeout_seconds":15,"wall_seconds":40},False)):
    result = {"claim_id":"K4-20261013-J-"+name,"mathematics":{
        "assertion_tested":assertion,"coefficient_domain":"Exact modular arithmetic and declared numerical score comparisons",
        "conventions":"No external solution submission or persistent workload; outputs created exclusively.",
        "inputs":paths,"bounds":bounds,"non_claims":["No GPU or dashboard load test","No authenticated K4/K5 solution"]},
        "execution_artifacts":paths,"software":[{"name":"Python","version":"3.14.5"}],
        "randomness":{"used":random,"generator":"Python random.Random; UUID names do not select mathematical data" if random else "",
                      "seed":"Fixed literal seeds in pinned test_calibration.py and test_factor_search.py" if random else None}}
    with (ROOT / "research" / ("J-"+name+"-contract.json")).open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)
