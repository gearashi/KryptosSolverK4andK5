"""Exhaust PK3's 17,576 crib-compatible plaintexts under one fixed known model.

Separate protocol extending only the previous 676-completion budget. Full
message, identity route, KRYPTOS alphabet, periods 10/8, and 24 artificial
supplied letters are unchanged. No source, cipher or key-family expansion.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research import pk_benchmarks as benchmark
from kryptos.layer_plan import compile_layer_plan

SOURCE_PATHS = ("research/pk3_extended.py", *benchmark.SOURCE_PATHS)
EXPECTED_LENGTH = 280
EXPECTED_DIMENSION = 3
EXACT_CANDIDATES = 26 ** EXPECTED_DIMENSION
ENUMERATION_TIME_LIMIT_SECONDS = 45


def file_hashes():
    return {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def prepare():
    fixtures, sources = benchmark.load_fixtures()
    fixture = next(f for f in fixtures if f["id"] == "pk3")
    if fixture["length"] != EXPECTED_LENGTH:
        raise ValueError("This fixed protocol requires full 280-letter PK3")
    known = {i: fixture["plaintext"][i] for i in benchmark.crib_positions()}
    return fixture, known, sources


def recover(ciphertext, known):
    """No published key or undisclosed plaintext is passed into recovery."""
    if len(ciphertext) != EXPECTED_LENGTH or tuple(sorted(known)) != benchmark.crib_positions():
        raise ValueError("The fixed length and 24-position mask must be unchanged")
    plan = compile_layer_plan(EXPECTED_LENGTH, known, "SST", range(EXPECTED_LENGTH), 10, 8)
    if plan.plaintext_dimension != EXPECTED_DIMENSION:
        raise AssertionError("Unexpected dimension: this protocol is only for the 17,576-completion case")
    solved = plan.solve(ciphertext, known, benchmark.ALPHABET)
    if not solved["feasible"]:
        raise AssertionError("Verified PK3 model is unexpectedly inconsistent")
    solution = solved["solution"]
    if solution.distinct_plaintext_count != EXACT_CANDIDATES:
        raise AssertionError("Unexpected exact completion count")
    started = perf_counter()
    records = []
    for values, plaintext in solution.enumerate_plaintexts(max_candidates=EXACT_CANDIDATES):
        if perf_counter() - started > ENUMERATION_TIME_LIMIT_SECONDS:
            raise TimeoutError("45-second enumeration cap reached; no complete result or partial rank is written")
        keys = solution.keys(values)
        stages = benchmark.encrypt_stages(plaintext, keys)
        if stages[-1] != ciphertext or any(plaintext[i] != ch for i, ch in known.items()):
            raise AssertionError("A candidate fails literal two-stage re-encryption or a supplied crib")
        score = benchmark.english_score(plaintext, known)
        if not math.isfinite(score):
            raise AssertionError("Nonfinite score")
        records.append({"plaintext": plaintext, "score": score,
                        "representative_keys": list(keys), "freedom_values": list(values),
                        "stage_1_sha256": benchmark.digest(stages[0])})
    if len(records) != EXACT_CANDIDATES or len({r["plaintext"] for r in records}) != EXACT_CANDIDATES:
        raise AssertionError("Enumeration is incomplete or repeats a plaintext")
    records.sort(key=lambda record: (-record["score"], record["plaintext"]))
    return {"status": "complete", "feasible": True, "plaintext_dimension": EXPECTED_DIMENSION,
            "crib_components": plan.component_count, "full_components": plan.full_component_count,
            "required_candidates": EXACT_CANDIDATES, "evaluated_candidates": len(records),
            "literal_reencryptions": len(records), "prediction_mask": solution.prediction_mask(),
            "ranked_candidates": records,
            "ranked_candidates_sha256": benchmark.digest(benchmark.canonical(records)),
            "enumeration_seconds": perf_counter() - started}


def analyze():
    started, before = perf_counter(), file_hashes()
    benchmark.self_test()
    fixture, known, sources = prepare()
    recovered = recover(fixture["ciphertext"], known)
    evaluated = benchmark.assess(recovered, fixture["plaintext"])
    if not evaluated["exact_plaintext_recovered"]:
        raise AssertionError("Complete enumeration missed the published plaintext")
    after = file_hashes()
    if before != after:
        raise RuntimeError("An input changed during the run; discard this output")
    contract = {"extends": "pk-benchmarks-001 PK3 budget-only gap",
                "full_message_length": EXPECTED_LENGTH, "alphabet": benchmark.ALPHABET,
                "method_known": True, "order": "SST", "route": "identity", "periods": [10, 8],
                "supplied_cribs_zero_based": [[i, ch] for i, ch in known.items()],
                "supplied_cribs_are_artificial": True, "scored_positions": EXPECTED_LENGTH - len(known),
                "exact_completion_count": EXACT_CANDIDATES,
                "enumeration_time_cap_seconds": ENUMERATION_TIME_LIMIT_SECONDS,
                "python_version": platform.python_version(), "python_implementation": platform.python_implementation()}
    return {"experiment": "published-pk3-complete-method-known-recovery", "contract": contract,
            "resolved_inputs_sha256": benchmark.digest(benchmark.canonical({"contract": contract, "fixture": fixture})),
            "summary": {"complete_cases": 1, "evaluated_candidates": recovered["evaluated_candidates"],
                        "literal_reencryptions": recovered["literal_reencryptions"], **evaluated},
            "fixture": fixture, "sources": sources, "recovery": recovered, "evaluation": evaluated,
            "score_description": benchmark.SCORE_DESCRIPTION,
            "checks": {"inputs_unchanged": True, "every_candidate_reencrypted": True,
                       "every_distinct_plaintext_enumerated": True, "external_code_executed": False},
            "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in SOURCE_PATHS],
            "runtime_seconds": perf_counter() - started,
            "non_claims": ["Methods and periods are supplied; this is not blind method discovery.",
                           "The 24 supplied letters are artificial PK cribs, not official clues.",
                           "Exact enumeration leaves ambiguity even if English ranking places the true text first.",
                           "Two published texts do not calibrate the language scorer or general recovery probability.",
                           "Representative keys can differ from the published words through gauge freedom.",
                           "No K4/K5 method inference, external submission, extra cribs, retuning, or wider model search."]}


def check_plan():
    benchmark.self_test()
    fixture, known, _ = prepare()
    plan = compile_layer_plan(EXPECTED_LENGTH, known, "SST", range(EXPECTED_LENGTH), 10, 8)
    solved = plan.solve(fixture["ciphertext"], known, benchmark.ALPHABET)
    if not solved["feasible"] or plan.plaintext_dimension != EXPECTED_DIMENSION:
        raise AssertionError("Fixed protocol preflight failed")
    return {"plan_feasible": True, "plaintext_dimension": plan.plaintext_dimension,
            "required_candidates": solved["solution"].distinct_plaintext_count,
            "candidate_enumeration_performed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-plan", action="store_true")
    args = parser.parse_args()
    if args.check_plan:
        if args.output is not None:
            parser.error("--check-plan does not produce a canonical output")
        print(json.dumps(check_plan(), indent=2))
        return
    if args.output is None:
        parser.error("--output is required")
    if args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({**result["summary"], "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
