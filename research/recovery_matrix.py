"""Deterministic, bounded in-family recovery checks with hidden fixture keys.

This is an authored synthetic corpus, not a language benchmark or K4 solution
search. Recovery receives no fixture plaintext, key, generating route, order,
or period pair. Evaluation joins those facts only after recovery is complete.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CRIBS
from kryptos.layer_plan import compile_layer_plan
from kryptos.scoring import SCORE_DESCRIPTION, english_score
from research.check_layer_hypothesis import hypothesis_routes
from research.layer_constraints import apply_layers

ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ORDERS = ("SST", "STS", "TSS")
GENERATION_PAIRS = ((2, 3), (4, 2))
MAX_PERIOD = 8
MAX_DIMENSION = 1
MAX_BUDGET = 5000
SOURCE_PATHS = (
    "research/recovery_matrix.py", "kryptos/data.py", "kryptos/layer_plan.py",
    "kryptos/scoring.py", "research/layer_constraints.py",
    "research/check_layer_hypothesis.py", "research/check_physical_routes.py",
    "research/check_classes.py", "research/k3_reference.py",
)
# Authored for this experiment, without a source corpus or score optimization.
# Only the first 97 letters are used, then the 24 disclosed crib letters replace
# the corresponding positions. Resulting joins need not be grammatical.
CORPUS = (
    ("bakery", "Before the market opened the baker carried warm loaves into the "
     "little shop and set fresh flowers beside the window while rain fell outside."),
    ("music", "The young musician practised a quiet melody after supper and then "
     "wrote a letter to her teacher about the concert planned for the following week."),
    ("garden", "Along the garden path the children found a small green beetle and "
     "watched it climb a fallen branch before they returned home for their lunch."),
    ("station", "At the railway station a porter helped the travellers with their "
     "bags while a family waited near the ticket office for the morning train."),
)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def file_hashes():
    return {path: sha256((ROOT / path).read_bytes()).hexdigest()
            for path in SOURCE_PATHS}


def crib_map():
    known = {}
    for crib in K4_CRIBS:
        for offset, symbol in enumerate(crib["text"]):
            position = crib["start"] - 1 + offset
            if position in known and known[position] != symbol:
                raise ValueError("Conflicting fixture cribs")
            known[position] = symbol
    if len(known) != 24 or any(not 0 <= i < 97 for i in known):
        raise ValueError("This contract requires the existing 24 K4 crib positions")
    return known


def route_bank():
    result = []
    for permutation, aliases in hypothesis_routes().items():
        selected = sorted(alias for alias in aliases if alias.startswith("K3-inspired"))
        if selected:
            result.append({"id": f"k3-route-{len(result)}", "aliases": selected,
                           "permutation": list(permutation),
                           "permutation_sha256": sha256(canonical_bytes(list(permutation))).hexdigest()})
    if len(result) != 2:
        raise ValueError("This contract requires exactly two existing K3-inspired routes")
    return result


def compile_bank(routes, known):
    """Compile all 384 parameter combinations; do not use generation metadata."""
    result = []
    for route in routes:
        for order in ORDERS:
            for period_a in range(1, MAX_PERIOD + 1):
                for period_b in range(1, MAX_PERIOD + 1):
                    metadata = {"route_id": route["id"], "order": order,
                                "period_a": period_a, "period_b": period_b}
                    plan = compile_layer_plan(97, known, order, route["permutation"],
                                              period_a, period_b)
                    result.append((metadata, plan))
    if len(result) != 384:
        raise AssertionError("Unexpected model bank size")
    return result


def fundamental_period(key):
    return next(p for p in range(1, len(key) + 1)
                if len(key) % p == 0 and all(key[i] == key[i % p] for i in range(len(key))))


def make_fixtures(routes, known):
    """Truth records are isolated from recover(), which never receives them."""
    fixtures = []
    offsets = {2: (0, 7), 3: (0, 5, 11), 4: (0, 1, 4, 11)}
    for route in routes:
        for order in ORDERS:
            for period_a, period_b in GENERATION_PAIRS:
                case_number = len(fixtures)
                corpus_id, prose = CORPUS[(case_number + case_number // 4) % len(CORPUS)]
                original = "".join(ch for ch in prose.upper() if "A" <= ch <= "Z")
                if len(original) < 97:
                    raise AssertionError("Authored corpus entry is too short")
                plain = list(original[:97])
                for i, symbol in known.items():
                    plain[i] = symbol
                plain = "".join(plain)
                key_a = "".join(ALPHABET[(3 * case_number + n) % 26] for n in offsets[period_a])
                key_b = "".join(ALPHABET[(5 * case_number + 9 + n) % 26] for n in offsets[period_b])
                if (fundamental_period(key_a), fundamental_period(key_b)) != (period_a, period_b):
                    raise AssertionError("Fixture key collapsed to a shorter period")
                cipher = apply_layers(plain, key_a, key_b, ALPHABET, order, route["permutation"])
                fixtures.append({"case_id": f"case-{case_number + 1:02d}", "corpus_id": corpus_id,
                                 "plaintext": plain, "ciphertext": cipher,
                                 "route_id": route["id"], "order": order,
                                 "period_a": period_a, "period_b": period_b,
                                 "period_gcd": math.gcd(period_a, period_b),
                                 "key_a": key_a, "key_b": key_b})
    if len(fixtures) != 12 or len({f["ciphertext"] for f in fixtures}) != 12:
        raise AssertionError("Expected twelve distinct synthetic ciphertexts")
    return fixtures


def recover(ciphertext, known, bank, candidate_budget):
    """Search a complete declared bank, without access to any fixture truth.

    The cap counts raw model completions before global plaintext deduplication.
    All eligible counts are preflighted; an oversized input is wholly skipped.
    """
    if type(candidate_budget) is not int or not 1 <= candidate_budget <= MAX_BUDGET:
        raise ValueError(f"candidate_budget must be an integer in 1..{MAX_BUDGET}")
    eligible, dimension_histogram = [], Counter()
    feasible_models = []
    for metadata, plan in bank:
        result = plan.solve(ciphertext, known, ALPHABET)
        if result["feasible"]:
            solution = result["solution"]
            dimension_histogram[plan.plaintext_dimension] += 1
            feasible_models.append({**metadata, "plaintext_dimension": plan.plaintext_dimension,
                                    "distinct_plaintexts_in_model": solution.distinct_plaintext_count})
            if plan.plaintext_dimension <= MAX_DIMENSION:
                eligible.append((metadata, solution))
    required = sum(solution.distinct_plaintext_count for _, solution in eligible)
    report = {"status": "budget-skipped" if required > candidate_budget else "complete",
              "parameter_combinations": len(bank), "feasible_models": feasible_models,
              "contradicted_models": len(bank) - len(feasible_models),
              "feasible_dimension_histogram": {str(k): v for k, v in sorted(dimension_histogram.items())},
              "eligible_models": len(eligible),
              "excluded_high_dimension_models": len(feasible_models) - len(eligible),
              "raw_completions_required": required, "raw_completion_budget": candidate_budget,
              "raw_completions_evaluated": 0, "literal_reencryptions": 0,
              "distinct_plaintexts": None, "ranked_candidates": [],
              "ambiguity": None}
    if required > candidate_budget:
        return report
    candidates = {}
    for metadata, solution in eligible:
        for freedom_values, plaintext in solution.enumerate_plaintexts(max_candidates=candidate_budget):
            if any(plaintext[i] != letter for i, letter in known.items()):
                raise AssertionError("A recovery candidate violates a crib")
            key_a, key_b = solution.keys(freedom_values)
            if apply_layers(plaintext, key_a, key_b, ALPHABET, metadata["order"],
                            solution.plan.permutation) != ciphertext:
                raise AssertionError("Literal stage-by-stage candidate re-encryption failed")
            report["literal_reencryptions"] += 1
            report["raw_completions_evaluated"] += 1
            if plaintext in candidates:
                candidates[plaintext]["model_completion_multiplicity"] += 1
                continue
            score = english_score(plaintext, known)
            if not math.isfinite(score):
                raise AssertionError("Nonfinite score")
            candidates[plaintext] = {
                "plaintext": plaintext, "score": score, "model_completion_multiplicity": 1,
                "representative_model": {**metadata, "key_a": key_a, "key_b": key_b,
                                         "freedom_values": list(freedom_values)},
            }
    ranked = sorted(candidates.values(), key=lambda row: (-row["score"], row["plaintext"]))
    if report["raw_completions_evaluated"] != required:
        raise AssertionError("Incomplete enumeration")
    report["ranked_candidates"] = ranked
    report["distinct_plaintexts"] = len(ranked)
    report["ranked_candidates_sha256"] = sha256(canonical_bytes(ranked)).hexdigest()
    report["ambiguity"] = {
        "unique_plaintext_within_enumerated_models": len(ranked) == 1,
        "top_score_tie_count": sum(row["score"] == ranked[0]["score"] for row in ranked) if ranked else 0,
        "multiple_models_or_gauges_are_not_distinct_plaintexts": True,
    }
    return report


def evaluate(recovery, fixture):
    """Join the concealed synthetic truth only after recovery has returned."""
    generating = next((model for model in recovery["feasible_models"]
                       if all(model[key] == fixture[key] for key in ("route_id", "order", "period_a", "period_b"))), None)
    if generating is None:
        raise AssertionError("The planted generating model was incorrectly rejected")
    result = {"generating_model_plaintext_dimension": generating["plaintext_dimension"],
              "generating_model_inside_enumeration_scope": generating["plaintext_dimension"] <= MAX_DIMENSION,
              "recovered": None, "true_plaintext_lexical_tiebreak_rank": None,
              "true_plaintext_competition_rank": None, "true_plaintext_score": None,
              "true_score_tie_count": None, "outranking_distinct_plaintexts": None,
              "interpretation": "Budget-skipped: no recovery success or failure is assigned."}
    if recovery["status"] != "complete":
        return result
    ranked = recovery["ranked_candidates"]
    match = next(((i, row) for i, row in enumerate(ranked) if row["plaintext"] == fixture["plaintext"]), None)
    result["recovered"] = match is not None
    result["interpretation"] = "Exact plaintext inclusion/rank within the enumerated family; no authentication or key-identification claim."
    if match is not None:
        index, row = match
        greater = sum(candidate["score"] > row["score"] for candidate in ranked)
        result.update({"true_plaintext_lexical_tiebreak_rank": index + 1,
                       "true_plaintext_competition_rank": greater + 1,
                       "true_plaintext_score": row["score"],
                       "true_score_tie_count": sum(candidate["score"] == row["score"] for candidate in ranked),
                       "outranking_distinct_plaintexts": greater})
    elif generating["plaintext_dimension"] <= MAX_DIMENSION:
        raise AssertionError("Complete enumeration missed an eligible planted plaintext")
    return result


def analyze(candidate_budget=MAX_BUDGET):
    if type(candidate_budget) is not int or not 1 <= candidate_budget <= MAX_BUDGET:
        raise ValueError(f"candidate_budget must be an integer in 1..{MAX_BUDGET}")
    started = perf_counter()
    before = file_hashes()
    known, routes = crib_map(), route_bank()
    bank = compile_bank(routes, known)
    fixtures = make_fixtures(routes, known)
    config = {"alphabet": ALPHABET, "period_range": [1, MAX_PERIOD], "orders": list(ORDERS),
              "maximum_plaintext_dimension": MAX_DIMENSION, "candidate_budget_per_input": candidate_budget,
              "generation_period_pairs": [list(pair) for pair in GENERATION_PAIRS],
              "cribs_zero_based": [[i, ch] for i, ch in sorted(known.items())],
              "routes": routes, "corpus": [{"id": name, "prose": prose} for name, prose in CORPUS],
              "python_version": platform.python_version(), "python_implementation": platform.python_implementation()}
    resolved_inputs_sha256 = sha256(canonical_bytes({"config": config, "fixtures": fixtures})).hexdigest()
    cases = []
    for fixture in fixtures:
        recovered = recover(fixture["ciphertext"], known, bank, candidate_budget)
        assessment = evaluate(recovered, fixture)
        cases.append({"fixture": fixture, "recovery": recovered, "evaluation": assessment})
    after = file_hashes()
    if before != after:
        raise RuntimeError("Input source changed during the experiment; discard this result")
    complete = [case for case in cases if case["recovery"]["status"] == "complete"]
    return {
        "base_checkpoint": "K4-20261012-H", "experiment": "deterministic-in-family-recovery-matrix",
        "config": config, "resolved_inputs_sha256": resolved_inputs_sha256,
        "score_description": SCORE_DESCRIPTION, "scored_positions_per_candidate": 73,
        "summary": {"cases": len(cases), "complete_cases": len(complete),
                    "budget_skipped_cases": len(cases) - len(complete),
                    "recovered_true_plaintext_cases": sum(case["evaluation"]["recovered"] for case in complete),
                    "true_plaintext_rank_one_cases": sum(case["evaluation"]["true_plaintext_competition_rank"] == 1 for case in complete),
                    "unique_plaintext_cases": sum(case["recovery"]["distinct_plaintexts"] == 1 for case in complete),
                    "raw_completions_evaluated": sum(case["recovery"]["raw_completions_evaluated"] for case in cases),
                    "literal_reencryptions": sum(case["recovery"]["literal_reencryptions"] for case in cases)},
        "checks": {"inputs_unchanged": True, "fixture_count": 12, "parameter_combinations_per_input": 384,
                   "every_evaluated_raw_completion_reencrypted": True},
        "inputs": [{"path": path, "sha256_before": before[path], "sha256_after": after[path]} for path in SOURCE_PATHS],
        "runtime_seconds": perf_counter() - started, "cases": cases,
        "non_claims": [
            "The four authored texts and twelve fixtures are not a representative language benchmark.",
            "The generating family is guaranteed to be in the declared search bank; this does not identify the family of K4.",
            "Distinct parameter combinations can define identical ciphers; counts are not independent-hypothesis counts.",
            "Dimension above one is not enumerated, even if crib-feasible; uniqueness is conditional on the enumerated subset.",
            "Budget-skipped cases have neither success nor failure verdicts, and have no partial rank.",
            "The plaintext scorer is an uncalibrated English heuristic; rank is not authentication.",
            "Representative keys can differ from planted keys through gauge and model equivalences.",
            "No K4 candidate search, K5 input, external submission, broad route search, GPU run, or application tests.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Fresh full evidence JSON path")
    parser.add_argument("--candidate-budget", type=int, default=MAX_BUDGET,
                        help=f"Raw completions per input, 1..{MAX_BUDGET}; oversized inputs are wholly skipped")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze(args.candidate_budget)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({**result["summary"], "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
