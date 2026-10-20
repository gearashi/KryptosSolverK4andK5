"""Method-known PK1/PK3 recovery, using independently published full messages.

No network calls or external-code execution. Only 24 artificial supplied crib
letters enter recovery. Published keys and remaining plaintext are evaluator
data, not recovery arguments. This is not a blind method-selection benchmark.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import re
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CRIBS
from kryptos.layer_plan import compile_layer_plan
from kryptos.scoring import SCORE_DESCRIPTION, english_score

ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CACHE = ROOT / "research/source_snapshots/pk-benchmarks"
MODEL_SPECS = {"pk1": (10, 1), "pk3": (10, 8)}
MAX_CANDIDATES = 676
SOURCE_PATHS = (
    "research/pk_benchmarks.py", "kryptos/data.py", "kryptos/layer_plan.py",
    "kryptos/scoring.py", "research/source_snapshots/pk-benchmarks/sources.json",
    *tuple("research/source_snapshots/pk-benchmarks/" + name for name in (
        "pk1_result.txt", "pk3_result.txt", "verify_all_source.txt",
        "official_challenge_asset.txt", "firsthand_methods.html.txt")),
)


def digest(value):
    return sha256(value.encode("utf-8")).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def file_hashes():
    return {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def additive_stage(text, key, alphabet=ALPHABET, decrypt=False):
    """Independent literal per-character operation, not a LayerPlan helper."""
    if (not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26
            or not isinstance(text, str) or not text or not isinstance(key, str) or not key
            or any(ch not in alphabet for ch in text + key)):
        raise ValueError("A nonempty text/key and a 26-symbol alphabet are required")
    sign = -1 if decrypt else 1
    return "".join(alphabet[(alphabet.index(ch) + sign * alphabet.index(key[i % len(key)])) % 26]
                   for i, ch in enumerate(text))


def encrypt_stages(plaintext, keys, alphabet=ALPHABET):
    stages = []
    for key in keys:
        plaintext = additive_stage(plaintext, key, alphabet)
        stages.append(plaintext)
    return stages


def crib_positions():
    positions = tuple(sorted({crib["start"] - 1 + offset
                              for crib in K4_CRIBS for offset in range(len(crib["text"]))}))
    if len(positions) != 24 or positions != tuple(range(21, 34)) + tuple(range(63, 74)):
        raise ValueError("This benchmark pins exactly the existing 24 K4 crib positions")
    return positions


def load_fixtures():
    """Extract data from retained text; never import/evaluate downloaded code."""
    sources = json.loads((CACHE / "sources.json").read_text(encoding="utf-8"))
    expected_files = {Path(path).name for path in SOURCE_PATHS[5:]}
    if {entry["file"] for entry in sources["sources"]} != expected_files:
        raise ValueError("Unexpected source manifest entries")
    for entry in sources["sources"]:
        if sha256((CACHE / entry["file"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Source snapshot changed: " + entry["file"])
    asset = (CACHE / "official_challenge_asset.txt").read_text(encoding="utf-8")
    methods = (CACHE / "firsthand_methods.html.txt").read_text(encoding="utf-8")
    fixture_keys = {"pk1": ("PROVENANCE",), "pk3": ("PENTIMENTO", "ORDINATE")}
    lengths = {"pk1": 192, "pk3": 280}
    prefix_hashes = {"pk1": ("c52a2399f1f4f3f5", "86748db025480f07"),
                     "pk3": ("8f8b1cc851def197", "660ff56d93e5b99d")}
    fixtures = []
    for name, keys in fixture_keys.items():
        report = (CACHE / (name + "_result.txt")).read_text(encoding="utf-8")
        blocks = re.findall(r"(?m)^```\n(.*?)^```", report, re.S)
        plain_blocks = [re.sub(r"\s", "", block) for block in blocks
                        if re.fullmatch(r"[A-Z\s]+", block)]
        cipher_blocks = re.findall(r'slug:"' + name + r'"[^}]*ciphertext:"([A-Z]+)"', asset)
        if len(plain_blocks) != 1 or len(cipher_blocks) != 1:
            raise ValueError("Expected one unambiguous published text pair for " + name)
        plaintext, ciphertext = plain_blocks[0], cipher_blocks[0]
        if len(plaintext) != lengths[name] or len(ciphertext) != lengths[name]:
            raise ValueError("Published fixture length mismatch")
        if any(key not in methods for key in keys):
            raise ValueError("Published method key was not found in retained source")
        p_hash, c_hash = digest(plaintext), digest(ciphertext)
        if not (p_hash.startswith(prefix_hashes[name][0]) and c_hash.startswith(prefix_hashes[name][1])):
            raise ValueError("Source report's published digest prefix does not match")
        stages = encrypt_stages(plaintext, keys)
        if stages[-1] != ciphertext:
            raise AssertionError("Independent full published-fixture encryption failed: " + name)
        decrypted = ciphertext
        for key in reversed(keys):
            decrypted = additive_stage(decrypted, key, decrypt=True)
        if decrypted != plaintext:
            raise AssertionError("Full published-fixture decryption failed")
        # A separately published effective key provides a second PK3 check.
        combined_key = None
        if name == "pk3":
            combined_key = "BFPNBZITCSGKFENPJQHQVMWIQNUBWFAVXOZATKBJ"
            if combined_key not in report or additive_stage(plaintext, combined_key) != ciphertext:
                raise AssertionError("Published PK3 period-40 key failed independent round trip")
        fixtures.append({"id": name, "length": len(plaintext), "plaintext": plaintext,
                         "ciphertext": ciphertext, "published_keys": list(keys),
                         "published_combined_key": combined_key,
                         "plaintext_sha256": p_hash, "ciphertext_sha256": c_hash,
                         "encryption_stage_sha256": [digest(stage) for stage in stages],
                         "published_pair_roundtrip": True})
    return fixtures, sources


def recover(ciphertext, known, period_a, period_b, candidate_budget=MAX_CANDIDATES):
    """Keys and unknown plaintext are absent from this method-known interface."""
    if type(candidate_budget) is not int or not 1 <= candidate_budget <= MAX_CANDIDATES:
        raise ValueError("candidate_budget must be an integer in 1..676")
    plan = compile_layer_plan(len(ciphertext), known, "SST", range(len(ciphertext)), period_a, period_b)
    solved = plan.solve(ciphertext, known, ALPHABET)
    report = {"period_a": period_a, "period_b": period_b, "order": "SST",
              "route": "identity", "plaintext_dimension": plan.plaintext_dimension,
              "crib_components": plan.component_count, "full_components": plan.full_component_count,
              "feasible": solved["feasible"], "candidate_budget": candidate_budget,
              "required_candidates": 0, "evaluated_candidates": 0, "literal_reencryptions": 0,
              "ranked_candidates": [], "prediction_mask": None}
    if not solved["feasible"]:
        report.update(status="contradicted", conflict_edge=solved["conflict_edge"],
                      residual_mod_26=solved["residual_mod_26"])
        return report
    solution = solved["solution"]
    report["required_candidates"] = solution.distinct_plaintext_count
    report["prediction_mask"] = solution.prediction_mask()
    if solution.distinct_plaintext_count > candidate_budget:
        report["status"] = "budget-skipped"
        return report
    report["status"] = "complete"
    for values, plaintext in solution.enumerate_plaintexts(max_candidates=candidate_budget):
        keys = solution.keys(values)
        stages = encrypt_stages(plaintext, keys)
        if stages[-1] != ciphertext or any(plaintext[i] != ch for i, ch in known.items()):
            raise AssertionError("Candidate does not literally re-encrypt or violates a supplied crib")
        score = english_score(plaintext, known)
        if not math.isfinite(score):
            raise AssertionError("Nonfinite candidate score")
        report["ranked_candidates"].append({"plaintext": plaintext, "score": score,
                                           "representative_keys": list(keys),
                                           "freedom_values": list(values),
                                           "stage_sha256": [digest(stage) for stage in stages]})
        report["evaluated_candidates"] += 1
        report["literal_reencryptions"] += 1
    report["ranked_candidates"].sort(key=lambda row: (-row["score"], row["plaintext"]))
    if (report["evaluated_candidates"] != report["required_candidates"]
            or len({row["plaintext"] for row in report["ranked_candidates"]}) != report["evaluated_candidates"]):
        raise AssertionError("Enumeration is incomplete or duplicates plaintexts")
    return report


def assess(recovery, expected_plaintext):
    evaluation = {"exact_plaintext_recovered": None, "true_plaintext_lexical_tiebreak_rank": None,
                  "true_plaintext_competition_rank": None, "true_score_tie_count": None,
                  "unique_plaintext_within_supplied_model": None}
    if recovery["status"] != "complete":
        return evaluation
    ranked = recovery["ranked_candidates"]
    matches = [(i, row) for i, row in enumerate(ranked) if row["plaintext"] == expected_plaintext]
    evaluation["exact_plaintext_recovered"] = bool(matches)
    evaluation["unique_plaintext_within_supplied_model"] = len(ranked) == 1
    if matches:
        i, row = matches[0]
        evaluation.update(true_plaintext_lexical_tiebreak_rank=i + 1,
                          true_plaintext_competition_rank=1 + sum(c["score"] > row["score"] for c in ranked),
                          true_score_tie_count=sum(c["score"] == row["score"] for c in ranked))
    return evaluation


def self_test():
    # Literal standard-alphabet arithmetic: A+1+3=E, B+2+1=E, etc.
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if encrypt_stages("ABCD", ("BC", "DB"), standard) != ["BDDF", "EEGG"]:
        raise AssertionError("Independent two-stage hand vector failed")
    if additive_stage("KR", "RR") != "RY" or additive_stage("RY", "RR", decrypt=True) != "KR":
        raise AssertionError("KRYPTOS-alphabet hand vector failed")
    plan = compile_layer_plan(4, (0, 1), "SST", range(4), 2, 2)
    solved = plan.solve("EEGG", {0: "A", 1: "B"}, standard)
    if not solved["feasible"] or solved["solution"].plaintext(()) != "ABCD":
        raise AssertionError("Compiled model disagrees with independent hand vector")
    bad = compile_layer_plan(4, (0, 1, 2), "SST", range(4), 2, 2)
    if bad.solve("EEGG", {0: "A", 1: "B", 2: "D"}, standard)["feasible"]:
        raise AssertionError("Deliberately incompatible hand crib was accepted")
    fixtures, _ = load_fixtures()
    return {"tiny_hand_controls": "passed", "published_full_roundtrips": [
        {"id": f["id"], "length": f["length"], "plaintext_sha256": f["plaintext_sha256"],
         "ciphertext_sha256": f["ciphertext_sha256"]} for f in fixtures],
        "canonical_recovery_run_performed": False}


def analyze(candidate_budget=MAX_CANDIDATES):
    if type(candidate_budget) is not int or not 1 <= candidate_budget <= MAX_CANDIDATES:
        raise ValueError("candidate_budget must be an integer in 1..676")
    started, before = perf_counter(), file_hashes()
    self_test()
    fixtures, sources = load_fixtures()
    positions, cases = crib_positions(), []
    for fixture in fixtures:
        known = {i: fixture["plaintext"][i] for i in positions}
        period_a, period_b = MODEL_SPECS[fixture["id"]]
        recovered = recover(fixture["ciphertext"], known, period_a, period_b, candidate_budget)
        evaluation = assess(recovered, fixture["plaintext"])
        if not recovered["feasible"]:
            raise AssertionError("A verified published fixture was rejected by its supplied model")
        if recovered["status"] == "complete" and not evaluation["exact_plaintext_recovered"]:
            raise AssertionError("Complete enumeration omitted the verified published plaintext")
        cases.append({"fixture": fixture, "artificial_supplied_cribs_zero_based": [[i, ch] for i, ch in known.items()],
                      "scored_position_count": fixture["length"] - len(known),
                      "recovery": recovered, "evaluation": evaluation})
    after = file_hashes()
    if before != after:
        raise RuntimeError("Input changed during the run; discard this output")
    contract = {"full_messages": True, "alphabet": ALPHABET, "method_known": True,
                "supplied_period_pairs": {k: list(v) for k, v in MODEL_SPECS.items()},
                "supplied_route": "identity", "supplied_order": "SST",
                "crib_positions_zero_based": list(positions), "crib_letters": "actual fixture letters, not K4 phrases",
                "candidate_budget_per_case": candidate_budget,
                "pk1_representation": "period-10 substitution plus an unknown constant shift; equivalent to one period-10 stage",
                "python_version": platform.python_version(), "python_implementation": platform.python_implementation()}
    return {"experiment": "published-pk1-pk3-method-known-recovery", "contract": contract,
            "resolved_inputs_sha256": digest(canonical({"contract": contract, "fixtures": fixtures})),
            "sources": sources, "score_description": SCORE_DESCRIPTION,
            "summary": {"cases": len(cases), "complete_cases": sum(c["recovery"]["status"] == "complete" for c in cases),
                        "budget_skipped_cases": sum(c["recovery"]["status"] == "budget-skipped" for c in cases),
                        "recovered_cases": sum(c["evaluation"]["exact_plaintext_recovered"] is True for c in cases),
                        "unique_plaintext_cases": sum(c["evaluation"]["unique_plaintext_within_supplied_model"] is True for c in cases),
                        "literal_reencryptions": sum(c["recovery"]["literal_reencryptions"] for c in cases)},
            "checks": {"inputs_unchanged": True, "every_candidate_reencrypted": True,
                       "published_full_pairs_verified": True, "external_code_executed": False},
            "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in SOURCE_PATHS],
            "cases": cases, "runtime_seconds": perf_counter() - started,
            "non_claims": ["Artificial supplied cribs are not official PK clues; methods and periods are given.",
                           "Published keys and unknown plaintext do not enter recovery, but this is not a human blind test.",
                           "Two published texts do not establish language-score calibration or general recovery rates.",
                           "Gauge-equivalent representative keys need not equal the published words.",
                           "A budget-skipped case has no recovery success/failure verdict or rank.",
                           "Exact reencryption verifies the stated pair and method, not authorial intent or K4/K5 methods.",
                           "No external submission, external-code execution, K4 search, GPU job, or application tests."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidate-budget", type=int, default=MAX_CANDIDATES)
    args = parser.parse_args()
    if args.self_test:
        if args.output is not None:
            parser.error("--self-test does not write a canonical recovery output")
        print(json.dumps(self_test(), indent=2))
        return
    if args.output is None:
        parser.error("--output is required for the canonical recovery run")
    if args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze(args.candidate_budget)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({**result["summary"], "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
