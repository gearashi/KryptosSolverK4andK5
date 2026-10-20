"""Tiny deterministic audit of two distinct ENE/BC interpretations.

Read existing layer results; do not launch a new cryptanalytic search. Preserve
the literal 97-position crib mask before applying an explicitly declared pair
of variable-length replacements. Inputs are hashed before and after the read.

Run from the project root:
    python research/semantic_constraints.py
Optionally save the full JSON with --output PATH. Only that destination is written.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
EXPECTED_CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
EXPECTED_CRIBS = [
    {"start": 22, "text": "EAST"}, {"start": 26, "text": "NORTHEAST"},
    {"start": 64, "text": "BERLIN"}, {"start": 70, "text": "CLOCK"},
]
SELECTED_PERIODS = {(3, 2), (2, 3)}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal_inputs(path):
    """Read only literal constants from the source; do not execute that module."""
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    values = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in ("K4_CIPHERTEXT", "K4_CRIBS"):
                    values[target.id] = ast.literal_eval(statement.value)
    ciphertext, cribs = values["K4_CIPHERTEXT"], values["K4_CRIBS"]
    if ciphertext != EXPECTED_CIPHERTEXT or cribs != EXPECTED_CRIBS:
        raise ValueError("literal K4 inputs differ from the pinned 97-letter/24-crib scope")
    return ciphertext, cribs


def mask_replacements(ciphertext, cribs):
    mask = ["?"] * len(ciphertext)
    known = {}
    for crib in cribs:
        for offset, symbol in enumerate(crib["text"]):
            i = crib["start"] - 1 + offset
            if i in known and known[i] != symbol:
                raise ValueError("contradictory literal cribs")
            known[i] = symbol
            mask[i] = symbol
    original = "".join(mask)
    assert len(original) == 97 and len(known) == 24 and original.count("?") == 73
    assert original[21:34] == "EASTNORTHEAST" and original[63:74] == "BERLINCLOCK"
    compass = original[:21] + "ENE" + original[34:63] + "BC" + original[74:]
    word_initials = original[:21] + "EN" + original[34:63] + "BC" + original[74:]
    assert len(compass) == 78 and compass.count("?") == 73
    assert len(word_initials) == 77 and word_initials.count("?") == 73
    assert compass[21:24] == "ENE" and compass[53:55] == "BC"
    assert word_initials[21:23] == "EN" and word_initials[52:54] == "BC"
    return known, {
        "literal_mask": original, "literal_length": 97, "literal_known_positions": 24,
        "unchanged_unknown_positions": 73,
        "only_two_declared_phrase_replacements": {
            "rules": {"EASTNORTHEAST": "ENE", "BERLINCLOCK": "BC"},
            "mask": compass, "length": len(compass),
            "new_phrase_positions_one_based": {"ENE": [22, 24], "BC": [54, 55]},
            "arithmetic": "97 - 13 - 11 + 3 + 2 = 78",
        },
        "literal_word_initials_alternative": {
            "segments": [["EAST", "NORTHEAST"], ["BERLIN", "CLOCK"]],
            "initials": ["EN", "BC"], "mask": word_initials,
            "length": len(word_initials), "arithmetic": "97 - 13 - 11 + 2 + 2 = 77",
        },
        "split_compound_initials_alternative": {
            "segments": [["EAST", "NORTH", "EAST"], ["BERLIN", "CLOCK"]],
            "initials": ["ENE", "BC"], "length": len(compass),
        },
        "interpretation": "These are masks under explicit local replacement rules, not recovered messages or lengths of K5.",
    }


def verify_witness(row, model, ciphertext, known, alphabet):
    """Recompute every selected certificate without importing the graph solver."""
    permutation = [position - 1 for position in row["source_positions_one_based"]]
    assert sorted(permutation) == list(range(len(ciphertext)))
    inverse = [0] * len(permutation)
    for output, source in enumerate(permutation):
        inverse[source] = output
    a, b, order = model["period_a"], model["period_b"], row["order"]
    balances_a, balances_b = Counter(), Counter()
    signed_residue = 0
    witness = model["witness"]
    if not witness or not witness["cycle"]:
        raise ValueError("a recorded rejection has no certificate")
    for i1, j1, a1, b1, residue, coefficient in witness["cycle"]:
        i, j = i1 - 1, j1 - 1
        assert i in known and inverse[i] == j
        if order == "SST":
            phase_a, phase_b = i % a, i % b
        elif order == "STS":
            phase_a, phase_b = i % a, j % b
        elif order == "TSS":
            phase_a, phase_b = j % a, j % b
        else:
            raise ValueError("unknown layer order")
        assert (a1, b1) == (phase_a + 1, phase_b + 1)
        assert residue == (alphabet.index(ciphertext[j]) - alphabet.index(known[i])) % 26
        assert coefficient in (-1, 1)
        balances_a[phase_a] += coefficient
        balances_b[phase_b] += coefficient
        signed_residue += coefficient * residue
    assert all(value == 0 for value in balances_a.values())
    assert all(value == 0 for value in balances_b.values())
    assert signed_residue % 26 == witness["residual_mod_26"] != 0


def inspect_stored_models(results, ciphertext, known):
    assert results["checkpoint"] == "K4-20261012-D"
    assert results["alphabet"] == EXPECTED_ALPHABET
    assert results["period_range"] == [1, 16]
    assert results["distinct_routes"] == 29
    assert set(results["orders"]) == {"SST", "STS", "TSS"}
    routes, route_orders, summary, examples = set(), set(), {}, {}
    selected_count = feasible_count = certificate_count = 0
    for row in results["records"]:
        route = tuple(row["source_positions_one_based"])
        assert sorted(route) == list(range(1, 98))
        route_order = (route, row["order"])
        assert route_order not in route_orders
        route_orders.add(route_order)
        routes.add(route)
        selected = [model for model in row["models"]
                    if (model["period_a"], model["period_b"]) in SELECTED_PERIODS]
        assert len(selected) == 2
        assert {(model["period_a"], model["period_b"]) for model in selected} == SELECTED_PERIODS
        for model in selected:
            selected_count += 1
            key = f"{row['order']}:({model['period_a']},{model['period_b']})"
            group = summary.setdefault(key, {"models": 0, "feasible": 0, "contradicted": 0, "certificates_verified": 0})
            group["models"] += 1
            if model["feasible"]:
                feasible_count += 1
                group["feasible"] += 1
            else:
                verify_witness(row, model, ciphertext, known, results["alphabet"])
                certificate_count += 1
                group["contradicted"] += 1
                group["certificates_verified"] += 1
                examples.setdefault(key, {
                    "route_aliases": row["aliases"],
                    "order": row["order"], "period_a": model["period_a"], "period_b": model["period_b"],
                    "witness": model["witness"],
                })
    assert len(routes) == 29 and len(route_orders) == 29 * 3
    assert selected_count == 29 * 3 * 2 == 174
    assert len(summary) == 6 and all(group["models"] == 29 for group in summary.values())
    return {
        "interpretation": "Alternative hypothesis: ENE and BC are literal repeating additive keys, not abbreviations after decryption.",
        "source_checkpoint": results["checkpoint"], "alphabet": results["alphabet"],
        "period_pairs": [[3, 2], [2, 3]], "routes": 29, "orders": ["SST", "STS", "TSS"],
        "selected_models": selected_count, "feasible": feasible_count,
        "contradicted": selected_count - feasible_count, "certificates_verified": certificate_count,
        "all_selected_period_models_ruled_out": feasible_count == 0,
        "by_order_and_period_pair": summary, "certificate_examples": examples,
        "scope": "Arbitrary keys of these lengths are covered; literal ENE/BC are subsets. Other routes, alphabets, phase-reset rules, and post-decryption codebooks are not covered.",
    }


def analyze():
    started = datetime.now(timezone.utc).isoformat()
    timer = time.perf_counter()
    relative_inputs = [
        "kryptos/data.py", "research/SEMANTIC_LAYER.md", "research/semantic_constraints.py",
        "research/runs/layers-001/results.json", "research/runs/layers-001/manifest.json",
    ]
    paths = {name: ROOT / name for name in relative_inputs}
    before = {name: sha256(path) for name, path in paths.items()}
    old_manifest = json.loads(paths["research/runs/layers-001/manifest.json"].read_text(encoding="utf-8"))
    old_results = json.loads(paths["research/runs/layers-001/results.json"].read_text(encoding="utf-8"))
    old_result_hash = next(item["sha256"] for item in old_manifest["outputs"]
                           if item["path"] == "research/runs/layers-001/results.json")
    assert before["research/runs/layers-001/results.json"] == old_result_hash
    historical_data_hash = next(item["sha256"] for item in old_manifest["input_artifacts"]
                                if item["path"] == "kryptos/data.py")
    ciphertext, cribs = literal_inputs(paths["kryptos/data.py"])
    known, replacements = mask_replacements(ciphertext, cribs)
    key_interpretation = inspect_stored_models(old_results, ciphertext, known)
    after = {name: sha256(path) for name, path in paths.items()}
    assert before == after
    return {
        "base_checkpoint": "K4-20261012-E", "task": "ENE/BC distinction and finite stored-result audit",
        "started_at": started, "runtime_seconds": time.perf_counter() - timer,
        "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
        "input_artifacts": [{"path": name, "sha256": before[name], "sha256_after": after[name]}
                            for name in relative_inputs],
        "checks": {"input_hashes_unchanged": before == after,
                   "stored_layer_results_match_original_manifest": True,
                   "current_data_file_matches_layer_manifest": before["kryptos/data.py"] == historical_data_hash,
                   "literal_ciphertext_and_cribs_match_pinned_scope": True},
        "replacement_arithmetic": replacements, "alternative_key_interpretation": key_interpretation,
        "non_claims": [
            "No K4 or K5 decryption, length discovery, language score, novelty, or probabilistic claim.",
            "No new cryptanalytic search: only 174 selected existing classifications and certificates were checked.",
            "No contradiction to an abbreviation or codebook applied after decrypting the original 97 symbols.",
            "The 78 and 77 lengths assume only the two specified replacements and leave 73 positions unknown.",
            "The letter string EASTNORTHEAST does not itself choose between EAST|NORTHEAST and EAST|NORTH|EAST.",
            "Full app tests and large CPU/GPU searches remain unperformed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze()
    if args.output:
        output = args.output.resolve()
        protected = {ROOT / item["path"] for item in result["input_artifacts"]}
        if output in protected:
            raise ValueError("output must not overwrite an input")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
