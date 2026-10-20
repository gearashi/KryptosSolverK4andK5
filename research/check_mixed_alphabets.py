"""Bounded test of changing the alphabet between two substitution stages.

Reuses exactly the 29 recorded permutations, all three layer placements, and
four prespecified key-length pairs. Keys are arbitrary, not dictionary words.
"""
from __future__ import annotations
import argparse
import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research.mixed_alphabet_constraints import check_mixed_layers, self_test

ALPHABETS = {"standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
PERIODS = ((3, 2), (2, 3), (10, 8), (8, 10))


def inputs():
    values = {}
    for statement in ast.parse((ROOT / "kryptos/data.py").read_text(encoding="utf-8-sig")).body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in ("K4_CIPHERTEXT", "K4_CRIBS"):
                    values[target.id] = ast.literal_eval(statement.value)
    ciphertext = values["K4_CIPHERTEXT"]
    known = {c["start"] - 1 + j: value for c in values["K4_CRIBS"] for j, value in enumerate(c["text"])}
    assert len(ciphertext) == 97 and len(known) == 24
    path = ROOT / "research/runs/layers-001/results.json"
    manifest = json.loads((ROOT / "research/runs/layers-001/manifest.json").read_text())
    expected = next(x["sha256"] for x in manifest["outputs"] if x["path"] == "research/runs/layers-001/results.json")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    prior = json.loads(path.read_text())
    assert prior["checkpoint"] == "K4-20261012-D" and prior["distinct_routes"] == 29
    return ciphertext, known, prior


def independent_encrypt(plaintext, key_a, key_b, alpha_a, alpha_b, order, pi):
    text = list(plaintext)
    substitutions = iter(((alpha_a, key_a), (alpha_b, key_b)))
    for op in order:
        if op == "T":
            text = [text[source] for source in pi]
        else:
            alphabet, key = next(substitutions)
            text = [alphabet[(alphabet.index(c) + alphabet.index(key[i % len(key)])) % 26]
                    for i, c in enumerate(text)]
    return "".join(text)


def analyze():
    benchmark = self_test()
    ciphertext, known, prior = inputs()
    records, summary = [], defaultdict(lambda: {"models": 0, "fits": 0, "contradictions": 0})
    controls = 0
    route_orders = set()
    for row in prior["records"]:
        pi = [i - 1 for i in row["source_positions_one_based"]]
        assert sorted(pi) == list(range(97))
        route_order = (tuple(pi), row["order"])
        assert route_order not in route_orders
        route_orders.add(route_order)
        models = []
        old_models = {(m["period_a"], m["period_b"]): m for m in row["models"]}
        for name_a, alphabet_a in ALPHABETS.items():
            for name_b, alphabet_b in ALPHABETS.items():
                for p, q in PERIODS:
                    result = check_mixed_layers(ciphertext, known, alphabet_a, alphabet_b,
                                                row["order"], pi, p, q)
                    assert bool(result["total_key_pairs"]) == result["feasible"]
                    if name_a == name_b == "kryptos":
                        assert result["feasible"] == old_models[p, q]["feasible"]
                        controls += 1
                    if result["feasible"]:
                        plain, keys = result["representative_plaintext"], result["keys"]
                        assert all(plain[i] == value for i, value in known.items())
                        assert independent_encrypt(plain, keys["a"], keys["b"], alphabet_a, alphabet_b,
                                                   row["order"], pi) == ciphertext
                    group = summary[f"{name_a}/{name_b}:{row['order']}:({p},{q})"]
                    group["models"] += 1
                    group["fits" if result["feasible"] else "contradictions"] += 1
                    models.append({"alphabet_a": name_a, "alphabet_b": name_b,
                                   "period_a": p, "period_b": q, "result": result})
        records.append({"aliases": row["aliases"], "order": row["order"],
                        "source_positions_one_based": row["source_positions_one_based"], "models": models})
    assert len(route_orders) == 87 and controls == 348
    count = sum(group["models"] for group in summary.values())
    assert count == 1392 and all(group["models"] == 29 for group in summary.values())
    fits = sum(group["fits"] for group in summary.values())
    return {"checkpoint": "K4-20261012-G", "base_checkpoint": "K4-20261012-F",
            "alphabet_definitions": ALPHABETS, "period_pairs": PERIODS,
            "models": count, "fits": fits, "contradictions": count - fits,
            "shared_kryptos_regressions": controls, "benchmarks": benchmark,
            "summary": dict(summary), "records": records,
            "scope": "Two additive substitutions, each with its own fixed alphabet from standard/KRYPTOS, one of 29 recorded gather permutations, three placements, four declared key-length pairs; arbitrary keys.",
            "non_claims": ["No arbitrary-alphabet exclusion", "No complete transposition search", "No decipherment from a crib fit", "No proof that K4 actually uses these layer types", "No language ranking or full app test"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh output path.")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("models", "fits", "contradictions", "shared_kryptos_regressions")}))
