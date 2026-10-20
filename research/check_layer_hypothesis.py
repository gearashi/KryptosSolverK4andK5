"""Bounded exact test of the user's two-substitution-plus-transposition idea.

Every crib contributes an equation between two key slots. Contradictions rule
out all possible keys of that length pair under the stated model. A consistent
graph is only a crib fit; its arbitrary representative is not a candidate solve.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from research.check_classes import ALPHABETS
from research.check_physical_routes import routes
from research.layer_constraints import check_layers, self_test
from research.k3_reference import route_indices, validate as validate_k3


def hypothesis_routes():
    result = routes()
    for widths in ((24, 8), (8, 24)):
        permutation = tuple(range(97))
        for width in widths:
            permutation = tuple(permutation[i] for i in route_indices(97, width))
        inverse = [0] * 97
        for output, original in enumerate(permutation):
            inverse[original] = output
        assert sorted(permutation) == list(range(97))
        for direction, item in (("forward", permutation), ("inverse", tuple(inverse))):
            result.setdefault(item, []).append(f"K3-inspired-ragged-widths{widths[0]},{widths[1]}/{direction}")
    return result


def analyze():
    validation = {"graph_hand_checks": self_test(), "k3_known_pair": validate_k3()}
    known = {crib["start"] - 1 + offset: letter
             for crib in K4_CRIBS for offset, letter in enumerate(crib["text"])}
    records, samples = [], []
    total, fit, failed_reencryptions = 0, 0, 0
    # K1/K2's keyed alphabet is fixed in this first implementation of the idea.
    alphabet = ALPHABETS["kryptos"]
    for permutation, aliases in hypothesis_routes().items():
        for order in ("SST", "STS", "TSS"):
            models = []
            for a in range(1, 17):
                for b in range(1, 17):
                    result = check_layers(K4_CIPHERTEXT, known, alphabet, order,
                                          list(permutation), a, b)
                    total += 1
                    row = {"period_a": a, "period_b": b,
                           "feasible": result["feasible"],
                           "witness": None if result["feasible"] else {
                               "residual_mod_26": result["witness"]["residual_mod_26"],
                               "cycle": [[e["plaintext_position"], e["ciphertext_position"],
                                          e["key_a_position"], e["key_b_position"],
                                          e["residue"], e["coefficient"]]
                                         for e in result["witness"]["cycle_edges"]]},
                           "free_components": result.get("free_components")}
                    if result["feasible"]:
                        fit += 1
                        plain = result["representative_plaintext"]
                        correct = (result["reencrypted_ciphertext"] == K4_CIPHERTEXT
                                   and all(plain[i] == p for i, p in known.items()))
                        failed_reencryptions += not correct
                        assert correct
                        if len(samples) < 5:
                            samples.append({"aliases": aliases, "order": order,
                                            "period_a": a, "period_b": b,
                                            "keys": result["keys"],
                                            "plaintext": plain,
                                            "label": "Arbitrary graph completion, NOT a decryption claim"})
                    models.append(row)
            records.append({"aliases": aliases, "order": order,
                            "source_positions_one_based": [i + 1 for i in permutation],
                            "tested": len(models),
                            "crib_fits": sum(row["feasible"] for row in models),
                            "original_length_pairs": [row for row in models
                                                      if (row["period_a"], row["period_b"])
                                                      in ((10, 8), (8, 10))],
                            "models": models})
    return {"checkpoint": "K4-20261012-D", "base_checkpoint": "K4-20261012-C",
            "hypothesis": "Two additive substitutions with independently chosen repeating keys, plus one specified route transposition",
            "alphabet": alphabet, "period_range": [1, 16],
            "distinct_routes": len(hypothesis_routes()),
            "validation": validation,
            "witness_cycle_columns": ["plaintext_position_1based", "ciphertext_position_1based", "key_a_position_1based", "key_b_position_1based", "residue", "signed_coefficient"],
            "transposition_convention": "T(x)[j]=x[permutation[j]], zero-based",
            "orders": {"SST": "substitution A, substitution B, transposition",
                       "STS": "substitution A, transposition, substitution B",
                       "TSS": "transposition, substitution A, substitution B"},
            "model_count": total, "crib_fit_count": fit,
            "contradicted_count": total - fit,
            "failed_reencryptions": failed_reencryptions,
            "arbitrary_fit_examples": samples, "records": records,
            "non_claims": ["Physical-grid scans and explicit ragged adaptations of a known-pair-equivalent K3 procedure; no adaptation is authenticated for K4.",
                           "All results are conditional on fixed shared KRYPTOS alphabet and additive substitutions.",
                           "Passing means some keys fit 24 clues, not that the text is English or authentic.",
                           "Other periods, keyed alphabets, nulls, grids, and transposition keys remain open.",
                           "Keys are arbitrary graph representatives, not discovered historical keys."]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("model_count", "crib_fit_count", "contradicted_count", "failed_reencryptions")}))
    for order in result["orders"]:
        rows = [row for row in result["records"] if row["order"] == order]
        originals = [model for row in rows for model in row["original_length_pairs"]]
        print(order, "fits", sum(row["crib_fits"] for row in rows),
              "original-length fits", sum(model["feasible"] for model in originals),
              "of", len(originals))
    for row in result["records"]:
        if any(alias.startswith("K3-inspired") for alias in row["aliases"]):
            print(row["aliases"], row["order"], "fits", row["crib_fits"],
                  "8/10 fits", sum(model["feasible"] for model in row["original_length_pairs"]))


if __name__ == "__main__":
    main()
