"""Checkpoint-K joint column/key controls and an opt-in fixed18-model K4 probe.

Development controls only:
    python research/joint_columnar_K.py --output NEW_PATH.json
Parent's predeclared bounded canonical probe:
    python research/joint_columnar_K.py --include-k4 --output NEW_PATH.json
Existing outputs are never overwritten. No answer keys/orders enter recovery.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import string
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.joint_columnar import recover_joint_columnar


FIXTURE = ROOT / "research/source_snapshots/sculpture-J/pk2_fixture.json"
FIXTURE_HASH = "ee1dfbf1a56cd7a7825f382c1081b58bd64717c9933d2897b2d2ce37c13b6ddb"
CONTROL_BOUNDS = {"max_segmentations": 2048, "max_states": 200000, "max_candidates": 20, "time_limit_seconds": 5}
K4_BOUNDS = {"max_segmentations": 128, "max_states": 20000, "max_candidates": 3, "time_limit_seconds": 1}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal(plaintext, width, columns, key, order, cipher="vigenere", alphabet=string.ascii_uppercase):
    def substitute(text):
        result = []
        for i, letter in enumerate(text):
            p, k = alphabet.index(letter), alphabet.index(key[i % len(key)])
            result.append(alphabet[(p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k) % 26])
        return "".join(result)
    def gather(text):
        return "".join(text[col::width] for col in columns)
    return gather(substitute(plaintext)) if order == "ST" else substitute(gather(plaintext))


def run(include_k4=False):
    files = [Path(__file__).resolve(), ROOT / "kryptos/joint_columnar.py", ROOT / "kryptos/columnar.py",
             ROOT / "kryptos/data.py", FIXTURE]
    before = {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in files}
    assert sha(FIXTURE) == FIXTURE_HASH
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    plaintext = fixture["plaintext"]
    assert hashlib.sha256(plaintext.encode()).hexdigest() == fixture["plaintext_sha256"]
    assert "".join(plaintext[col::7] for col in fixture["read_order"]) == fixture["ciphertext"]
    started, records = time.perf_counter(), []

    def control(name, ciphertext, cribs, expected_plaintext=None, expected_order=None, expected_key=None, **model):
        result = recover_joint_columnar(ciphertext, cribs, **model, **CONTROL_BOUNDS)
        checks = {"complete": result["complete"],
                  "all_complete_candidates_reencrypt": all(row["evidence"]["literal_reencryption_matches"]
                      for row in result["candidates"] if row["recipe_complete_for_message"])}
        if expected_plaintext is not None:
            checks["planted_key_order_plaintext_present"] = any(
                row["plaintext"] == expected_plaintext and row["column_order"] == expected_order
                and row["key_pattern"] == expected_key for row in result["candidates"])
        assert all(checks.values()), (name, checks, result["stop_reason"])
        records.append({"name": name, "kind": "control", "request": {"ciphertext": ciphertext, "cribs": cribs, **model},
                        "checks": checks, "result": result})
        return result

    for order in ("ST", "TS"):
        for cipher in ("vigenere", "beaufort", "variant"):
            ciphertext = literal(plaintext, 7, fixture["read_order"], "DOG", order, cipher)
            result = control("synthetic_substitution_wrapped_pk2_" + order + "_" + cipher, ciphertext,
                             [{"start": 1, "text": plaintext[:14]}, {"start": len(plaintext) - 6, "text": plaintext[-7:]}],
                             plaintext, fixture["read_order"], "DOG", width=7, period=3,
                             order=order, cipher=cipher, alphabet="standard")
            records[-1]["truth_provenance"] = "Synthetic extra substitution wrapped around source-verified PK2. Published text/order and synthetic key are withheld from recovery except21 plaintext crib letters; supplied width, period, order and cipher rule remain assumptions."
            records[-1]["unique_joint_recovery"] = result["total_order_key_assignments"] == 1
    hand = control("ragged_hand", "DKBIJHIFGN", [{"start": 1, "text": "ABCDEFGHIJ"}],
                   "ABCDEFGHIJ", [2, 0, 3, 1], "BE", width=4, period=2, order="TS", alphabet="standard")
    partial = control("partial_keys_preserved", "ABCDEFGH", [{"start": 1, "text": "A"}],
                      width=2, period=3, alphabet="standard")
    assert partial["total_order_key_assignments"] == 1352 and all(row["plaintext"] is None for row in partial["candidates"])
    symmetry = control("factorial_and_free_key_shortcut", "A" * 40, [], width=20, period=3)
    assert symmetry["total_column_orders"] == 2432902008176640000
    assert symmetry["total_order_key_assignments"] == 2432902008176640000 * 26 ** 3
    assert symmetry["work"]["branches"] == 0
    rejection = control("matching_not_sufficient", "AB", [{"start": 1, "text": "AA"}],
                        width=2, period=1, alphabet="standard")
    assert rejection["total_order_key_assignments"] == 0 and rejection["work"]["phase_support_rejections"] > 0
    k4_records = []
    if include_k4:
        for width in (7, 8, 10):
            for period in (2, 3, 4):
                for order in ("ST", "TS"):
                    model = {"width": width, "period": period, "order": order,
                             "cipher": "vigenere", "alphabet": "kryptos"}
                    result = recover_joint_columnar(K4_CIPHERTEXT, K4_CRIBS, **model, **K4_BOUNDS)
                    k4_records.append({"model": model, "result": result})
    after = {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in files}
    assert before == after
    return {"schema": "kryptos.joint-columnar-benchmarks.K.v1", "utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(), "platform": platform.platform(),
            "elapsed_seconds": time.perf_counter() - started,
            "contract": {"arithmetic": "Exact residues modulo26, labelled finite permutations, integer counts",
                         "convention": "ST/TS encryption order; gather output[j]=input[permutation[j]]; one-based original plaintext cribs",
                         "control_cases": 10, "control_bounds": CONTROL_BOUNDS,
                         "k4_included": include_k4, "k4_models": 18 if include_k4 else 0,
                         "k4_widths": [7, 8, 10], "k4_periods": [2, 3, 4], "k4_orders": ["ST", "TS"],
                         "k4_cipher": "vigenere", "k4_alphabet": "kryptos", "k4_bounds_per_model": K4_BOUNDS,
                         "workers": 1, "gpu": False, "answer_keys_or_orders_supplied_to_recovery": False,
                         "nonclaims": ["Substitution-wrapped PK2 is a synthetic layered fixture, not a claim about published PK2's method.",
                                        "Counts are within each declared period and geometry; summing them would double-count some equivalent models.",
                                        "A truncated K4 model is inconclusive; this family excludes other geometries, alphabets, stage orders, and cipher systems.",
                                        "Neither a fit nor a reencryption authenticates K4 or K5."]},
            "input_sha256_before": before, "input_sha256_after": after,
            "summary": {"control_cases": len(records), "all_control_checks_pass": True,
                        "controls_unique_joint_recoveries": sum(row.get("unique_joint_recovery", False) for row in records),
                        "control_states": sum(row["result"]["work"]["states"] for row in records),
                        "k4_models": len(k4_records), "k4_complete": sum(row["result"]["complete"] for row in k4_records),
                        "k4_truncated": sum(row["result"]["truncated"] for row in k4_records),
                        "k4_proved_infeasible": sum(row["result"]["feasible"] is False for row in k4_records),
                        "k4_with_witness": sum(row["result"]["feasible"] is True for row in k4_records),
                        "k4_states": sum(row["result"]["work"]["states"] for row in k4_records)},
            "controls": records, "k4": k4_records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-k4", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output path")
    result = run(args.include_k4)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
