"""Small bounded controls for unknown column order; answer orders are withheld.

Run from the project root:
    python research/columnar_benchmarks.py --output NEW_RESULTS_PATH.json
The output is created exclusively; existing evidence is never overwritten.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kryptos.columnar import recover_column_order
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS


FIXTURE = ROOT / "research/source_snapshots/sculpture-J/pk2_fixture.json"
FIXTURE_SHA256 = "ee1dfbf1a56cd7a7825f382c1081b58bd64717c9933d2897b2d2ce37c13b6ddb"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal_encrypt(plaintext, width, order):
    # Independent of the recovery module: row-filled columns sliced directly.
    return "".join(plaintext[column::width] for column in order)


def run():
    paths = [Path(__file__).resolve(), ROOT / "kryptos/columnar.py", ROOT / "kryptos/data.py", FIXTURE]
    before = {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in paths}
    if sha(FIXTURE) != FIXTURE_SHA256:
        raise ValueError("PK2 fixture differs from the source agent's verified snapshot")
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    p, c = fixture["plaintext"], fixture["ciphertext"]
    assert len(p) == len(c) == 350
    assert hashlib.sha256(p.encode()).hexdigest() == fixture["plaintext_sha256"]
    assert hashlib.sha256(c.encode()).hexdigest() == fixture["ciphertext_sha256"]
    assert literal_encrypt(p, fixture["width"], fixture["read_order"]) == c
    bounds = {"max_segmentations": 2048, "max_states": 200000, "max_candidates": 20, "time_limit_seconds": 5}
    records = []
    started = time.perf_counter()

    def record(name, ciphertext, cribs, expected_plaintext=None, expected_order=None, **geometry):
        result = recover_column_order(ciphertext, cribs, **geometry, **bounds)
        checks = {"search_complete": result["complete"],
                  "every_saved_candidate_reencrypts": all(row["reencryption_matches"] for row in result["candidates"])}
        if expected_plaintext is not None:
            checks["expected_plaintext_recovered"] = any(row["plaintext"] == expected_plaintext for row in result["candidates"])
        if expected_order is not None:
            checks["expected_order_recovered"] = any(row["column_order"] == expected_order for row in result["candidates"])
        assert all(checks.values()), (name, checks)
        records.append({"name": name, "request": {"ciphertext": ciphertext, "cribs": cribs, **geometry},
                        "checks": checks, "result": result})
        return result

    result = record("pk2_hidden_order", c,
                    [{"start": 1, "text": p[:14]}, {"start": len(p) - 6, "text": p[-7:]}],
                    p, fixture["read_order"], width=7)
    assert result["total_column_orders"] == 1 and result["unique_plaintext_within_family"]
    # The source-known order is consulted only to validate the returned result.
    records[-1]["fixture_provenance"] = fixture["plaintext_provenance"]
    records[-1]["source_paths"] = [row["path"] for row in fixture["sources"]]
    result = record("ragged_noninvolutive_hand", "CGAEIDHBFJ", [{"start": 1, "text": "ABCD"}],
                    "ABCDEFGHIJ", [2, 0, 3, 1], width=4)
    assert result["total_column_orders"] == 1
    synthetic = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    order = [4, 1, 5, 0, 3, 2]
    result = record("ragged_six_columns_hidden_order", literal_encrypt(synthetic, 6, order),
                    [{"start": 1, "text": synthetic[:6]}], synthetic, order, width=6)
    assert result["total_column_orders"] == 1
    result = record("insufficient_cribs_preserve_ambiguity", "BECFAD", [{"start": 1, "text": "A"}],
                    "ABCDEF", [1, 2, 0], width=3)
    assert result["total_column_orders"] == 2 and result["forced_plaintext_mask"] == "A??D??"
    result = record("matching_forced_edge_propagation", "ACDBEF",
                    [{"start": 2, "text": "A"}, {"start": 6, "text": "B"}],
                    "EADFCB", [1, 2, 0], width=3)
    assert result["work"]["supported_edges_removed"] == 2
    result = record("factorial_ambiguity_count", "A" * 40, [], width=20)
    assert result["total_column_orders"] == 2432902008176640000
    assert result["total_distinct_plaintexts"] == 1 and len(result["candidates"]) == 20
    # Known K4 occupancy surrogate: four cells in columns28..31, then three
    # full31-letter rows. Other sculpture cells are not treated as nulls.
    cells = [(0, 27 + i) for i in range(4)] + [(1 + i // 31, i % 31) for i in range(93)]
    result = record("k4_pure_transposition_inventory_only", K4_CIPHERTEXT, K4_CRIBS, cells=cells)
    assert result["inventory_rejection"] and result["total_column_orders"] == 0
    assert result["work"]["states"] == 0
    after = {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p) for p in paths}
    assert before == after
    return {"schema": "kryptos.columnar-benchmark.v1", "utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(), "platform": platform.platform(),
            "elapsed_seconds": time.perf_counter() - started,
            "contract": {"model": "unknown whole-column order, supplied geometry and vertical direction, pure transposition",
                         "cases": 7, "bounds_per_case": bounds,
                         "expected_answers_passed_to_recovery": False,
                         "pk2_known_plaintext_letters_supplied": 21,
                         "k4_scope": "letter inventory precheck only; no column-order search is needed",
                         "nonclaims": "A fixture benchmark and bounded model check cannot authenticate a K4 or K5 solution. No unknown surrounding substitution is tested."},
            "input_sha256_before": before, "input_sha256_after": after,
            "summary": {"cases": len(records),
                        "all_checks_pass": all(all(row["checks"].values()) for row in records),
                        "segmentations_tested": sum(row["result"]["work"]["segmentations_tested"] for row in records),
                        "charged_states": sum(row["result"]["work"]["states"] for row in records),
                        "orders_by_case": {row["name"]: row["result"]["total_column_orders"] for row in records}},
            "records": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a fresh path")
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
