"""Exact bounded test of numeric-coordinate shifts a*r+b*c+d modulo 26.

Same routes, alphabets, frames, and shared lookup offsets as grid_probe.py.
The arbitrary row/column graph is a necessary-condition prefilter, followed
by exactly 26*26 coefficient pairs and a crib-derived constant per survivor.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.grid import ALPHABETS, check_grid_model, coordinate_routes, encrypt_grid, k4_cells


def affine_coefficients(ciphertext, known, cells, permutation, *, alphabet="kryptos",
                        row_frame="source", column_frame="source", row_shift=0, column_shift=0):
    """All affine coefficient triples for a single exact model; at least one crib.

    The graph validates input and can reject this strict subfamily immediately.
    A,b range over all 0..25, including nonunits. No modular division is used.
    Every first-crib-consistent d is uniquely derived rather than enumerated.
    """
    if not known:
        raise ValueError("at least one known plaintext letter is required to derive d")
    options = {"alphabet": alphabet, "row_frame": row_frame, "column_frame": column_frame,
               "row_shift": row_shift, "column_shift": column_shift}
    graph = check_grid_model(ciphertext, known, cells, permutation, **options)
    result = {"prefilter_feasible": graph["feasible"], "prefilter_witness": graph["witness"],
              "coefficient_pairs_tested": 0, "crib_checks": 0, "rejected_pairs": 0,
              "first_failure_position_histogram": {}, "fits": []}
    if not graph["feasible"]:
        return result
    result["prefilter_plaintext_dimension"] = graph["plaintext_dimension"]
    letters = ALPHABETS.get(alphabet, alphabet)
    index = {symbol: value for value, symbol in enumerate(letters)}
    inverse = [0] * len(permutation)
    for j, i in enumerate(permutation):
        inverse[i] = j
    points = []
    for i, j in enumerate(inverse):
        r = cells[((i if row_frame == "source" else j) + row_shift) % len(cells)][0]
        c = cells[((i if column_frame == "source" else j) + column_shift) % len(cells)][1]
        points.append((r, c))
    observations = [(i, *points[i], (index[ciphertext[inverse[i]]] - index[symbol]) % 26)
                    for i, symbol in sorted(known.items())]
    _, first_r, first_c, first_residue = observations[0]
    failed_at = Counter()
    for a in range(26):
        for b in range(26):
            d = (first_residue - a * first_r - b * first_c) % 26
            result["coefficient_pairs_tested"] += 1
            # Count the first crib used to derive d, plus subsequent comparisons.
            result["crib_checks"] += 1
            for i, r, c, residue in observations[1:]:
                result["crib_checks"] += 1
                if (a * r + b * c + d) % 26 != residue:
                    failed_at[i + 1] += 1
                    break
            else:
                plaintext = "".join(letters[(index[ciphertext[inverse[i]]] - a * r - b * c - d) % 26]
                                    for i, (r, c) in enumerate(points))
                assert all(plaintext[i] == symbol for i, symbol in known.items())
                # The constant can be absorbed into every row key because a
                # constant additive shift commutes with every gather route.
                row_keys = {r: (a * r + d) % 26 for r, c in cells}
                column_keys = {c: b * c % 26 for r, c in cells}
                reencrypted = encrypt_grid(plaintext, row_keys, column_keys, cells, permutation, **options)
                assert reencrypted == ciphertext
                result["fits"].append({"a": a, "b": b, "d": d, "plaintext": plaintext,
                                       "reencrypted_ciphertext": reencrypted, "reencryption_matches": True})
    result["rejected_pairs"] = sum(failed_at.values())
    result["first_failure_position_histogram"] = dict(sorted(failed_at.items()))
    result["distinct_plaintexts"] = len({fit["plaintext"] for fit in result["fits"]})
    assert result["rejected_pairs"] + len(result["fits"]) == 676
    return result


def self_test():
    cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
    permutation, known = [0, 2, 3, 1, 5, 4], dict(enumerate("ABCDEF"))
    checks = 0
    hand = {("source", "source"): "HTNNZT", ("source", "destination"): "HOXIUY",
            ("destination", "source"): "HTKQZT", ("destination", "destination"): "HOULUY"}
    for (row_frame, column_frame), ciphertext in hand.items():
        result = affine_coefficients(ciphertext, known, cells, permutation, alphabet="standard",
                                      row_frame=row_frame, column_frame=column_frame)
        assert result["prefilter_feasible"] and result["coefficient_pairs_tested"] == 676
        assert len(result["fits"]) == 1
        fit = result["fits"][0]
        assert (fit["a"], fit["b"], fit["d"], fit["plaintext"]) == (3, 5, 7, "ABCDEF")
        checks += 1
    nonunit = affine_coefficients("EGJSLX", known, cells, permutation, alphabet="standard")
    assert [(row["a"], row["b"], row["d"]) for row in nonunit["fits"]] == [(2, 13, 4)]
    checks += 1
    # Positive for unrestricted row/column keys, negative for affine keys.
    strict = affine_coefficients("DOJJUP", known, cells, permutation, alphabet="standard")
    assert strict["prefilter_feasible"] and not strict["fits"] and strict["rejected_pairs"] == 676
    checks += 1
    rejected = affine_coefficients("EOJJUP", known, cells, permutation, alphabet="standard")
    assert not rejected["prefilter_feasible"] and rejected["coefficient_pairs_tested"] == 0
    checks += 1
    partial = affine_coefficients("HTNNZT", {0: "A"}, cells, permutation, alphabet="standard")
    assert len(partial["fits"]) == partial["distinct_plaintexts"] == 676
    assert partial["crib_checks"] == 676
    checks += 1
    translated = [(r + 100, c - 200) for r, c in cells]
    origin = affine_coefficients("HTNNZT", known, translated, permutation, alphabet="standard")
    assert [(row["a"], row["b"], row["d"]) for row in origin["fits"]] == [(3, 5, (7 - 3 * 100 + 5 * 200) % 26)]
    assert origin["fits"][0]["plaintext"] == "ABCDEF"
    checks += 1
    return {"passed_cases": checks, "scope": "Independent hand vectors for all four frames; nonunit coefficients; strict-subfamily rejection; graph rejection; partial ambiguity; origin translation."}


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze():
    started, timer = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    names = ["research/grid_affine_probe.py", "kryptos/grid.py", "kryptos/data.py"]
    before = {name: _hash(ROOT / name) for name in names}
    controls = self_test()
    cells, routes = k4_cells(), coordinate_routes(k4_cells())
    known = {crib["start"] - 1 + offset: symbol for crib in K4_CRIBS for offset, symbol in enumerate(crib["text"])}
    assert len(cells) == len(K4_CIPHERTEXT) == 97 and len(known) == 24 and len(routes) == 59
    records = []
    for route_index, route in enumerate(routes):
        for alphabet in ("standard", "kryptos"):
            for row_frame in ("source", "destination"):
                for column_frame in ("source", "destination"):
                    for shift in (-1, 0, 1):
                        result = affine_coefficients(K4_CIPHERTEXT, known, cells, route["permutation"], alphabet=alphabet,
                                                      row_frame=row_frame, column_frame=column_frame,
                                                      row_shift=shift, column_shift=shift)
                        records.append({"route_index": route_index, "alphabet": alphabet, "row_frame": row_frame,
                                        "column_frame": column_frame, "row_shift": shift, "column_shift": shift, **result})
    assert len(records) == 1416
    after = {name: _hash(ROOT / name) for name in names}
    assert before == after
    prefilter_fits = sum(row["prefilter_feasible"] for row in records)
    fit_models = [row for row in records if row["fits"]]
    triples = sum(len(row["fits"]) for row in records)
    return {
        "started_at": started, "runtime_seconds": time.perf_counter() - timer,
        "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
        "input_artifacts": [{"path": name, "sha256": before[name], "sha256_after": after[name]} for name in names],
        "input_hashes_unchanged": True, "complete": True, "controls": controls,
        "distinct_routes": len(routes), "model_count_tested": len(records),
        "prefilter_fits": prefilter_fits, "prefilter_rejections": len(records) - prefilter_fits,
        "affine_fit_models": len(fit_models), "affine_fitting_triples": triples,
        "coefficient_pairs_tested": sum(row["coefficient_pairs_tested"] for row in records),
        "coefficient_crib_checks": sum(row["crib_checks"] for row in records),
        "limits": {"models": 1416, "pairs_per_surviving_model": 676,
                   "coefficient_pair_upper_bound_without_prefilter": 1416 * 676,
                   "crib_checks_per_pair_maximum": 24},
        "formula": "idx(C[j])=idx(P[i])+a*r+b*c+d mod26; j=inverse_pi[i]; a,b,d range0..25",
        "phase_convention": "Choose source i or destination j independently for row and column; lookup cells[(chosen index+shared shift)%97], shift in{-1,0,1}.",
        "coordinate_convention": "K4 occupied cells only; local row0 columns27..30 then rows1..3 columns0..30; absolute origin absorbed by free constant d.",
        "cells": cells, "routes": routes, "records": records,
        "non_claims": [
            "Only the stated affine coordinate-shift family is tested, not all position-dependent or grid-based ciphers.",
            "Arbitrary or nonlinear row/column shifts, bilinear terms, other routes, offsets, alphabets, and surrounding-text interactions are outside this run.",
            "The occupied-cell geometry and source/destination phase conventions remain explicit hypotheses.",
            "A fit and exact re-encryption would establish consistency, not authentic plaintext or construction.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    result = self_test() if args.self_test else analyze()
    if args.output:
        output = args.output.resolve()
        if output.exists():
            raise ValueError("choose a new output path to preserve existing evidence")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.self_test:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps({key: result[key] for key in ("complete", "runtime_seconds", "controls", "distinct_routes",
                                                      "model_count_tested", "prefilter_fits", "prefilter_rejections",
                                                      "affine_fit_models", "affine_fitting_triples",
                                                      "coefficient_pairs_tested", "coefficient_crib_checks")}, indent=2))


if __name__ == "__main__":
    main()
