"""Bounded exact K4 occupied-grid probe; no language scoring or key brute force."""

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
from kryptos.grid import check_grid_model, coordinate_routes, k4_cells
from research.check_physical_routes import routes as old_routes


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(max_models=4096):
    if isinstance(max_models, bool) or not isinstance(max_models, int) or not 0 <= max_models <= 4096:
        raise ValueError("max_models must be an integer from 0 through 4096")
    timer, started = time.perf_counter(), datetime.now(timezone.utc).isoformat()
    names = ["kryptos/grid.py", "kryptos/data.py", "research/grid_probe.py",
             "research/check_physical_routes.py", "research/check_classes.py"]
    before = {name: _hash(ROOT / name) for name in names}
    cells = k4_cells()
    known = {crib["start"] - 1 + offset: symbol for crib in K4_CRIBS for offset, symbol in enumerate(crib["text"])}
    assert len(cells) == len(K4_CIPHERTEXT) == 97 and len(known) == 24
    routes = coordinate_routes(cells)
    old = set(old_routes())
    new = {tuple(row["permutation"]) for row in routes}
    assert old <= new
    records = []
    frames = [(r, c) for r in ("source", "destination") for c in ("source", "destination")]
    expected = len(routes) * 2 * len(frames) * 3
    for route_index, route in enumerate(routes):
        for alphabet in ("standard", "kryptos"):
            for row_frame, column_frame in frames:
                for shift in (-1, 0, 1):
                    if len(records) >= max_models:
                        break
                    result = check_grid_model(K4_CIPHERTEXT, known, cells, route["permutation"], alphabet=alphabet,
                                               row_frame=row_frame, column_frame=column_frame,
                                               row_shift=shift, column_shift=shift)
                    records.append({"route_index": route_index, "alphabet": alphabet,
                                    "row_frame": row_frame, "column_frame": column_frame,
                                    "row_shift": shift, "column_shift": shift, **result})
    fits = [record for record in records if record["feasible"]]
    forced_counts = Counter(len(row["forced_unknown_positions"]) for row in fits)
    dimensions = Counter(row["plaintext_dimension"] for row in fits)
    by_frame_shift = []
    for r, c in frames:
        for shift in (-1, 0, 1):
            group = [record for record in records if (record["row_frame"], record["column_frame"], record["row_shift"]) == (r, c, shift)]
            by_frame_shift.append({"row_frame": r, "column_frame": c, "shift": shift,
                                   "models": len(group), "fits": sum(row["feasible"] for row in group)})
    after = {name: _hash(ROOT / name) for name in names}
    assert before == after
    return {
        "started_at": started, "runtime_seconds": time.perf_counter() - timer,
        "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
        "input_artifacts": [{"path": name, "sha256": before[name], "sha256_after": after[name]} for name in names],
        "input_hashes_unchanged": True, "complete": len(records) == expected,
        "limits": {"max_models": max_models, "declared_family_maximum": 1920},
        "model_count_requested": expected, "model_count_tested": len(records),
        "old_distinct_routes": len(old), "distinct_routes": len(routes), "added_distinct_routes": len(new - old),
        "fits": len(fits), "rejections": len(records) - len(fits),
        "known_plaintext_positions": len(known), "unknown_plaintext_positions": 97 - len(known),
        "forced_unknown_count_histogram": dict(sorted(forced_counts.items())),
        "plaintext_dimension_histogram": dict(sorted(dimensions.items())),
        "by_frame_and_shift": by_frame_shift,
        "coordinate_convention": "Local zero-based cells: row0 columns27..30, rows1..3 columns0..30; absolute sculpture row origin unasserted.",
        "phase_convention": "Select source i or destination j=inverse_pi[i] independently for row/column; look up cells[(selected index+shared shift)%97].",
        "cells": cells, "routes": routes, "records": records,
        "non_claims": [
            "These occupied K4 cells are a layout surrogate; earlier passages are outside the model, not nulls or padding.",
            "Arbitrary row and column shifts are flexible hypothetical keys, not authenticated sculpture instructions.",
            "Cyclic stream shifts -1,0,1 are declared alternatives; no other shifts or surrounding-text interactions were tested.",
            "Fits, representative re-encryption, and forced letters establish model consistency, not plaintext authenticity.",
            "Fixed shared alphabets only; no unknown alphabets, fractionation, feedback, or nonlinear coordinate substitutions.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-models", type=int, default=4096)
    args = parser.parse_args()
    result = analyze(args.max_models)
    if args.output:
        output = args.output.resolve()
        if output.exists():
            raise ValueError("choose a new output path to preserve existing evidence")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("complete", "runtime_seconds", "old_distinct_routes", "distinct_routes",
                                                  "added_distinct_routes", "model_count_requested", "model_count_tested",
                                                  "fits", "rejections", "forced_unknown_count_histogram",
                                                  "plaintext_dimension_histogram", "by_frame_and_shift")}, indent=2))


if __name__ == "__main__":
    main()
