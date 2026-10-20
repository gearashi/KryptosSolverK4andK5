"""Exact, small test of modular substitution plus physical-grid scan orders.

This is not a general transposition search. The K4 shape is four letters in
columns 28..31, followed by three complete 31-letter rows. Empty cells are
skipped; no null letters are inserted. Every permutation and its inverse is
tested as an explicit intermediate ciphertext reading order.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from research.check_classes import ALPHABETS, first_conflict, residue_key


def routes():
    cells = [(0, 27 + i, i) for i in range(4)]
    cells += [(1 + i // 31, i % 31, 4 + i) for i in range(93)]
    result = {}
    for column_major in (False, True):
        for reverse_major in (False, True):
            for reverse_minor in (False, True):
                for snake in (False, True):
                    major_axis = int(column_major)
                    major_values = sorted({c[major_axis] for c in cells}, reverse=reverse_major)
                    order = []
                    for scan_index, major in enumerate(major_values):
                        minor_reversed = reverse_minor ^ (snake and scan_index % 2 == 1)
                        group = sorted((c for c in cells if c[major_axis] == major),
                                       key=lambda c: c[1 - major_axis], reverse=minor_reversed)
                        order.extend(c[2] for c in group)
                    name = f"{'columns' if column_major else 'rows'}-major_reverse{int(reverse_major)}-minor_reverse{int(reverse_minor)}-snake{int(snake)}"
                    assert sorted(order) == list(range(97))
                    inverse = [0] * 97
                    for position, source in enumerate(order):
                        inverse[source] = position
                    assert [order[inverse[i]] for i in range(97)] == list(range(97))
                    for suffix, permutation in (("forward", order), ("inverse", inverse)):
                        result.setdefault(tuple(permutation), []).append(name + "/" + suffix)
    return result


def analyze():
    known = {crib["start"] - 1 + offset: letter
             for crib in K4_CRIBS for offset, letter in enumerate(crib["text"])}
    records = []
    count = 0
    for permutation, aliases in routes().items():
        intermediate = "".join(K4_CIPHERTEXT[i] for i in permutation)
        rows = []
        for c_name, c_alphabet in ALPHABETS.items():
            for p_name, p_alphabet in ALPHABETS.items():
                for variant in ("vigenere", "beaufort", "variant"):
                    values = {i: residue_key(c_alphabet.index(intermediate[i]),
                                             p_alphabet.index(letter), variant)
                              for i, letter in known.items()}
                    for period in range(1, 27):
                        count += 1
                        conflict = first_conflict(values, period)
                        rows.append({"ciphertext_alphabet": c_name,
                                     "plaintext_alphabet": p_name, "variant": variant,
                                     "period": period, "conflict": conflict})
        records.append({"aliases": aliases,
                        "source_positions_one_based": [i + 1 for i in permutation],
                        "intermediate_ciphertext": intermediate,
                        "survivors": [row for row in rows if row["conflict"] is None],
                        "rejected_count": sum(row["conflict"] is not None for row in rows),
                        "checks": rows})
    return {"checkpoint": "K4-20261012-C", "base_checkpoint": "K4-20261012-B",
            "physical_layout": "four rightmost cells of a 31-column row, then three full rows",
            "distinct_routes": len(records), "model_count": count,
            "survivor_count": sum(len(row["survivors"]) for row in records),
            "routes": records,
            "non_claims": ["No general exclusion of layered ciphers or all transpositions.",
                           "Only these explicit scans and fixed short repeating modular keys.",
                           "Scan hypotheses are not authenticated encryption instructions.",
                           "Period above 26, alternative alphabets, other grids, nulls and feedback remain untested here."]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("distinct_routes", "model_count", "survivor_count")}))
    for route in result["routes"]:
        if route["survivors"]:
            print(route["aliases"], route["survivors"])


if __name__ == "__main__":
    main()
