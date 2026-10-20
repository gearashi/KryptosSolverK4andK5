"""Bounded direct coordinate-fractionation probe, with no key or language search."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.fractionation import fractionate_decrypt, fractionate_encrypt

ALPHABETS = {"standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
INPUTS = ("kryptos/data.py", "kryptos/fractionation.py", "research/fractionation_probe.py")


def reference_encrypt(text, alphabet, rows, columns, period):
    """Independent block formula: V = row_code * columns**n + column_code.

    V is then written in base rows*columns, avoiding interleaved-digit helpers.
    """
    output = []
    size = rows * columns
    for start in range(0, len(text), period):
        block = text[start:start+period]
        row_code = column_code = 0
        for symbol in block:
            position = alphabet.index(symbol)
            row_code = row_code * rows + position // columns
            column_code = column_code * columns + position % columns
        value = row_code * columns**len(block) + column_code
        encoded = []
        for _ in block:
            encoded.append(alphabet[value % size])
            value //= size
        assert value == 0
        output.extend(reversed(encoded))
    return "".join(output)


def analyze():
    clock = perf_counter()
    before = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    values = {}
    for node in ast.parse((ROOT/"kryptos/data.py").read_text(encoding="utf-8-sig")).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ("K4_CIPHERTEXT", "K4_CRIBS"):
                    values[target.id] = ast.literal_eval(node.value)
    ciphertext = values["K4_CIPHERTEXT"]
    known = {}
    for crib in values["K4_CRIBS"]:
        for offset, symbol in enumerate(crib["text"]):
            position = crib["start"] - 1 + offset
            assert position not in known or known[position] == symbol
            known[position] = symbol
    assert len(ciphertext) == 97 and len(known) == 24
    # Independent integer-arithmetic hand vectors: grouped 0,1,0,0 has
    # rank 169 for a 2x13 block, yielding base-26 digits 6,13 (GN).
    assert fractionate_encrypt("AN", period=2) == "GN"
    assert fractionate_decrypt("GN", period=2) == "AN"
    assert fractionate_encrypt("CA", period=2) == "BA"
    records, outputs, groups = [], set(), {}
    for name, alphabet in ALPHABETS.items():
        for rows, columns in ((2, 13), (13, 2)):
            for direction, transform, inverse in (
                ("decrypt", fractionate_decrypt, fractionate_encrypt),
                ("encrypt-as-inverse-hypothesis", fractionate_encrypt, fractionate_decrypt),
            ):
                group = Counter()
                for period in range(1, 98):
                    parameters = dict(alphabet=alphabet, rows=rows, columns=columns, period=period)
                    candidate = transform(ciphertext, **parameters)
                    assert inverse(candidate, **parameters) == ciphertext
                    if direction == "decrypt":
                        assert reference_encrypt(candidate, alphabet, rows, columns, period) == ciphertext
                    else:
                        assert reference_encrypt(ciphertext, alphabet, rows, columns, period) == candidate
                    mismatches = [[i+1, expected, candidate[i]] for i, expected in sorted(known.items()) if candidate[i] != expected]
                    group["models"] += 1
                    group["fits" if not mismatches else "rejected"] += 1
                    group["maximum_crib_matches"] = max(group["maximum_crib_matches"], 24-len(mismatches))
                    outputs.add(candidate)
                    records.append({"alphabet": name, "rows": rows, "columns": columns,
                                    "direction": direction, "period": period,
                                    "crib_matches": 24-len(mismatches), "exact_crib_fit": not mismatches,
                                    "first_mismatch": mismatches[0] if mismatches else None,
                                    "candidate_sha256": sha256(candidate.encode("ascii")).hexdigest(),
                                    **({"candidate": candidate} if not mismatches else {})})
                groups[f"{name}:{rows}x{columns}:{direction}"] = dict(group)
    after = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    assert before == after
    assert len(records) == 776
    fit_count = sum(record["exact_crib_fit"] for record in records)
    return {"base_checkpoint": "K4-20261012-H", "family": "mixed-radix coordinate regrouping",
            "model_count": len(records), "fits": fit_count, "rejected": len(records)-fit_count,
            "maximum_crib_matches": max(record["crib_matches"] for record in records),
            "distinct_outputs_on_this_target": len(outputs),
            "output_deduplication_caveat": "Equal outputs on K4 do not establish equivalent functions on all inputs.",
            "alphabet_definitions": ALPHABETS, "period_range": [1, 97],
            "distinct_cipher_symbols": len(set(ciphertext)),
            "direct_25_symbol_grid_impossible": len(set(ciphertext)) > 25,
            "direct_25_symbol_scope": "A direct 25-symbol output alphabet cannot emit more than 25 distinct symbols; this says nothing about additional layers or alternate symbol encodings.",
            "checks": {"integer_hand_vectors": 3, "literal_roundtrips": 776,
                       "independent_base26_formula_checks": 776, "inputs_unchanged": True},
            "runtime_seconds": perf_counter()-clock,
            "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in INPUTS],
            "groups": groups, "records": records,
            "non_claims": ["The rectangular extension is a proposed model, not attributed to Sanborn or Scheidt",
                           "No unknown keyed alphabets, further substitutions, transpositions, padding, feedback or block offsets",
                           "No full Bifid-family exclusion", "No K4 or K5 decipherment", "No language scoring or application testing"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write full evidence JSON to a fresh path")
    args = parser.parse_args()
    if args.output is not None and args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in (
        "model_count", "fits", "rejected", "maximum_crib_matches", "distinct_outputs_on_this_target",
        "distinct_cipher_symbols", "direct_25_symbol_grid_impossible", "checks", "runtime_seconds")}, indent=2))
