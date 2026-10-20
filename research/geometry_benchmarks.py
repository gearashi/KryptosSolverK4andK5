"""Verify the source-backed textual sculpture layout and fixed mapping bank.

This is an inscription/coordinate regression, not a K4 cipher search or a
physical 3D reconstruction. No interpretation is inferred from overlay text.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT
from kryptos.sculpture import (TRANSFORMS, apply_gather, cells, fixed_overlay, fixed_routes,
                              load_layout, section_cells, section_text)
from research.k3_reference import K3_CIPHERTEXT, K3_PLAINTEXT, decrypt_k3, encrypt_k3

SOURCE_PATHS = ("research/geometry_benchmarks.py", "kryptos/sculpture.py", "research/sculpture_layout.json",
                "kryptos/data.py", "research/k3_reference.py", "research/recovery_benchmarks.py",
                "research/source_snapshots/sculpture-J/dunin_transcript.html.txt",
                "research/source_snapshots/sculpture-J/cia_sculpture.html.txt")


def file_hashes():
    return {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS}


def known_answers(layout=None):
    layout = load_layout() if layout is None else layout
    # Read only the existing constant literals; importing its recovery routines
    # would add unnecessary dependencies and would not independently check data.
    wanted = {"K1_CIPHERTEXT", "K1_PLAINTEXT", "K2_CIPHERTEXT", "K2_PLAINTEXT"}
    fixture = {}
    tree = ast.parse((ROOT / "research/recovery_benchmarks.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in wanted:
                fixture[name] = ast.literal_eval(node.value)
    if set(fixture) != wanted:
        raise ValueError("Existing known-answer constants are unavailable")
    alphabet = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    checks = []
    for section, key in (("K1", "PALIMPSEST"), ("K2", "ABSCISSA")):
        ciphertext, plaintext = section_text(section, layout), fixture[section + "_PLAINTEXT"]
        encoded = "".join(alphabet[(alphabet.index(p) + alphabet.index(key[i % len(key)])) % 26]
                          for i, p in enumerate(plaintext))
        decoded = "".join(alphabet[(alphabet.index(c) - alphabet.index(key[i % len(key)])) % 26]
                          for i, c in enumerate(ciphertext))
        if ciphertext != fixture[section + "_CIPHERTEXT"] or encoded != ciphertext or decoded != plaintext:
            raise AssertionError(section + " source extraction/roundtrip failed")
        checks.append({"section": section, "letters": len(ciphertext), "known_roundtrip": True})
    k3 = section_text("K3", layout)
    if k3 != K3_CIPHERTEXT or decrypt_k3(k3) != K3_PLAINTEXT or encrypt_k3(K3_PLAINTEXT) != k3:
        raise AssertionError("K3 source extraction/known roundtrip failed")
    checks.append({"section": "K3", "letters": len(k3), "known_roundtrip": True})
    if section_text("K4", layout) != K4_CIPHERTEXT:
        raise AssertionError("K4 source coordinates do not extract the canonical 97 letters")
    checks.append({"section": "K4", "letters": 97, "canonical_ciphertext_match": True,
                   "known_roundtrip": None})
    return checks


def analyze():
    before, started = file_hashes(), perf_counter()
    layout = load_layout()
    known = known_answers(layout)
    route_checks = []
    for section in ("K1", "K2", "K3", "K4", "ALL"):
        text = section_text(section, layout)
        routes = fixed_routes(section, layout)
        for route in routes:
            perm = route["permutation"]
            transformed = apply_gather(text, perm)
            if apply_gather(transformed, perm, inverse=True) != text:
                raise AssertionError("Coordinate route loses or duplicates a symbol")
        route_checks.append({"section": section, "letters": len(text), "distinct_routes": len(routes),
                             "declared_transform_scan_pairs": 16, "all_inverse_checks": True})
    k4_routes = fixed_routes("K4", layout)
    overlays = [fixed_overlay("K4", transform, layout) for transform in TRANSFORMS]
    after = file_hashes()
    if before != after:
        raise RuntimeError("Input changed during coordinate verification")
    return {"experiment": "verified-sculpture-text-coordinate-bank", "python_version": platform.python_version(),
            "known_answers": known, "route_checks": route_checks,
            "summary": {"cipher_letters": len(section_text("ALL", layout)),
                        "preserved_question_marks": sum(c.symbol == "?" for c in cells("cipher", layout)),
                        "cipher_transcribed_rows": 28, "tableau_transcribed_rows": 28,
                        "k4_occupied_letter_cells": 97, "k4_distinct_routes": len(k4_routes),
                        "fixed_ordinal_overlays": len(overlays)},
            "k4_cells": [c.to_dict() for c in section_cells("K4", layout)],
            "k4_fixed_routes": list(k4_routes), "k4_fixed_overlays": overlays,
            "sources": layout["sources"], "anomalies": layout["anomalies"],
            "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in SOURCE_PATHS],
            "inputs_unchanged": True, "runtime_seconds": perf_counter() - started,
            "limitations": layout["limitations"] + [
                "No physical distances, curvature, compass alignment, bearings or 3D coordinates were measured.",
                "The fixed ordinal routes/overlays are explicit hypotheses, not authenticated cipher instructions.",
                "This verifies main-screen text, not the sculpture's entire courtyard installation or hidden K5 text."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
