"""Tiny exact K4 hypothesis checks, independent of the search engine.

Run from project root: python research/check_classes.py --output PATH
No scoring, stochastic search, workers, networking, or app tests.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS

ALPHABETS = {
    "standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ",
}


def residue_key(c: int, p: int, variant: str) -> int:
    return {"vigenere": c - p, "beaufort": c + p, "variant": p - c}[variant] % 26


def first_conflict(values: dict[int, int], period: int, drift: int = 0):
    """K_i = base[i mod period] + floor(i / period) * drift, zero-based i."""
    seen = {}
    for i, key in sorted(values.items()):
        value = (key - (i // period) * drift) % 26
        phase = i % period
        if phase in seen and seen[phase][1] != value:
            return {"positions": [seen[phase][0] + 1, i + 1],
                    "required_base_values": [seen[phase][1], value]}
        seen[phase] = (i, value)
    return None


def plaintext_feedback(cipher_values, known_values, lag, variant):
    """Solve all feedback chains, including comparisons separated by multiple lags.

    P_i = sign * P_(i-lag) + offset(C_i), so each P is an affine
    expression in one of the first `lag` unknown plaintext symbols.
    """
    chain_sign, chain_offset = [], []
    for i, cipher in enumerate(cipher_values):
        if i < lag:
            sign, offset = 1, 0
        elif variant == "vigenere":
            sign, offset = -chain_sign[i - lag], cipher - chain_offset[i - lag]
        elif variant == "beaufort":
            sign, offset = chain_sign[i - lag], chain_offset[i - lag] - cipher
        else:
            sign, offset = chain_sign[i - lag], chain_offset[i - lag] + cipher
        chain_sign.append(sign)
        chain_offset.append(offset % 26)
    forced_roots = {}
    witnesses = {}
    for i, plain in sorted(known_values.items()):
        root = i % lag
        value = ((plain - chain_offset[i]) * chain_sign[i]) % 26
        if root in forced_roots and forced_roots[root] != value:
            return {"conflict": {"positions": [witnesses[root] + 1, i + 1],
                                  "primer_chain": root + 1,
                                  "required_root_values": [forced_roots[root], value]}}
        forced_roots[root], witnesses[root] = value, i
    partial = [((chain_sign[i] * forced_roots[i % lag] + chain_offset[i]) % 26)
               if i % lag in forced_roots else None for i in range(len(cipher_values))]
    # The initial key/primer is then C-P, C+P, or P-C over its first lag letters.
    return {"conflict": None, "forced_root_count": len(forced_roots),
            "free_root_count": lag - len(forced_roots), "partial_plaintext_values": partial}


def analyze():
    # Independent arithmetic examples, with full feedback propagated across gaps.
    toy_plain = [1, 4, 2, 6, 3, 8]
    toy_cipher = {
        "vigenere": [6, 11, 3, 10, 5, 14],
        "beaufort": [4, 3, 25, 24, 25, 24],
        "variant": [22, 23, 1, 2, 1, 2],
    }
    for mode, cipher in toy_cipher.items():
        solved = plaintext_feedback(cipher, {4: 3, 5: 8}, 2, mode)
        assert solved["conflict"] is None
        assert solved["partial_plaintext_values"] == toy_plain
        assert plaintext_feedback(cipher, {0: 1, 4: 4}, 2, mode)["conflict"]
    assert plaintext_feedback([0, 1, 2], {0: 0, 2: 0}, 1, "vigenere")["conflict"]
    assert len(K4_CIPHERTEXT) == 97
    for alphabet in ALPHABETS.values():
        assert len(alphabet) == len(set(alphabet)) == 26
    known = {}
    for crib in K4_CRIBS:
        for i, letter in enumerate(crib["text"], crib["start"] - 1):
            assert i not in known or known[i] == letter
            known[i] = letter
    assert len(known) == 24
    assert K4_CIPHERTEXT[21:34] == "FLRVQQPRNGKSS"
    assert K4_CIPHERTEXT[63:74] == "NYPVTTMZFPK"
    counts = Counter(K4_CIPHERTEXT)
    required = Counter(known.values())
    inventory_conflicts = {
        letter: {"ciphertext_count": counts[letter], "minimum_plaintext_count": count}
        for letter, count in sorted(required.items()) if count > counts[letter]
    }
    models = []
    for c_name, c_alphabet in ALPHABETS.items():
        for p_name, p_alphabet in ALPHABETS.items():
            for variant in ("vigenere", "beaufort", "variant"):
                values = {i: residue_key(c_alphabet.index(K4_CIPHERTEXT[i]),
                                         p_alphabet.index(p), variant)
                          for i, p in known.items()}
                conflicts = {str(period): first_conflict(values, period)
                             for period in range(1, 98)}
                drift_feasible = [
                    {"period": period, "drift": drift}
                    for period in range(1, 27) for drift in range(26)
                    if first_conflict(values, period, drift) is None
                ]
                # Known plaintext feedback: only compare where the earlier P is known.
                # Ciphertext feedback: earlier C is always available.
                autokey = {}
                for feedback in ("plaintext", "ciphertext"):
                    survivors, witnesses = [], {}
                    for lag in range(1, 97):
                        violations = []
                        for i, key in values.items():
                            earlier = i - lag
                            if earlier < 0:
                                continue
                            if feedback == "plaintext":
                                if earlier not in known:
                                    continue
                                expected = p_alphabet.index(known[earlier])
                            else:
                                expected = c_alphabet.index(K4_CIPHERTEXT[earlier])
                            if key != expected:
                                violations.append({"position": i + 1,
                                                   "feedback_position": earlier + 1,
                                                   "key_value": key,
                                                   "feedback_value": expected})
                        if violations:
                            witnesses[str(lag)] = violations[0]
                        else:
                            survivors.append(lag)
                    autokey[feedback] = {"not_excluded_lags": survivors,
                                         "rejected_lag_witnesses": witnesses}
                # Strengthen plaintext feedback using its complete recurrence.
                feedback_models = {
                    str(lag): plaintext_feedback(
                        [c_alphabet.index(c) for c in K4_CIPHERTEXT],
                        {i: p_alphabet.index(p) for i, p in known.items()}, lag, variant)
                    for lag in range(1, 97)
                }
                full_feedback = {
                    "not_excluded_lags": [int(lag) for lag, row in feedback_models.items()
                                           if row["conflict"] is None],
                    "rejected_lag_witnesses": {lag: row["conflict"]
                                               for lag, row in feedback_models.items()
                                               if row["conflict"] is not None},
                    "surviving_patterns": {
                        lag: {"free_root_count": row["free_root_count"],
                              "partial_plaintext": "".join(
                                  "?" if value is None else p_alphabet[value]
                                  for value in row["partial_plaintext_values"])}
                        for lag, row in feedback_models.items() if row["conflict"] is None
                    },
                }
                models.append({
                    "ciphertext_alphabet": c_name, "plaintext_alphabet": p_name,
                    "variant": variant,
                    "key_values_at_cribs": {str(i + 1): v for i, v in values.items()},
                    "key_segments_standard_encoding": [
                        "".join(ALPHABETS["standard"][values[i]] for i in range(a, b))
                        for a, b in ((21, 34), (63, 74))],
                    "not_excluded_periods": [int(p) for p, v in conflicts.items() if v is None],
                    "rejected_period_witnesses": {p: v for p, v in conflicts.items() if v},
                    "not_excluded_progressive_keys": drift_feasible,
                    "autokey": autokey,
                    "plaintext_autokey_full_recurrence": full_feedback,
                })
    return {
        "checkpoint": "K4-20261012-B",
        "base_checkpoint": "K4-20261012-A",
        "input_sha256": hashlib.sha256(json.dumps(
            {"ciphertext": K4_CIPHERTEXT, "cribs": K4_CRIBS},
            sort_keys=True).encode()).hexdigest(),
        "indexing": "reported positions 1-based; recurrence arithmetic uses zero-based i",
        "feedback_encoding": "Plaintext feedback uses plaintext alphabet indexes; ciphertext feedback uses ciphertext alphabet indexes. Re-encoding feedback in a different key alphabet is not tested.",
        "checks": ["26 unique symbols per alphabet", "97 ciphertext letters", "24 unique crib positions", "exact two ciphertext crib slices", "three hand-computed full feedback vectors and injected contradictions", "gap-propagation counterexample"],
        "ciphertext": K4_CIPHERTEXT, "cribs": K4_CRIBS,
        "pure_transposition_inventory_conflicts": inventory_conflicts,
        "models": models,
        "non_claims": [
            "Not a decryption or a novelty claim.",
            "Survival means not excluded by the check performed, not correct or likely. The direct-pair plaintext feedback check is weaker than the separately recorded full recurrence check.",
            "Only the stated alphabet assignments and equations are tested.",
            "Layered ciphers, alternate alphabets, nulls, and rearranged stages remain open.",
            "A feedback lag with no comparable known positions survives vacuously.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Pure transposition inventory conflicts:",
          result["pure_transposition_inventory_conflicts"])
    for model in result["models"]:
        print(model["ciphertext_alphabet"], model["plaintext_alphabet"], model["variant"],
              "minimum consistent period", min(model["not_excluded_periods"]),
              "progressive survivors", len(model["not_excluded_progressive_keys"]),
              "minimum plaintext-autokey lag", min(model["autokey"]["plaintext"]["not_excluded_lags"]),
              "minimum ciphertext-autokey lag", min(model["autokey"]["ciphertext"]["not_excluded_lags"]))
        print("  full plaintext feedback minimum lag:",
              min(model["plaintext_autokey_full_recurrence"]["not_excluded_lags"]))


if __name__ == "__main__":
    main()
