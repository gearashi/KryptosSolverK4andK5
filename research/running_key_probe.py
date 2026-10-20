"""Exact inventory filter for K3 running-key substitution, then any permutation.

Bounded bank: 240 nonwrapping 97-letter windows, two reading directions,
two fixed alphabets and three explicitly defined modular equations. This tests
C=T(S(P,K)), not C=S(T(P),K), and performs no transposition or language search.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from research.k3_reference import K3_PLAINTEXT

ALPHABETS = {"standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
EQUATIONS = {"p_plus_k": "Z_i=(P_i+K_i) mod26",
             "k_minus_p": "Z_i=(K_i-P_i) mod26",
             "p_minus_k": "Z_i=(P_i-K_i) mod26"}
INPUTS = ("kryptos/data.py", "research/k3_reference.py", "research/running_key_probe.py")


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def inventory_filter(ciphertext, known, key, alphabet, equation):
    """Decide if the forced intermediate letters fit the cipher inventory.

    known uses original plaintext positions. key[i] is consumed at the same
    plaintext position before T. Deficits exclude every possible permutation T.
    Passing establishes only an arbitrary completion exists, with no language
    or physical-route restriction on it.
    """
    if not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26:
        raise ValueError("alphabet must contain 26 distinct symbols")
    if equation not in EQUATIONS:
        raise ValueError("unknown equation")
    if (not isinstance(ciphertext, str) or not ciphertext
            or any(ch not in alphabet for ch in ciphertext)):
        raise ValueError("ciphertext must be nonempty and use the alphabet")
    if (not isinstance(key, str) or len(key) != len(ciphertext)
            or any(ch not in alphabet for ch in key)):
        raise ValueError("key must have one alphabet symbol per plaintext position")
    if (not isinstance(known, dict)
            or any(type(i) is not int or not 0 <= i < len(ciphertext) for i in known)
            or any(not isinstance(ch, str) or len(ch) != 1 or ch not in alphabet
                   for ch in known.values())):
        raise ValueError("known must map valid zero-based plaintext positions to single symbols")
    index = {ch: i for i, ch in enumerate(alphabet)}
    forced = {}
    for position, plaintext in sorted(known.items()):
        p, k = index[plaintext], index[key[position]]
        value = p + k if equation == "p_plus_k" else k - p if equation == "k_minus_p" else p - k
        forced[position] = alphabet[value % 26]
    required, available = Counter(forced.values()), Counter(ciphertext)
    deficits = []
    for symbol in sorted(required):
        if required[symbol] > available[symbol]:
            deficits.append({"symbol": symbol, "required": required[symbol],
                             "available": available[symbol],
                             "excess": required[symbol] - available[symbol],
                             "plaintext_positions_one_based": [i + 1 for i, ch in forced.items() if ch == symbol]})
    return {"fits_inventory": not deficits, "forced_counts": dict(sorted(required.items())),
            "total_excess": sum(witness["excess"] for witness in deficits),
            "first_deficit": deficits[0] if deficits else None}


def self_test():
    """Tiny independently written encryption/gather hand vectors only."""
    standard, kryptos = ALPHABETS["standard"], ALPHABETS["kryptos"]
    # P=ABCA, K=BBBB. Literal intermediate strings are BCDB, BAZB,
    # and ZABZ. Reading source positions (2,0,3,1) gives these ciphertexts.
    known = {0: "A", 1: "B", 3: "A"}
    vectors = (
        ("p_plus_k", "DBBC", "DDBC", "B", {"B": 2, "C": 1}),
        ("k_minus_p", "ZBBA", "ZDBA", "B", {"A": 1, "B": 2}),
        ("p_minus_k", "BZZA", "BDZA", "Z", {"A": 1, "Z": 2}),
    )
    checks = 0
    for equation, valid_cipher, invalid_cipher, deficit_symbol, forced_counts in vectors:
        good = inventory_filter(valid_cipher, known, "BBBB", standard, equation)
        if not good["fits_inventory"] or good["forced_counts"] != forced_counts:
            raise AssertionError("Positive hand vector failed")
        bad = inventory_filter(invalid_cipher, known, "BBBB", standard, equation)
        expected = {"symbol": deficit_symbol, "required": 2, "available": 1,
                    "excess": 1, "plaintext_positions_one_based": [1, 4]}
        if bad["fits_inventory"] or bad["first_deficit"] != expected or bad["total_excess"] != 1:
            raise AssertionError("Negative hand vector or certificate failed")
        checks += 2
    # In KRYPTOS coordinates K=0,R=1,Y=2,Z=25. P=KR,K=RR gives
    # RY / RK / ZK before reversing the two output positions.
    for equation, ciphertext, forced in (
        ("p_plus_k", "YR", {"R": 1, "Y": 1}),
        ("k_minus_p", "KR", {"K": 1, "R": 1}),
        ("p_minus_k", "KZ", {"K": 1, "Z": 1}),
    ):
        result = inventory_filter(ciphertext, {0: "K", 1: "R"}, "RR", kryptos, equation)
        if not result["fits_inventory"] or result["forced_counts"] != forced:
            raise AssertionError("Keyed-alphabet hand vector failed")
        checks += 1
    # Unequal key symbols catch mistakenly consuming key at output positions:
    # P=ABCA,K=BDFH => BEHH; gather (2,0,3,1) => HBHE.
    result = inventory_filter("HBHE", {0: "A", 3: "A"}, "BDFH", standard, "p_plus_k")
    if not result["fits_inventory"] or result["forced_counts"] != {"B": 1, "H": 1}:
        raise AssertionError("Plaintext-indexed running key hand vector failed")
    checks += 1
    # Empty cribs impose no inventory demand.
    if not inventory_filter("A", {}, "B", standard, "p_plus_k")["fits_inventory"]:
        raise AssertionError("Empty crib control failed")
    checks += 1
    for arguments in (
        ("AA", {True: "A"}, "BB", standard, "p_plus_k"),
        ("AA", {2: "A"}, "BB", standard, "p_plus_k"),
        ("AA", {0: "AA"}, "BB", standard, "p_plus_k"),
        ("AA", {}, "B", standard, "p_plus_k"),
        ("AA", {}, "BB", "A" * 26, "p_plus_k"),
        ("AA", {}, "BB", standard, "unknown"),
    ):
        try:
            inventory_filter(*arguments)
        except ValueError:
            checks += 1
        else:
            raise AssertionError("Invalid-input control was accepted")
    return {"passed_checks": checks,
            "scope": "Three literal equations with nonidentity gather, positive/negative deficit certificates, keyed alphabet, unequal key symbols, empty cribs, invalid inputs"}


def analyze():
    started = perf_counter()
    before = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS}
    validation = self_test()
    known = {crib["start"] - 1 + offset: letter
             for crib in K4_CRIBS for offset, letter in enumerate(crib["text"])}
    n = len(K4_CIPHERTEXT)
    if n != 97 or len(K3_PLAINTEXT) != 336 or len(known) != 24:
        raise ValueError("This bounded contract requires the pinned97/336-letter inputs and24crib positions")
    if any(symbol not in ALPHABETS["standard"] for symbol in K3_PLAINTEXT):
        raise ValueError("K3 source must use the full standard uppercase alphabet")
    records, groups, distinct_keys = [], {}, set()
    for direction in ("forward", "reverse"):
        for alphabet_name, alphabet in ALPHABETS.items():
            for equation in EQUATIONS:
                group = Counter()
                for start in range(len(K3_PLAINTEXT) - n + 1):
                    original = K3_PLAINTEXT[start:start + n]
                    key = original if direction == "forward" else original[::-1]
                    result = inventory_filter(K4_CIPHERTEXT, known, key, alphabet, equation)
                    distinct_keys.add(key)
                    group["models"] += 1
                    group["fits" if result["fits_inventory"] else "rejected"] += 1
                    records.append({"source_start_one_based": start + 1,
                                    "source_end_one_based": start + n,
                                    "direction": direction, "alphabet": alphabet_name,
                                    "equation": equation,
                                    "key_sha256": sha256(key.encode("ascii")).hexdigest(), **result})
                groups[f"{direction}:{alphabet_name}:{equation}"] = dict(group)
    if len(records) != 2880:
        raise AssertionError("Expected exactly2880 parameter combinations")
    after = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS}
    if before != after:
        raise RuntimeError("Input changed during run; discard result")
    resolved = {"ciphertext": K4_CIPHERTEXT, "key_source_plaintext": K3_PLAINTEXT,
                "known_zero_based": [[i, ch] for i, ch in sorted(known.items())],
                "alphabets": ALPHABETS, "equations": EQUATIONS,
                "window_length": 97, "directions": ["forward", "reverse"]}
    fits = sum(record["fits_inventory"] for record in records)
    return {"base_checkpoint": "K4-20261012-H", "experiment": "K3-running-key-inventory-filter",
            "formula": "C=T(Z), where Z_i is the selected modular equation on P_i and key_i; T is any97-position permutation",
            "model_count": len(records), "fits": fits, "rejected": len(records) - fits,
            "nonwrapping_source_windows": 240, "reading_directions": 2,
            "distinct_key_strings": len(distinct_keys),
            "minimum_total_excess": min(record["total_excess"] for record in records),
            "available_ciphertext_counts": dict(sorted(Counter(K4_CIPHERTEXT).items())),
            "resolved_inputs": resolved, "resolved_inputs_sha256": sha256(canonical_bytes(resolved)).hexdigest(),
            "validation": validation, "inputs_unchanged": True,
            "inputs": [{"path": path, "sha256_before": before[path], "sha256_after": after[path]} for path in INPUTS],
            "python_version": platform.python_version(), "groups": groups, "records": records,
            "runtime_seconds": perf_counter() - started,
            "non_claims": [
                "Every rejection excludes all transpositions for that exact running-key window, alphabet and equation only.",
                "Passing establishes inventory feasibility with arbitrary unknown plaintext and permutation, not meaningful text or a physical route.",
                "This is substitution followed by transposition; it does not cover transposition before substitution.",
                "No wrapping, alternative K3 spellings, ciphertext-derived keys, longer texts, other alphabets, feedback, nulls, or extra layers.",
                "Parameter counts can include equivalent models and are not independent-hypothesis counts.",
                "No language ranking, transposition search, K5 input or external submission.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run only tiny independent hand controls")
    parser.add_argument("--output", type=Path, help="Fresh evidence JSON path for the full bounded filter")
    args = parser.parse_args()
    if args.self_test:
        if args.output is not None:
            parser.error("--self-test does not accept --output")
        print(json.dumps(self_test(), indent=2))
        return
    if args.output is None:
        parser.error("use --self-test or --output")
    if args.output.exists():
        raise FileExistsError("Use a fresh output path")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({key: result[key] for key in (
        "model_count", "fits", "rejected", "distinct_key_strings", "minimum_total_excess",
        "validation", "inputs_unchanged", "runtime_seconds")}, indent=2))


if __name__ == "__main__":
    main()
