"""Exact inventory test for C=S(T(P),K): running key after any transposition.

Fixed bank: 240 nonwrapping 97-letter K3 plaintext windows, both directions,
two alphabets, three equations = 2880 parameter combinations. The key is used
at ciphertext/output positions. No route search or language score is used.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys
from time import perf_counter


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from research.k3_reference import K3_PLAINTEXT


ALPHABETS = {"standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
EQUATIONS = {
    "p_plus_k": {"forward": "C_j=(Y_j+K_j) mod26", "inverse": "Y_j=(C_j-K_j) mod26"},
    "k_minus_p": {"forward": "C_j=(K_j-Y_j) mod26", "inverse": "Y_j=(K_j-C_j) mod26"},
    "p_minus_k": {"forward": "C_j=(Y_j-K_j) mod26", "inverse": "Y_j=(C_j+K_j) mod26"},
}
INPUTS = ("kryptos/data.py", "research/k3_reference.py", "research/running_key_after_route.py")


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _validate(ciphertext, known, key, alphabet, equation):
    if not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26:
        raise ValueError("alphabet must contain26 distinct symbols")
    if equation not in EQUATIONS:
        raise ValueError("unknown modular equation")
    if not isinstance(ciphertext, str) or not ciphertext or any(c not in alphabet for c in ciphertext):
        raise ValueError("ciphertext must be a nonempty string over the selected alphabet")
    if not isinstance(key, str) or len(key) != len(ciphertext) or any(c not in alphabet for c in key):
        raise ValueError("key must have one symbol per ciphertext/output position")
    if (not isinstance(known, dict)
            or any(type(i) is not int or not 0 <= i < len(ciphertext)
                   or not isinstance(c, str) or len(c) != 1 or c not in alphabet
                   for i, c in known.items())):
        raise ValueError("known must map zero-based plaintext positions to single alphabet symbols")


def invert_running_substitution(ciphertext, key, alphabet, equation):
    """Materialize all Y=T(P), consuming key[j] at the same position as C[j]."""
    _validate(ciphertext, {}, key, alphabet, equation)
    index = {c: i for i, c in enumerate(alphabet)}
    output = []
    for cipher, key_letter in zip(ciphertext, key):
        c, k = index[cipher], index[key_letter]
        value = c - k if equation == "p_plus_k" else k - c if equation == "k_minus_p" else c + k
        output.append(alphabet[value % 26])
    return "".join(output)


def _forward_substitution(intermediate, key, alphabet, equation):
    index = {c: i for i, c in enumerate(alphabet)}
    result = []
    for plain, key_letter in zip(intermediate, key):
        p, k = index[plain], index[key_letter]
        value = p + k if equation == "p_plus_k" else k - p if equation == "k_minus_p" else p - k
        result.append(alphabet[value % 26])
    return "".join(result)


def _materialize(intermediate, known, key, alphabet, equation, ciphertext):
    """One arbitrary completion and its gather/inverse maps; no route inference."""
    n = len(intermediate)
    slots = {c: deque(i for i, value in enumerate(intermediate) if value == c) for c in alphabet}
    permutation, plaintext = [None] * n, [None] * n
    for i, c in sorted(known.items()):
        j = slots[c].popleft()
        permutation[j], plaintext[i] = i, c
    remaining_sources = [i for i, c in enumerate(plaintext) if c is None]
    remaining_outputs = [j for j, i in enumerate(permutation) if i is None]
    for i, j in zip(remaining_sources, remaining_outputs):
        plaintext[i], permutation[j] = intermediate[j], i
    if sorted(permutation) != list(range(n)) or any(c is None for c in plaintext):
        raise AssertionError("constructed completion is not a full permutation")
    plaintext = "".join(plaintext)
    inverse = [None] * n
    for j, i in enumerate(permutation):
        inverse[i] = j
    gathered = "".join(plaintext[i] for i in permutation)
    restored = "".join(intermediate[inverse[i]] for i in range(n))
    reencrypted = _forward_substitution(gathered, key, alphabet, equation)
    if (gathered != intermediate or restored != plaintext or reencrypted != ciphertext
            or any(plaintext[i] != c for i, c in known.items())):
        raise AssertionError("constructed plaintext/route failed independent direction checks")
    return {
        "representative_plaintext": plaintext, "gather_permutation_zero_based": permutation,
        "inverse_permutation_zero_based": inverse, "reencrypted_ciphertext": reencrypted,
        "gather_matches_intermediate": True, "inverse_restores_plaintext": True,
        "reencryption_matches": True,
        "interpretation": "Deterministic arbitrary inventory completion; neither a proposed physical route nor recovered language",
    }


def inventory_filter_after_route(ciphertext, known, key, alphabet, equation):
    """Necessary and sufficient for some P,pi satisfying cribs and C=S(T_pi(P),K).

    No constraint on pi besides bijectivity. Complete inversion fixes Y. Every
    known plaintext letter needs a different occurrence of that letter in Y.
    Any remaining occurrences fill unrestricted plaintext positions.
    """
    _validate(ciphertext, known, key, alphabet, equation)
    intermediate = invert_running_substitution(ciphertext, key, alphabet, equation)
    required, available = Counter(known.values()), Counter(intermediate)
    deficits = []
    for symbol in sorted(required):
        if required[symbol] > available[symbol]:
            deficits.append({
                "symbol": symbol, "required": required[symbol], "available": available[symbol],
                "excess": required[symbol] - available[symbol],
                "plaintext_positions_one_based": [i + 1 for i, c in sorted(known.items()) if c == symbol],
                "intermediate_positions_one_based": [j + 1 for j, c in enumerate(intermediate) if c == symbol],
            })
    feasible = not deficits
    return {
        "fits_inventory": feasible, "inverted_substitution_text": intermediate,
        "intermediate_counts": dict(sorted(available.items())),
        "required_plaintext_counts": dict(sorted(required.items())),
        "total_excess": sum(witness["excess"] for witness in deficits),
        "deficits": deficits, "first_deficit": deficits[0] if deficits else None,
        "materialization": _materialize(intermediate, known, key, alphabet, equation, ciphertext)
                           if feasible else None,
    }


def self_test():
    """Literal hand vectors, negative witnesses and distinct stage-order cases."""
    checks = 0
    permutation = [2, 0, 3, 1]  # a four-cycle: inverse is [1,3,0,2]
    # Numeric P=(0,1,2,0); Y=T(P)=(2,0,0,1); K=(1,3,5,7).
    # Positive C: plus=(3,3,5,8), Beaufort=(25,3,5,6), variant=(1,23,21,20).
    # Negative Y=(2,0,1,1) has only one zero-symbol, while P needs two.
    vectors = (
        ("standard", "ABCA", "BDFH", "CAAB", (
            ("p_plus_k", "DDFI", "DDGI"), ("k_minus_p", "ZDFG", "ZDEG"),
            ("p_minus_k", "BXVU", "BXWU"))),
        ("kryptos", "KRYK", "RPOA", "YKKR", (
            ("p_plus_k", "PPOB", "PPSB"), ("k_minus_p", "ZPOS", "ZPTS"),
            ("p_minus_k", "RWUQ", "RWVQ"))),
    )
    for alphabet_name, plaintext, key, intermediate, equations in vectors:
        alphabet = ALPHABETS[alphabet_name]
        known = dict(enumerate(plaintext))
        if "".join(plaintext[i] for i in permutation) != intermediate:
            raise AssertionError("independently specified gather hand vector is wrong")
        for equation, valid_cipher, invalid_cipher in equations:
            good = inventory_filter_after_route(valid_cipher, known, key, alphabet, equation)
            if (not good["fits_inventory"] or good["inverted_substitution_text"] != intermediate
                    or good["materialization"]["representative_plaintext"] != plaintext
                    or good["materialization"]["gather_permutation_zero_based"] != permutation
                    or good["materialization"]["inverse_permutation_zero_based"] != [1, 3, 0, 2]):
                raise AssertionError("positive hand vector or inverse materialization failed")
            bad = inventory_filter_after_route(invalid_cipher, known, key, alphabet, equation)
            expected = {"symbol": alphabet[0], "required": 2, "available": 1, "excess": 1,
                        "plaintext_positions_one_based": [1, 4], "intermediate_positions_one_based": [2]}
            if (bad["fits_inventory"] or bad["deficits"] != [expected]
                    or bad["total_excess"] != 1 or bad["materialization"] is not None):
                raise AssertionError("negative hand vector/complete deficit certificate failed")
            checks += 2
    # The same unequal key before T instead produces HBHE, not DDFI.
    # Inverting HBHE with the output-indexed key yields GYCX, missing both As.
    wrong_order = inventory_filter_after_route("HBHE", {0: "A", 3: "A"}, "BDFH",
                                               ALPHABETS["standard"], "p_plus_k")
    if wrong_order["fits_inventory"] or wrong_order["inverted_substitution_text"] != "GYCX":
        raise AssertionError("key was incorrectly consumed at original plaintext positions")
    checks += 1
    # Partial and empty cribs require an explicit, arbitrary full completion.
    for known in ({0: "A", 3: "A"}, {}):
        result = inventory_filter_after_route("DDFI", known, "BDFH", ALPHABETS["standard"], "p_plus_k")
        if not result["fits_inventory"] or not result["materialization"]["reencryption_matches"]:
            raise AssertionError("partial/empty crib completion failed")
        checks += 1
    # Multiple deficits must all be saved, not merely the first one.
    multiple = inventory_filter_after_route("CCCC", {0: "A", 1: "A", 2: "B", 3: "B"},
                                            "AAAA", ALPHABETS["standard"], "p_plus_k")
    if len(multiple["deficits"]) != 2 or multiple["total_excess"] != 4:
        raise AssertionError("all-deficits witness control failed")
    checks += 1
    for arguments in (
        ("AA", {True: "A"}, "BB", ALPHABETS["standard"], "p_plus_k"),
        ("AA", {2: "A"}, "BB", ALPHABETS["standard"], "p_plus_k"),
        ("AA", {0: "AA"}, "BB", ALPHABETS["standard"], "p_plus_k"),
        ("AA", {}, "B", ALPHABETS["standard"], "p_plus_k"),
        ("AA", {}, "BB", "A" * 26, "p_plus_k"),
        ("AA", {}, "BB", ALPHABETS["standard"], "unknown"),
    ):
        try:
            inventory_filter_after_route(*arguments)
        except ValueError:
            checks += 1
        else:
            raise AssertionError("invalid-input control was accepted")
    return {"passed_checks": checks,
            "scope": "Three equations x two alphabets; non-involutive gather/inverse; positive/negative complete inventory witnesses; unequal output-indexed key; arbitrary partial/empty completion; invalid inputs"}


def analyze():
    started = perf_counter()
    before = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS}
    validation = self_test()
    known = {crib["start"] - 1 + offset: letter
             for crib in K4_CRIBS for offset, letter in enumerate(crib["text"])}
    n = len(K4_CIPHERTEXT)
    if n != 97 or len(K3_PLAINTEXT) != 336 or len(known) != 24:
        raise ValueError("fixed contract requires97 cipher letters,336 K3 letters and24 known positions")
    if any(c not in ALPHABETS["standard"] for c in K3_PLAINTEXT):
        raise ValueError("K3 key source must contain uppercase ASCII letters only")
    records, groups, distinct_keys = [], {}, set()
    for direction in ("forward", "reverse"):
        for alphabet_name, alphabet in ALPHABETS.items():
            for equation in EQUATIONS:
                group = Counter(models=0, fits=0, rejected=0)
                for start in range(len(K3_PLAINTEXT) - n + 1):
                    original = K3_PLAINTEXT[start:start + n]
                    key = original if direction == "forward" else original[::-1]
                    result = inventory_filter_after_route(K4_CIPHERTEXT, known, key, alphabet, equation)
                    distinct_keys.add(key)
                    group["models"] += 1
                    group["fits" if result["fits_inventory"] else "rejected"] += 1
                    records.append({"model_record_index_zero_based": len(records),
                                    "source_start_one_based": start + 1, "source_end_one_based": start + n,
                                    "direction": direction, "alphabet": alphabet_name, "equation": equation,
                                    "key_sha256": sha256(key.encode("ascii")).hexdigest(), **result})
                groups[f"{direction}:{alphabet_name}:{equation}"] = dict(group)
    if len(records) != 2880:
        raise AssertionError("expected exactly2880 declared parameter combinations")
    after = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in INPUTS}
    if before != after:
        raise RuntimeError("an input changed during the run; do not save result")
    resolved = {"ciphertext": K4_CIPHERTEXT, "key_source_plaintext": K3_PLAINTEXT,
                "known_zero_based": [[i, c] for i, c in sorted(known.items())],
                "alphabets": ALPHABETS, "equations": EQUATIONS, "window_length": n,
                "directions": ["forward", "reverse"],
                "stage_order": "C=S(T(P),K)", "key_position": "ciphertext/output position j",
                "gather_convention": "T(P)[j]=P[permutation[j]], zero-based permutation"}
    fits = sum(record["fits_inventory"] for record in records)
    return {
        "base_checkpoint": "K4-20261012-H", "experiment": "K3-running-key-after-route-inventory-filter",
        "formula": "Y=T(P), C_j=S(Y_j,K_j); invert all97 output-indexed key symbols before comparing inventories",
        "model_count": len(records), "fits": fits, "rejected": len(records) - fits,
        "nonwrapping_source_windows": 240, "reading_directions": 2, "distinct_key_strings": len(distinct_keys),
        "inverse_substitution_positions_checked": len(records) * n,
        "arbitrary_materializations_checked": fits,
        "minimum_total_excess": min(record["total_excess"] for record in records),
        "required_plaintext_counts": dict(sorted(Counter(known.values()).items())),
        "resolved_inputs": resolved, "resolved_inputs_sha256": sha256(canonical_bytes(resolved)).hexdigest(),
        "validation": validation, "inputs_unchanged": True,
        "inputs": [{"path": path, "sha256_before": before[path], "sha256_after": after[path]} for path in INPUTS],
        "python_version": platform.python_version(), "groups": groups, "records": records,
        "runtime_seconds": perf_counter() - started,
        "non_claims": [
            "Each rejection excludes every bijective97-position transposition for that exact output-indexed key, alphabet and equation only.",
            "A pass establishes only an arbitrary plaintext/permutation completion of the24 cribs, not a recovered message or physical route.",
            "This tests running-key substitution after transposition; the separately saved earlier probe tests substitution before transposition.",
            "No wrapping, alternative K3 spellings, ciphertext-derived keys, different offsets, other alphabets, nulls, feedback or extra layers.",
            "Parameter combinations can be equivalent; counts are not independent-hypothesis counts.",
            "No language ranking, route search, authenticated K5 input or external submission.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run only tiny hand controls")
    parser.add_argument("--output", type=Path, help="new evidence JSON file for the bounded2880-model run")
    args = parser.parse_args(argv)
    if args.self_test:
        if args.output is not None:
            parser.error("--self-test does not accept --output")
        print(json.dumps(self_test(), indent=2))
        return
    if args.output is None:
        parser.error("use --self-test or --output")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "research") or output.exists():
        parser.error("choose a new output file under research; existing evidence is never replaced")
    result = analyze()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(result, file, indent=2, ensure_ascii=True, allow_nan=False)
        file.write("\n")
    print(json.dumps({key: result[key] for key in (
        "model_count", "fits", "rejected", "distinct_key_strings", "minimum_total_excess",
        "validation", "inputs_unchanged", "runtime_seconds")}, indent=2))


if __name__ == "__main__":
    main()
