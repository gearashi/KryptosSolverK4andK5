"""Frozen supported-edge audit; exhaustive small graphs and finite cipher fixtures."""
import argparse
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import string
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.alphabet_propagation import all_different_support, recover_cyclic_alphabet
from kryptos.keyed_alphabet import recover_cyclic_alphabet as original
from kryptos.explanations import replay_recipe

INPUT_PATHS = ("research/alphabet_propagation_K.py", "kryptos/alphabet_propagation.py",
               "kryptos/keyed_alphabet.py", "kryptos/explanations.py", "kryptos/ciphers.py")
A = string.ascii_uppercase


def encrypt(text, alphabet, key, cipher):
    out = []
    for i, c in enumerate(text):
        p, k = alphabet.index(c), key[i % len(key)]
        out.append(alphabet[(p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k) % 26])
    return "".join(out)


def graph_audit():
    counts = []
    stream = sha256()
    for n in range(1, 5):
        permutations = tuple(itertools.permutations(range(n)))
        graphs = feasible = removed = 0
        for domains in itertools.product(range(1 << n), repeat=n):
            expected = [0] * n
            valid = 0
            for permutation in permutations:
                if all(domain & (1 << value) for domain, value in zip(domains, permutation)):
                    valid += 1
                    for v, w in enumerate(permutation):
                        expected[v] |= 1 << w
            actual = all_different_support(domains)
            assert actual["feasible"] == bool(valid)
            if valid:
                assert actual["domains"] == expected
                assert all_different_support(actual["domains"])["domains"] == expected
                feasible += 1
                removed += actual["removed_edges"]
            graphs += 1
            stream.update(bytes(domains) + bytes(expected) + bytes([bool(valid)]))
        counts.append({"size": n, "graphs": graphs, "feasible": feasible, "unsupported_edges_removed": removed})
    return {"exhaustive_sizes": [1, 4], "counts": counts, "ordered_comparison_sha256": stream.hexdigest(),
            "hall_pruning_witness": all_different_support([3, 3, 15, 15]),
            "hall_impossibility_witness": all_different_support([3, 3, 3, 15])}


def cipher_audit():
    records = []
    fixed = {c: i for i, c in enumerate(A[:22])}
    for cipher in ("vigenere", "beaufort", "variant"):
        for message in (A + A[::-1] + "WXYZWAWBXCYDZ", "WXXWYZ", "WXYZ", "A"):
            key = (3, 19) if len(message) > 1 else (0,)
            ciphertext = encrypt(message, A[:22] + "YWZX", key, cipher)
            expected = set()
            for tail in itertools.permutations("WXYZ"):
                alpha = A[:22] + "".join(tail)
                residues = []
                for i in range(len(key)):
                    p, c = alpha.index(message[i]), alpha.index(ciphertext[i])
                    residues.append((c - p if cipher == "vigenere" else c + p if cipher == "beaufort" else p - c) % 26)
                if encrypt(message, alpha, residues, cipher) == ciphertext:
                    expected.add((alpha, "".join(alpha[k] for k in residues)))
            kwargs = dict(period=len(key), cipher=cipher, fixed_indices=fixed,
                          max_states=20000, max_candidates=100, time_limit_seconds=5)
            cribs = [{"start": 1, "text": message}]
            old, new = original(ciphertext, cribs, **kwargs), recover_cyclic_alphabet(ciphertext, cribs, **kwargs)
            for result in (old, new):
                assert result["complete"] and result["total_alphabet_key_assignments"] == len(expected)
                assert {(c["alphabet"], c["key_pattern"]) for c in result["candidates"]} == expected
                for candidate in result["candidates"]:
                    assert replay_recipe(candidate["plaintext"], candidate["encryption_recipe"])["ciphertext"] == ciphertext
            records.append({"cipher": cipher, "plaintext": message, "ciphertext": ciphertext,
                            "period": len(key), "fixed_indices": fixed, "brute_alphabets": 24,
                            "expected_assignments": len(expected), "J": old, "supported_edge": new})
    impossible = []
    for cipher in ("vigenere", "beaufort", "variant"):
        old = original("AB", [{"start": 1, "text": "AA"}], period=1, cipher=cipher)
        new = recover_cyclic_alphabet("AB", [{"start": 1, "text": "AA"}], period=1, cipher=cipher)
        assert old["complete"] and new["complete"] and old["feasible"] is False and new["feasible"] is False
        impossible.append({"cipher": cipher, "J": old, "supported_edge": new})
    return {"planted_and_ambiguous": records, "impossible": impossible,
            "summary": {"planted_and_ambiguous_cases": len(records), "impossible_cases": len(impossible),
                        "J_states": sum(r["J"]["stats"]["states"] for r in records),
                        "supported_edge_states": sum(r["supported_edge"]["stats"]["states"] for r in records),
                        "supported_edges_removed": sum(r["supported_edge"]["stats"]["all_different_edges_pruned"] for r in records)}}


def run():
    started = perf_counter()
    before = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUT_PATHS}
    graphs, ciphers = graph_audit(), cipher_audit()
    after = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUT_PATHS}
    assert before == after
    return {"schema": "kryptos.supported-alphabet-audit.v1", "python": platform.python_version(),
            "contract": "All square domain graphs n=1..4 versus independent permutation enumeration; twelve fixed cipher controls and three impossible controls versus J. No K4 scan or unit-scaling quotient.",
            "graphs": graphs, "ciphers": ciphers, "input_sha256_before": before, "input_sha256_after": after,
            "elapsed_seconds": perf_counter() - started,
            "nonclaims": "Exact matching support is stronger propagation, not guaranteed wall-clock acceleration. Counts remain complete alphabet/used-key assignments under J's gauge, not plaintext counts."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh result path")
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"graphs": result["graphs"]["counts"], "ciphers": result["ciphers"]["summary"], "seconds": result["elapsed_seconds"]}))
