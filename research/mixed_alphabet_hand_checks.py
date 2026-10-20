"""Bounded independent toy check: 676 A-key pairs, never imports the engine.

Run: python research/mixed_alphabet_hand_checks.py
The alphabet B swaps A/B; the gather permutation is deliberately non-involutive.
"""
from datetime import datetime, timezone
import hashlib
from itertools import product
import json
from pathlib import Path
import time

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
PI = [0, 2, 3, 1, 5, 4]
INVERSE = [0, 3, 1, 2, 5, 4]
P = "ABCDEF"
KEY_A, KEY_B = [1, 4], [2, 7, 11]


def substitute(text, alphabet, key):
    return "".join(alphabet[(alphabet.index(c) + key[i % len(key)]) % 26]
                   for i, c in enumerate(text))


def transpose(text):
    return "".join(text[i] for i in PI)


def encrypt(text, order, a=KEY_A, b=KEY_B):
    if order == "SST":
        return transpose(substitute(substitute(text, A, a), B, b))
    if order == "STS":
        return substitute(transpose(substitute(text, A, a)), B, b)
    if order == "TSS":
        return substitute(substitute(transpose(text), A, a), B, b)
    raise ValueError(order)


def enumerate_sts(known_positions):
    """Brute-force both A-key entries independently; infer all three B entries.

    This does not use graph propagation or assume a root parameterization.
    The selected toy crib sets all touch each B phase.
    """
    ciphertext = "CKSHQQ"
    solutions = []
    for a in product(range(26), repeat=2):
        b = [None] * 3
        consistent = True
        for i in known_positions:
            j = INVERSE[i]
            middle = A[(A.index(P[i]) + a[i % 2]) % 26]
            required = (B.index(ciphertext[j]) - B.index(middle)) % 26
            phase = j % 3
            if b[phase] is not None and b[phase] != required:
                consistent = False
                break
            b[phase] = required
        if not consistent:
            continue
        assert all(value is not None for value in b)
        plain = [None] * 6
        for j, i in enumerate(PI):
            middle = B[(B.index(ciphertext[j]) - b[j % 3]) % 26]
            plain[i] = A[(A.index(middle) - a[i % 2]) % 26]
        plain = "".join(plain)
        assert all(plain[i] == P[i] for i in known_positions)
        assert encrypt(plain, "STS", a, b) == ciphertext
        solutions.append({"a": list(a), "b": b, "plaintext": plain})
    return solutions


def main():
    started = datetime.now(timezone.utc).isoformat()
    timer = time.perf_counter()
    assert [PI[INVERSE[i]] for i in range(6)] == list(range(6))
    assert PI != INVERSE
    ciphers = {order: encrypt(P, order) for order in ("SST", "STS", "TSS")}
    assert ciphers == {"SST": "COJMUM", "STS": "CKSHQQ", "TSS": "CNPHNT"}
    tree = enumerate_sts([0, 1, 3, 5])
    one_cycle = enumerate_sts([0, 1, 3, 4, 5])
    two_cycles = enumerate_sts(list(range(6)))
    assert len(tree) == 26
    assert one_cycle == [
        {"a": [1, 4], "b": [2, 7, 11], "plaintext": "ABCDEF"},
        {"a": [20, 24], "b": [8, 13, 18], "plaintext": "ABDDEF"},
    ]
    assert two_cycles == one_cycle[:1]
    output = {
        "base_checkpoint": "K4-20261012-F", "started_at": started,
        "alphabet_a": A, "alphabet_b": B, "gather_permutation": PI,
        "inverse_permutation": INVERSE, "input_plaintext": P,
        "key_a": KEY_A, "key_b": KEY_B, "ciphertexts_by_order": ciphers,
        "bounds": {"A_key_pairs_per_case": 676, "cases": 3, "message_letters": 6},
        "method": "Enumerate all 26^2 A-key pairs; derive B phases from cribs; compare duplicate phase requirements; decrypt and reencrypt every retained pair.",
        "cases": [
            {"known_positions_zero_based": [0, 1, 3, 5], "components": 1,
             "cycle_rank": 0, "key_assignment_count": len(tree),
             "distinct_plaintext_count": len({r['plaintext'] for r in tree}),
             "solutions": tree},
            {"known_positions_zero_based": [0, 1, 3, 4, 5], "components": 1,
             "cycle_rank": 1, "key_assignment_count": len(one_cycle),
             "distinct_plaintext_count": 2, "solutions": one_cycle},
            {"known_positions_zero_based": list(range(6)), "components": 1,
             "cycle_rank": 2, "key_assignment_count": len(two_cycles),
             "distinct_plaintext_count": 1, "solutions": two_cycles}],
        "non_claims": ["No K4 candidate, search, or app test.",
                       "Toy vectors audit the stated mixed-alphabet equations; historical alphabet choices remain a separate assumption."],
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runtime_seconds": time.perf_counter() - timer,
    }
    destination = Path(__file__).with_suffix(".json")
    destination.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ciphertexts": ciphers, "key_counts": [len(tree), len(one_cycle), len(two_cycles)],
                      "plaintext_counts": [row['distinct_plaintext_count'] for row in output['cases']],
                      "runtime_seconds": output['runtime_seconds'], "output": str(destination)}))


if __name__ == "__main__":
    main()
