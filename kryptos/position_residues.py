"""Necessary constraints for C[i] = F(P[i]) + step*i (mod 26).

F is an unknown bijective substitution. Reducing modulo 2 or 13 is a
strictly weaker hypothesis, and does not establish the full equation.
Positions are one-based; another origin is absorbed into F.
"""

from math import factorial
from .ciphers import get_alphabet


def check_position_residues(ciphertext, known, *, modulus=2, step=1, alphabet="standard"):
    letters = get_alphabet(alphabet)
    if not isinstance(ciphertext, str) or not ciphertext or any(c not in letters for c in ciphertext):
        raise ValueError("ciphertext must be nonempty uppercase A-Z")
    if type(modulus) is not int or modulus not in (2, 13, 26):
        raise ValueError("modulus must be 2, 13, or 26")
    if type(step) is not int:
        raise ValueError("step must be an integer")
    if not isinstance(known, dict) or any(type(i) is not int or not 0 <= i < len(ciphertext)
            or not isinstance(p, str) or len(p) != 1 or p not in letters for i, p in known.items()):
        raise ValueError("known must map zero-based positions to single uppercase letters")
    values, first, classes = {}, {}, [[] for _ in range(modulus)]
    result = {"feasible": False, "modulus": modulus, "step": step % modulus,
              "alphabet": alphabet, "position_origin": 1, "witness": None}
    for i, symbol in sorted(known.items()):
        residue = (letters.index(ciphertext[i]) - step * (i + 1)) % modulus
        if symbol in values and values[symbol] != residue:
            result["witness"] = {"kind": "repeated_letter", "letter": symbol,
                "positions_one_based": [first[symbol] + 1, i + 1], "residues": [values[symbol], residue]}
            return result
        if symbol not in values:
            values[symbol], first[symbol] = residue, i
            classes[residue].append(symbol)
            if len(classes[residue]) > 26 // modulus:
                result["witness"] = {"kind": "bijection_capacity", "residue": residue,
                    "letters": sorted(classes[residue]), "capacity": 26 // modulus}
                return result
    unobserved = sorted(set(letters) - set(values))
    remaining = [26 // modulus - len(group) for group in classes]
    partitions = factorial(len(unobserved))
    for count in remaining:
        partitions //= factorial(count)
    result.update({"feasible": True, "letter_residues": dict(sorted(values.items())),
        "classes": [sorted(group) for group in classes], "unobserved_letters": unobserved,
        "remaining_class_capacities": remaining, "residue_partition_completions": partitions,
        "interpretation": "Necessary and sufficient for this residue constraint only; no decryption or authentication."})
    return result
