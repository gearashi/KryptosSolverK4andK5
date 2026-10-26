"""Independent checkpoint-J controls; no CSP helper is used by the oracles."""

import itertools
import math
import string
import unittest

from kryptos.keyed_alphabet import recover_cyclic_alphabet


A = string.ascii_uppercase


class KeyedAlphabetAuditTests(unittest.TestCase):
    def test_unfixed_alphabet_cycle_has_twelve_unit_steps(self):
        # A->B->...->Z->A with a one-phase key forces index(letter_i)=i*k
        # after index(A)=0. Bijection holds iff k is a unit modulo26.
        for cipher in ("vigenere", "variant"):
            with self.subTest(cipher=cipher):
                result = recover_cyclic_alphabet(A[1:] + A[:1], [{"start": 1, "text": A}],
                                                  period=1, cipher=cipher, max_candidates=100,
                                                  time_limit_seconds=5)
                expected = set()
                for step in range(26):
                    if math.gcd(step, 26) != 1:
                        continue
                    indices = {letter: i * step % 26 for i, letter in enumerate(A)}
                    alphabet = "".join(sorted(A, key=indices.get))
                    numeric_key = step if cipher == "vigenere" else -step % 26
                    expected.add((alphabet, alphabet[numeric_key]))
                self.assertTrue(result["complete"])
                self.assertEqual(result["total_alphabet_key_assignments"], 12)
                self.assertEqual({(row["alphabet"], row["key_pattern"]) for row in result["candidates"]}, expected)
                self.assertEqual({row["plaintext"] for row in result["candidates"]}, {A})

    def test_two_unknown_letters_and_unconstrained_key_match_enumeration(self):
        # With24 absolute indices fixed, exactly2 alphabet completions remain.
        # With no cribs, each of26 numeric one-phase keys is permitted.
        fixed = {c: i for i, c in enumerate(A[:24])}
        for cipher in ("vigenere", "beaufort", "variant"):
            with self.subTest(cipher=cipher):
                expected = set()
                for tail in itertools.permutations("YZ"):
                    alphabet = A[:24] + "".join(tail)
                    for key in range(26):
                        values = [alphabet.index(c) for c in "ZY"]
                        plain = "".join(alphabet[(c - key if cipher == "vigenere" else
                                                  key - c if cipher == "beaufort" else c + key) % 26]
                                        for c in values)
                        expected.add((alphabet, alphabet[key], plain))
                result = recover_cyclic_alphabet("ZY", [], period=1, cipher=cipher,
                                                  fixed_indices=fixed, max_candidates=100,
                                                  time_limit_seconds=5)
                self.assertTrue(result["complete"])
                self.assertEqual(result["total_alphabet_key_assignments"], 52)
                actual = {(row["alphabet"], row["key_pattern"], row["plaintext"])
                          for row in result["candidates"]}
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
