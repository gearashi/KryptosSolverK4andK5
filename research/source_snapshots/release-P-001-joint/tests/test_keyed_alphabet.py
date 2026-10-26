import itertools
import string
import unittest

from kryptos.keyed_alphabet import recover_cyclic_alphabet
from kryptos.explanations import replay_recipe

A = string.ascii_uppercase


def literal_encrypt(text, alphabet, numeric_key, cipher):
    output = []
    for i, c in enumerate(text):
        p, k = alphabet.index(c), numeric_key[i % len(numeric_key)]
        output.append(alphabet[(p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k) % 26])
    return "".join(output)


class UnknownAlphabetTests(unittest.TestCase):
    def test_matches_independent_permutation_enumerator(self):
        # Alphabet and key are withheld; only 22 supplied indices and full
        # plaintext cribs constrain the remaining four symbols and two phases.
        plaintext = A + A[::-1] + "WXYZWAWBXCYDZ"
        secret = A[:22] + "YWZX"
        fixed = {c: i for i, c in enumerate(A[:22])}
        for cipher in ("vigenere", "beaufort", "variant"):
            ciphertext = literal_encrypt(plaintext, secret, [3, 19], cipher)
            expected = set()
            for tail in itertools.permutations("WXYZ"):
                alphabet = A[:22] + "".join(tail)
                key = []
                for i in range(2):
                    c, p = alphabet.index(ciphertext[i]), alphabet.index(plaintext[i])
                    key.append((c - p if cipher == "vigenere" else c + p if cipher == "beaufort" else p - c) % 26)
                if literal_encrypt(plaintext, alphabet, key, cipher) == ciphertext:
                    expected.add((alphabet, "".join(alphabet[k] for k in key)))
            result = recover_cyclic_alphabet(ciphertext, [{"start": 1, "text": plaintext}], period=2,
                cipher=cipher, fixed_indices=fixed, max_candidates=100, time_limit_seconds=10)
            self.assertTrue(result["complete"], result)
            self.assertEqual(expected, {(c["alphabet"], c["key_pattern"]) for c in result["candidates"]})
            self.assertEqual(len(expected), result["total_alphabet_key_assignments"])
            self.assertGreater(len(expected), 0)

    def test_storage_cap_does_not_censor_count(self):
        fixed = {c: i for i, c in enumerate(A[:24])}
        result = recover_cyclic_alphabet("A", [{"start": 1, "text": "A"}], period=1,
                                         fixed_indices=fixed, max_candidates=1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_alphabet_key_assignments"], 2)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertTrue(result["candidates_omitted"])

    def test_nonunit_coefficient_beaufort(self):
        alphabet = "NOPQRSTUVWXYZABCDEFGHIJKLM"
        fixed = {c: i for i, c in enumerate(alphabet)}
        result = recover_cyclic_alphabet("AAA", [{"start": 1, "text": "AAA"}], period=1,
                                         cipher="beaufort", fixed_indices=fixed)
        self.assertTrue(result["complete"])
        self.assertEqual(result["candidates"][0]["key_pattern"], "N")
        self.assertEqual(result["total_alphabet_key_assignments"], 1)

    def test_impossible_same_phase_is_exact_rejection(self):
        result = recover_cyclic_alphabet("AB", [{"start": 1, "text": "AA"}], period=1)
        self.assertTrue(result["complete"])
        self.assertFalse(result["feasible"])
        self.assertEqual(result["total_alphabet_key_assignments"], 0)

    def test_bound_is_inconclusive_without_witness(self):
        result = recover_cyclic_alphabet("ABC", [], period=2, max_states=1)
        self.assertFalse(result["complete"])
        self.assertIsNone(result["feasible"])
        self.assertIsNone(result["total_alphabet_key_assignments"])
        self.assertEqual(result["stop_reason"], "state_limit")

    def test_unused_phases_not_counted_and_replayable(self):
        result = recover_cyclic_alphabet("BC", [{"start": 1, "text": "AB"}], period=4,
                                         fixed_indices={c: i for i, c in enumerate(A)})
        candidate = result["candidates"][0]
        self.assertEqual(candidate["key_pattern"], "BB??")
        self.assertEqual(result["total_alphabet_key_assignments"], 1)
        self.assertEqual(replay_recipe(candidate["plaintext"], candidate["encryption_recipe"])["ciphertext"], "BC")

    def test_validation_precedes_easy_rejection(self):
        for kwargs in ({"max_states": True}, {"time_limit_seconds": float("nan")},
                       {"fixed_indices": {"A": 0, "B": 0}}, {"cipher": "table"}):
            with self.assertRaises(ValueError):
                recover_cyclic_alphabet("AB", [{"start": 1, "text": "AA"}], period=1, **kwargs)


if __name__ == "__main__":
    unittest.main()
