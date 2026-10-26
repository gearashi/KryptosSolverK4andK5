import itertools
import string
import unittest

from kryptos.alphabet_propagation import all_different_support, recover_cyclic_alphabet
from kryptos.keyed_alphabet import recover_cyclic_alphabet as original
from kryptos.explanations import replay_recipe

A = string.ascii_uppercase


def brute_support(domains):
    valid = [p for p in itertools.permutations(range(len(domains)))
             if all(d & (1 << w) for d, w in zip(domains, p))]
    return [sum(1 << w for w in {p[v] for p in valid}) for v in range(len(domains))] if valid else None


class AlphabetPropagationTests(unittest.TestCase):
    def test_exhaustive_three_by_three_graphs(self):
        for n in range(1, 4):
            for domains in itertools.product(range(1 << n), repeat=n):
                expected = brute_support(domains)
                actual = all_different_support(domains)
                self.assertEqual(actual["feasible"], expected is not None)
                if expected is not None:
                    self.assertEqual(actual["domains"], expected)

    def test_hall_set_prunes_edges_without_singletons(self):
        result = all_different_support([3, 3, 15, 15])
        self.assertEqual(result["domains"], [3, 3, 12, 12])
        self.assertEqual(result["removed_edges"], 4)
        self.assertEqual(len(set(result["matching"])), 4)
        self.assertEqual(all_different_support(result["domains"])["removed_edges"], 0)

    def test_hall_violation_not_only_duplicate_singletons(self):
        self.assertFalse(all_different_support([3, 3, 3, 15])["feasible"])

    def test_complete_assignment_counts_and_storage_cap_preserved(self):
        fixed = {c: i for i, c in enumerate(A[:22])}
        kwargs = dict(period=2, fixed_indices=fixed, max_candidates=2, max_states=5000, time_limit_seconds=10)
        for cipher in ("vigenere", "beaufort", "variant"):
            # One phase is unobserved by the one-letter message and not counted.
            old = original("A", [{"start": 1, "text": "A"}], cipher=cipher, **kwargs)
            new = recover_cyclic_alphabet("A", [{"start": 1, "text": "A"}], cipher=cipher, **kwargs)
            self.assertTrue(new["complete"])
            self.assertEqual(new["total_alphabet_key_assignments"], 24)
            self.assertEqual(old["total_alphabet_key_assignments"], new["total_alphabet_key_assignments"])
            self.assertTrue(new["candidates_omitted"])
            self.assertFalse(new["unit_scaling_quotient"])
            for c in new["candidates"]:
                self.assertEqual(replay_recipe(c["plaintext"], c["encryption_recipe"])["ciphertext"], "A")

    def test_absolute_indices_and_nonunit_equation_preserved(self):
        alphabet = "NOPQRSTUVWXYZABCDEFGHIJKLM"
        r = recover_cyclic_alphabet("AAA", [{"start": 1, "text": "AAA"}], period=1,
                                    cipher="beaufort", fixed_indices={c: i for i, c in enumerate(alphabet)})
        self.assertTrue(r["complete"])
        self.assertEqual(r["total_alphabet_key_assignments"], 1)
        self.assertEqual(r["candidates"][0]["alphabet"], alphabet)
        self.assertEqual(r["candidates"][0]["key_pattern"], "N")

    def test_impossible_and_censored_are_distinct(self):
        impossible = recover_cyclic_alphabet("AB", [{"start": 1, "text": "AA"}], period=1)
        self.assertTrue(impossible["complete"])
        self.assertFalse(impossible["feasible"])
        censored = recover_cyclic_alphabet("ABC", [], period=2, max_states=1)
        self.assertFalse(censored["complete"])
        self.assertIsNone(censored["feasible"])
        self.assertIsNone(censored["total_alphabet_key_assignments"])

    def test_domain_validation(self):
        for d in ([], [True], [2], [-1], [0] * 27):
            with self.assertRaises(ValueError):
                all_different_support(d)


if __name__ == "__main__":
    unittest.main()
