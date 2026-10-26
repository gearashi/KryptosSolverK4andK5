import itertools
import unittest

from kryptos.correlated_bound import CorrelatedNgramBound

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def brute(base, columns, domains, values, counts):
    options = [range(d) if v < 0 else (v,) for d, v in zip(domains, values)]
    grams = {"".join(A[(b + sum(c[j] * x for c, x in zip(columns, point))) % 26]
                     for j, b in enumerate(base)) for point in itertools.product(*options)}
    return max(counts.get(g, 0) for g in grams), len(grams)


class CorrelatedBoundTests(unittest.TestCase):
    def test_diagonal_excludes_individually_reachable_high_count(self):
        bound = CorrelatedNgramBound(A, {"AB": 1000, "CC": 5}, 1, 10)
        result = bound.upper([0, 0], [[1, 1]], [26], [-1])
        self.assertEqual(result["upper"], 51)
        self.assertEqual(result["maximizing_observed_gram"], "CC")
        self.assertEqual(result["reachable_gram_count"], 26)

    def test_exhaustive_all_two_slot_binary_generators_and_partial_assignments(self):
        counts = {"AA": 2, "AN": 3, "NA": 7, "NN": 11, "AB": 100}
        bound = CorrelatedNgramBound(A, counts, 3, 5)
        for flat in itertools.product((0, 13), repeat=4):
            columns = [flat[:2], flat[2:]]
            for base in itertools.product((0, 13), repeat=2):
                for values in itertools.product((-1, 0, 1), repeat=2):
                    exact, size = brute(base, columns, [2, 2], values, counts)
                    result = bound.upper(base, columns, [2, 2], values)
                    self.assertTrue(result["applicable"])
                    self.assertEqual(result["upper"], exact * 5 + 3)
                    self.assertEqual(result["reachable_gram_count"], size)

    def test_mixed_prime_domains_and_fixed_offsets(self):
        counts = {"AB": 99, "NB": 88, "EC": 7, "ZA": 3, "NN": 6}
        bound = CorrelatedNgramBound(A, counts, 1, 10)
        for domains, columns in (([2, 13], [[13, 0], [2, 4]]), ([26, 13], [[1, 3], [4, 2]])):
            for values in itertools.product(*[(-1, 0, d - 1) for d in domains]):
                exact, size = brute([0, 1], columns, domains, values, counts)
                result = bound.upper([0, 1], columns, domains, values)
                self.assertEqual(result["upper"], exact * 10 + 1)
                self.assertEqual(result["reachable_gram_count"], size)

    def test_nonclosed_domains_fallback_but_fixed_values_are_valid(self):
        bound = CorrelatedNgramBound(A, {"B": 3}, 1, 1)
        for domain in (2, 3, 13):
            self.assertFalse(bound.upper([0], [[1]], [domain], [-1])["applicable"])
            self.assertEqual(bound.upper([0], [[1]], [domain], [1])["upper"], 4)

    def test_empty_counts_and_zero_domain_contribution(self):
        bound = CorrelatedNgramBound(A, {}, 3, 7)
        result = bound.upper([0], [[5], [0]], [1, 3], [-1, -1])
        self.assertEqual(result["upper"], 3)
        self.assertEqual(result["reachable_gram_count"], 1)

    def test_invalid_inputs_raise_instead_of_fallback(self):
        for counts in ({"A": True}, {"A": -1}, {"AA": 1, "A": 1}):
            with self.assertRaises(ValueError):
                CorrelatedNgramBound(A, counts, 1, 1)
        bound = CorrelatedNgramBound(A, {"A": 1}, 1, 1)
        for args in (([0], [[1]], [True], [-1]), ([0], [[1]], [2], [2]), ([26], [], [], [])):
            with self.assertRaises(ValueError):
                bound.upper(*args)


if __name__ == "__main__":
    unittest.main()
