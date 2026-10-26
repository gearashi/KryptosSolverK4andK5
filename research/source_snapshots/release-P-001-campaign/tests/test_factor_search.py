"""Exact brute-force comparisons for bounded integer-factor optimization."""
import itertools
import math
import random
import unittest
from unittest.mock import patch

from kryptos.factor_search import (IntegerFactor, FactorBudgetExceeded,
    product_score, optimize_product, ngram_problem, optimize_ngrams)
from kryptos.general_layers import solve_layers
from kryptos.language import CorpusDocument, train_ngram_model


def brute(domains, factors):
    scored = []
    for assignment in itertools.product(*(range(v) for v in domains)):
        value = math.prod(f.values[tuple(assignment[i] for i in f.scope)] ** f.power for f in factors)
        scored.append((value, assignment))
    score = max(value for value, _ in scored)
    point = min(assignment for value, assignment in scored if value == score)
    return score, point


class FactorSearchTests(unittest.TestCase):
    def test_exact_against_bruteforce_with_overlapping_factors_and_ties(self):
        rng = random.Random(20261013)
        domains = (2, 3, 2, 4)
        for _ in range(12):
            factors = []
            for scope in ((0, 1), (1, 2), (0, 2, 3)):
                values = {point: rng.randrange(8) for point in itertools.product(*(range(domains[i]) for i in scope))}
                factors.append(IntegerFactor(scope, values))
            score, point = brute(domains, factors)
            result = optimize_product(domains, factors)
            self.assertTrue(result["complete"] and result["optimal"] and result["tie_break_proven"])
            self.assertEqual((result["score"], tuple(result["assignment"])), (score, point))
            self.assertEqual(result["upper_bound"], score)

    def test_admissible_upper_bounds_under_every_node_budget(self):
        domains = (3, 3, 3)
        factors = [IntegerFactor((0, 1), {(a, b): 1 + 7 * (a == b) for a in range(3) for b in range(3)}),
                   IntegerFactor((1, 2), {(b, c): 1 + 5 * (b != c) for b in range(3) for c in range(3)}),
                   IntegerFactor((0, 2), {(a, c): 1 + 9 * (a == c == 2) for a in range(3) for c in range(3)})]
        optimum, point = brute(domains, factors)
        saw_incomplete = False
        for limit in range(25):
            result = optimize_product(domains, factors, max_nodes=limit)
            self.assertLessEqual(result["lower_bound"], optimum)
            self.assertGreaterEqual(result["upper_bound"], optimum)
            self.assertEqual(result["score"], product_score(domains, factors, result["assignment"]))
            self.assertEqual(result["optimal"], result["lower_bound"] == result["upper_bound"])
            if result["tie_break_proven"]:
                self.assertEqual(tuple(result["assignment"]), point)
            saw_incomplete |= not result["complete"]
        self.assertTrue(saw_incomplete)

    def test_time_interruption_keeps_a_valid_incumbent_and_upper_bound(self):
        factors = [IntegerFactor((0,), {(0,): 1, (1,): 5})]
        with patch("kryptos.factor_search.monotonic", side_effect=(0.0, 2.0, 2.0)):
            result = optimize_product((2,), factors, time_limit_seconds=1.0)
        self.assertFalse(result["complete"])
        self.assertFalse(result["optimal"])
        self.assertEqual(result["stop_reason"], "time_budget")
        self.assertEqual((result["lower_bound"], result["upper_bound"]), (1, 5))

    def test_exact_pruning_reduces_the_number_of_complete_evaluations(self):
        domains = (2,) * 10
        factors = [IntegerFactor((i,), {(0,): 1, (1,): 3}) for i in range(10)]
        result = optimize_product(domains, factors)
        self.assertEqual((result["score"], tuple(result["assignment"])), brute(domains, factors))
        self.assertLess(result["leaf_nodes"] + 1, 1024)
        self.assertLess(result["nodes"], 1024)
        self.assertGreater(result["factor_cache_hits"], 0)
        uncached = optimize_product(domains, factors, max_cache_entries=0)
        self.assertEqual((uncached["score"], uncached["assignment"]), (result["score"], result["assignment"]))

    def test_zero_constant_and_empty_factors_preserve_tie_policy(self):
        for domains, factors in (((), []), ((2, 3), []), ((2,), [IntegerFactor((), {(): 0})]),
                                 ((2,), [IntegerFactor((0,), {(0,): 8, (1,): 8}, power=3)])):
            result = optimize_product(domains, factors)
            self.assertEqual((result["score"], tuple(result["assignment"])), brute(domains, factors))
            self.assertTrue(result["complete"] and result["tie_break_proven"])

    def test_ngram_adapter_uses_exact_saved_alpha_and_preserves_mask_gaps(self):
        # Deliberately synthetic symbols: this is an adapter regression, not a
        # trained English model or evidence of real-world language recognition.
        model = train_ngram_model([CorpusDocument("ABABABACCDABAB", "synthetic:training")],
                                  label="synthetic bigrams", order=2, alpha=0.1)
        solution = solve_layers("CDEFGH", {}, [{"operation": "substitution", "period": 1}])
        mask = (2,)
        problem = ngram_problem(solution, model, mask)
        self.assertEqual(problem.metadata["window_positions"], [[0, 1], [3, 4], [4, 5]])
        self.assertNotIn([1, 3], problem.metadata["window_positions"])
        num, den = (0.1).as_integer_ratio()
        self.assertEqual(problem.metadata["alpha_rational"]["numerator"], num)
        self.assertEqual(problem.metadata["alpha_rational"]["denominator"], den)
        for a, b, text in solution.enumerate_plaintexts(26):
            expected = math.prod(model.counts.get(text[i:i + 2], 0) * den + num for i in (0, 3, 4))
            self.assertEqual(product_score(problem.domains, problem.factors, a + b), expected)
            self.assertEqual(model.score(text, mask).windows, 3)
        best, point = brute(problem.domains, problem.factors)
        result = optimize_ngrams(solution, model, mask)
        self.assertEqual((result["search"]["score"], tuple(result["search"]["assignment"])), (best, point))
        self.assertTrue(result["candidate"]["reencryption_matches"])
        iterator_mask = optimize_ngrams(solution, model, iter(mask))
        self.assertEqual(iterator_mask["search"]["score"], result["search"]["score"])
        with self.assertRaises(FactorBudgetExceeded):
            ngram_problem(solution, model, mask, max_factor_entries=1)
        empty = optimize_ngrams(solution, model, range(6))
        self.assertFalse(empty["scoring"]["score_available"])
        self.assertIsNone(empty["display_model_score"]["mean_log_probability"])
        self.assertEqual(empty["search"]["score"], 1)

    def test_validation(self):
        with self.assertRaises(ValueError):
            IntegerFactor((0,), {(0,): -1})
        with self.assertRaises(ValueError):
            IntegerFactor((1, 0), {(0, 0): 1})
        with self.assertRaises(ValueError):
            optimize_product((2,), [IntegerFactor((0,), {(0,): 1})])
        with self.assertRaises(ValueError):
            optimize_product((True,), [])
        with self.assertRaises(ValueError):
            optimize_product((2,), [], time_limit_seconds=float("nan"))


if __name__ == "__main__":
    unittest.main()
