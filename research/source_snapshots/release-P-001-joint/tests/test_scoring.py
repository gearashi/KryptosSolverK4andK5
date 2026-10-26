"""Small scoring regressions; not the full application test suite."""
import math
import unittest
from unittest.mock import patch

from kryptos.engine import run_batch
from kryptos.scoring import english_score


class MaskedScoreTests(unittest.TestCase):
    def test_masked_letters_have_no_influence(self):
        self.assertEqual(english_score("THISBERLINTHAT", range(4, 10)),
                         english_score("THISQZXJKVTHAT", range(4, 10)))

    def test_no_artificial_adjacency_across_gap(self):
        # Weight by the number of scored characters, not the number of runs.
        expected = (english_score("T") + 2 * english_score("HE")) / 3
        self.assertAlmostEqual(english_score("TXHE", [1]), expected)
        self.assertNotEqual(english_score("TXHE", [1]), english_score("THE"))

    def test_penalties_do_not_cross_mask_boundaries(self):
        self.assertEqual(english_score("QX", [1]), english_score("Q"))
        self.assertEqual(english_score("QQ", [1]), english_score("Q"))

    def test_empty_coverage_is_finite_neutral(self):
        self.assertEqual(english_score("BERLIN", range(6)), 0.0)
        self.assertTrue(math.isfinite(english_score("")))

    def test_dictionary_reports_scored_coverage(self):
        result = run_batch({"target": "custom", "ciphertext": "LXFOPVEFRNHR",
                            "keys": ["LEMON"], "cribs": [{"start": 1, "text": "ATTACK"}]}, 0)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["score"], english_score("ATDAWN"))
        self.assertEqual(candidate["language_scored_characters"], 6)
        self.assertTrue(candidate["language_score_available"])
        all_known = run_batch({"target": "custom", "ciphertext": "LXFOPVEFRNHR",
                               "keys": ["LEMON"], "cribs": [{"start": 1, "text": "ATTACKATDAWN"}]}, 0)["candidates"][0]
        self.assertEqual(all_known["score"], 0.0)
        self.assertFalse(all_known["language_score_available"])

    def test_annealing_scores_use_the_same_mask(self):
        with patch("kryptos.engine.english_score", wraps=english_score) as scorer:
            run_batch({"target": "custom", "ciphertext": "LXFOPVEFRNHR", "method": "anneal",
                       "min_period": 5, "max_period": 5, "iterations": 1, "restarts": 1,
                       "cribs": [{"start": 1, "text": "ATT"}]}, 0)
        self.assertEqual(scorer.call_count, 2)
        self.assertTrue(all(call.kwargs["excluded_positions"] == frozenset((0, 1, 2))
                            for call in scorer.call_args_list))


if __name__ == "__main__":
    unittest.main()
