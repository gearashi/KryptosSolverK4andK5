import unittest
from kryptos.__main__ import run_recovery, run_layers, run_grid, run_residues, _target


class CliTests(unittest.TestCase):
    def test_optional_parity_hypothesis_is_explicit(self):
        result = run_residues({})
        self.assertTrue(result["feasible"])
        self.assertEqual(result["modulus"], 2)
        self.assertEqual(result["residue_partition_completions"], 1716)
        self.assertFalse(result["authenticated_solution"])
        self.assertEqual(result["explanation"]["classification"], "constraint_only")
        self.assertIsNone(result["explanation"]["encryption_recipe"])

    def test_normalization_preserves_positions(self):
        self.assertEqual(_target({"ciphertext": "a b\nc"})[1], "ABC")
        for request in ({"ciphertext": "ß"}, {"ciphertext": "ABC", "cribs": [{"start": 1, "text": "ß"}]}):
            with self.assertRaises(ValueError):
                _target(request)

    def test_invalid_limits_rejected_even_for_impossible_model(self):
        for field in ("max_candidates", "top", "time_limit_seconds"):
            with self.assertRaises(ValueError):
                run_layers({field: 0})
        with self.assertRaises(ValueError):
            run_recovery({"max_crib_checks": 1000001})

    def test_grid_requires_geometry_and_checks_literal_vector(self):
        with self.assertRaises(ValueError):
            run_grid({"ciphertext": "DOJJUP"})
        result = run_grid({"ciphertext": "DOJJUP", "alphabet": "standard",
            "cells": [[0,0],[0,1],[0,2],[1,0],[1,1],[1,2]],
            "permutation": [0,2,3,1,5,4], "cribs": [{"start": 1, "text": "ABCDEF"}]})
        self.assertTrue(result["feasible"])
        self.assertTrue(result["reencryption_matches"])
        self.assertEqual(result["plaintext_mask"], "ABCDEF")
        self.assertEqual(result["explanation"]["classification"], "consistency_witness")
        self.assertTrue(result["explanation"]["verification"]["literal_reencryption_matches"])

    def test_k5_requires_explicit_input(self):
        with self.assertRaises(ValueError):
            _target({"target": "k5"})

    def test_recovery_has_no_answer_key_argument(self):
        result = run_recovery({"target": "custom", "ciphertext": "LXFOPVEFRNHR", "alphabet": "standard",
                               "cribs": [{"start": 1, "text": "ATTACK"}], "max_period": 5})
        self.assertTrue(any(row["plaintext"] == "ATTACKATDAWN" for row in result["candidates"]))
        self.assertFalse(result["authenticated_solution"])
        candidate = next(row for row in result["candidates"] if row["plaintext"] == "ATTACKATDAWN")
        self.assertEqual(candidate["explanation"]["classification"], "complete_candidate")
        self.assertTrue(candidate["explanation"]["verification"]["literal_reencryption_matches"])

    def test_layer_budget_prevents_arbitrary_representative_ranking(self):
        request = {"ciphertext": "DKSHQQ", "alphabet": "standard", "order": "STS",
                   "permutation": [0, 2, 3, 1, 5, 4], "period_a": 2, "period_b": 3,
                   "cribs": [{"start": 1, "text": "AB"}, {"start": 4, "text": "D"}],
                   "max_candidates": 25}
        result = run_layers(request)
        self.assertTrue(result["feasible"])
        self.assertEqual(result["distinct_plaintext_count"], 26)
        self.assertEqual(result["evaluated"], 0)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["explanation"]["search"]["bounds"]["max_candidates"], 25)
        self.assertFalse(result["explanation"]["search"]["enumeration_complete"])
        request["max_candidates"] = 26
        result = run_layers(request)
        self.assertTrue(result["enumeration_complete"])
        self.assertEqual(result["evaluated"], 26)

    def test_overlapping_crib_contradiction(self):
        with self.assertRaises(ValueError):
            _target({"ciphertext": "ABC", "cribs": [{"start": 1, "text": "A"}, {"start": 1, "text": "B"}]})

    def test_wrong_cipher_or_unknown_settings_are_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            run_layers({"cipher": "beaufort"})
        with self.assertRaises(ValueError):
            run_layers({"key": "SECRET"})
        with self.assertRaises(ValueError):
            run_recovery({"periodd": 8})


if __name__ == "__main__":
    unittest.main()
