import copy
import hashlib
import json
from pathlib import Path
import unittest

from kryptos.__main__ import run_recovery, run_layers, run_grid, run_residues
from kryptos.explanations import replay_recipe


class ExplanationTests(unittest.TestCase):
    def test_recovery_explanation_is_deterministic_and_pins_sources(self):
        request = {"ciphertext": "LXFOPVEFRNHR", "alphabet": "standard",
                   "cribs": [{"start": 1, "text": "ATTACK"}], "max_period": 5}
        unchanged = copy.deepcopy(request)
        first, second = run_recovery(request), run_recovery(request)
        self.assertEqual(first, second)
        self.assertEqual(request, unchanged)
        explanation = first["explanation"]
        self.assertEqual(explanation["supplied_assumptions"]["declared_periods"], [1, 2, 3, 4, 5])
        self.assertEqual(explanation["input"]["ciphertext_sha256"], hashlib.sha256(b"LXFOPVEFRNHR").hexdigest())
        root = Path(__file__).resolve().parents[1]
        for source in explanation["provenance"]["source_files"]:
            self.assertEqual(source["sha256"], hashlib.sha256((root / source["path"]).read_bytes()).hexdigest())
        candidate = first["candidates"][0]
        recipe = json.loads(json.dumps(candidate["explanation"]["encryption_recipe"]))
        self.assertEqual(replay_recipe(candidate["plaintext"], recipe)["ciphertext"], "LXFOPVEFRNHR")
        self.assertFalse(candidate["explanation"]["authenticated_solution"])

    def test_partial_recovery_never_claims_full_reencryption(self):
        result = run_recovery({"ciphertext": "LXFOPVEFRNHR", "alphabet": "standard",
                               "cribs": [{"start": 1, "text": "A"}], "min_period": 5, "max_period": 5})
        explanation = result["candidates"][0]["explanation"]
        self.assertEqual(explanation["classification"], "partial_candidate")
        self.assertEqual(explanation["recovered_values"]["key_pattern"], "L????")
        self.assertEqual(explanation["verification"]["status"], "not_replayed_incomplete_plaintext")
        self.assertIsNone(explanation["verification"]["literal_reencryption_matches"])
        with self.assertRaises(ValueError):
            replay_recipe("ATTACKATDAWN", explanation["encryption_recipe"])

    def test_unused_unknown_key_slots_remain_explicit(self):
        result = run_recovery({"ciphertext": "BC", "alphabet": "standard",
                               "cribs": [{"start": 1, "text": "AB"}], "min_period": 4, "max_period": 4})
        explanation = result["candidates"][0]["explanation"]
        self.assertEqual(explanation["classification"], "complete_plaintext_with_partial_key")
        self.assertFalse(explanation["recovered_values"]["key_complete"])
        self.assertEqual(explanation["encryption_recipe"]["stages"][0]["key_pattern"], "BB??")
        self.assertTrue(explanation["verification"]["literal_reencryption_matches"])

    def test_hand_substitution_recipes_for_all_conventions_and_custom_alphabet(self):
        for cipher, ciphertext in (("vigenere", "BDD"), ("beaufort", "BBZ"), ("variant", "ZZB")):
            with self.subTest(cipher=cipher):
                result = run_recovery({"ciphertext": ciphertext, "alphabet": "standard", "cipher": cipher,
                                       "cribs": [{"start": 1, "text": "ABC"}], "min_period": 2, "max_period": 2})
                explanation = result["candidates"][0]["explanation"]
                self.assertEqual(explanation["recovered_values"]["key_pattern"], "BC")
                self.assertEqual(explanation["verification"]["reencrypted_ciphertext"], ciphertext)
        reversed_alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        result = run_recovery({"ciphertext": "ABC", "alphabet": reversed_alphabet,
                               "cribs": [{"start": 1, "text": "ABC"}], "min_period": 1, "max_period": 1})
        self.assertEqual(result["candidates"][0]["explanation"]["encryption_recipe"]["alphabet"], reversed_alphabet)
        self.assertEqual(result["candidates"][0]["key_pattern"], "Z")

    def test_recovery_recipes_follow_deduplicated_routes(self):
        permutation = [0, 2, 3, 1, 5, 4]
        # ABCDEF + repeating BC -> BDDFFH, then gather -> BDFDHF.
        request = {"ciphertext": "BDFDHF", "alphabet": "standard", "min_period": 2, "max_period": 2,
                   "cribs": [{"start": 1, "text": "ABCDEF"}],
                   "routes": [{"name": "identity", "permutation": list(range(6))},
                              {"name": "identity-alias", "permutation": list(range(6))},
                              {"name": "proper", "permutation": permutation},
                              {"name": "proper-alias", "permutation": permutation}]}
        result = run_recovery(request)
        candidate = next(row for row in result["candidates"] if row["route_index"] == 1)
        self.assertEqual(candidate["explanation"]["encryption_recipe"]["stages"][1]["permutation"], permutation)
        self.assertEqual(candidate["explanation"]["verification"]["reencrypted_ciphertext"], "BDFDHF")

    def test_recovery_route_before_substitution_has_correct_phase_origin(self):
        result = run_recovery({"ciphertext": "BEEDGG", "alphabet": "standard", "min_period": 2, "max_period": 2,
            "cribs": [{"start": 1, "text": "ABCDEF"}],
            "routes": [{"name": "gather-first", "order": "TS", "permutation": [0, 2, 3, 1, 5, 4]}]})
        explanation = result["candidates"][0]["explanation"]
        self.assertEqual(explanation["recovered_values"]["key_pattern"], "BC")
        self.assertEqual([step["output"] for step in explanation["verification"]["stage_outputs"]], ["ACDBFE", "BEEDGG"])

    def test_layer_recipe_preserves_literal_intermediate_stages(self):
        result = run_layers({"ciphertext": "DKSHQQ", "alphabet": "standard", "order": "STS",
                             "permutation": [0, 2, 3, 1, 5, 4], "period_a": 2, "period_b": 3,
                             "cribs": [{"start": 1, "text": "ABCD"}]})
        candidate = result["candidates"][0]
        self.assertEqual(candidate["plaintext"], "ABCDEF")
        explanation = candidate["explanation"]
        self.assertEqual([stage["output"] for stage in explanation["verification"]["stage_outputs"]],
                         ["AECGEI", "ACGEIE", "DKSHQQ"])
        self.assertEqual(result["explanation"]["search"]["evaluated"], 1)
        self.assertIn("gauge", explanation["chosen_values"]["key_note"])

    def test_layer_recipes_cover_each_gather_position(self):
        for order, ciphertext in (("SST", "DOJMUM"), ("STS", "DKSHQQ"), ("TSS", "DNPHNT")):
            with self.subTest(order=order):
                result = run_layers({"ciphertext": ciphertext, "alphabet": "standard", "order": order,
                    "permutation": [0, 2, 3, 1, 5, 4], "period_a": 2, "period_b": 3,
                    "cribs": [{"start": 1, "text": "ABCDEF"}]})
                candidate = result["candidates"][0]
                self.assertEqual(candidate["plaintext"], "ABCDEF")
                explanation = candidate["explanation"]
                self.assertEqual(explanation["verification"]["reencrypted_ciphertext"], ciphertext)
                self.assertEqual([stage["operation"] for stage in explanation["encryption_recipe"]["stages"]],
                                 ["gather" if s == "T" else "repeat_substitution" for s in order])

    def test_grid_recipes_for_all_frames_and_unequal_offsets(self):
        vectors = {("source", "source"): "TPA", ("source", "destination"): "NPG",
                   ("destination", "source"): "YPV", ("destination", "destination"): "SPB"}
        for (row_frame, column_frame), ciphertext in vectors.items():
            with self.subTest(row=row_frame, column=column_frame):
                result = run_grid({"ciphertext": ciphertext, "alphabet": "standard",
                    "cells": [[0, 1], [1, 0], [1, 1]], "permutation": [2, 0, 1],
                    "cribs": [{"start": 1, "text": "DOG"}], "row_frame": row_frame,
                    "column_frame": column_frame, "row_shift": 1, "column_shift": -1})
                explanation = result["explanation"]
                self.assertEqual(explanation["classification"], "consistency_witness")
                replay = replay_recipe("DOG", json.loads(json.dumps(explanation["encryption_recipe"])))
                self.assertEqual(replay["ciphertext"], ciphertext)

    def test_grid_freedom_and_residue_results_are_not_solutions(self):
        result = run_grid({"ciphertext": "DOJJUP", "alphabet": "standard",
            "cells": [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]], "permutation": [0, 2, 3, 1, 5, 4],
            "cribs": [{"start": 1, "text": "AB"}, {"start": 4, "text": "D"}]})
        explanation = result["explanation"]
        self.assertEqual(explanation["recovered_values"]["forced_plaintext_mask"], "AB?DE?")
        self.assertEqual(explanation["recovered_values"]["distinct_plaintext_count"], 26)
        self.assertIn("arbitrary", explanation["chosen_values"]["component_roots"])
        residues = run_residues({})["explanation"]
        self.assertEqual(residues["classification"], "constraint_only")
        self.assertIsNone(residues["encryption_recipe"])
        self.assertIsNone(residues["verification"]["literal_reencryption_matches"])

    def test_rejected_and_budget_limited_results_explain_what_was_checked(self):
        grid = run_grid({})["explanation"]
        self.assertEqual(grid["classification"], "infeasible_model")
        self.assertNotIn("encryption_recipe", grid)
        rejected = run_layers({"ciphertext": "EKSHQQ", "alphabet": "standard", "order": "STS",
            "permutation": [0, 2, 3, 1, 5, 4], "period_a": 2, "period_b": 3,
            "cribs": [{"start": 1, "text": "ABCDEF"}]})
        self.assertFalse(rejected["feasible"])
        self.assertEqual(rejected["explanation"]["search"]["evaluated"], 0)
        limited = run_recovery({"ciphertext": "LXFOPVEFRNHR", "alphabet": "standard",
                               "cribs": [{"start": 1, "text": "ATTACK"}], "max_period": 5, "max_models": 1})
        self.assertFalse(limited["explanation"]["search"]["complete"])
        self.assertEqual(limited["explanation"]["search"]["stop_reason"], "max_models")


if __name__ == "__main__":
    unittest.main()
