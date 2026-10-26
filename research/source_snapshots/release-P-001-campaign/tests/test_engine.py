import unittest

from kryptos.ciphers import (
    KRYPTOS_ALPHABET, crib_match_count, decrypt, derive_crib_constraints, encrypt,
)
from kryptos.engine import (
    DEFAULT_K4_CRIBS, K4_CIPHERTEXT, _route, inspect_periods, run_batch,
    total_batches, validate_config, work_units,
)
from kryptos.scoring import english_score


class CipherTests(unittest.TestCase):
    def test_independent_vigenere_vector(self):
        self.assertEqual(encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
        self.assertEqual(decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")

    def test_independent_beaufort_vectors(self):
        # A=0; B=1; Z=25. These values explicitly exercise modular wrap.
        self.assertEqual(encrypt("ABZ", "B", "beaufort"), "BAC")
        self.assertEqual(decrypt("BAC", "B", "beaufort"), "ABZ")
        self.assertEqual(encrypt("ABZ", "B", "variant"), "ZAY")
        self.assertEqual(decrypt("ZAY", "B", "variant"), "ABZ")

    def test_keyed_alphabet_vector(self):
        self.assertEqual(len(set(KRYPTOS_ALPHABET)), 26)
        # K=0, R=1, Y=2, Z=25 in the keyed alphabet.
        self.assertEqual(encrypt("KRZ", "R", alphabet="kryptos"), "RYK")
        self.assertEqual(decrypt("RYK", "R", alphabet="kryptos"), "KRZ")

    def test_all_conventions_roundtrip_and_crib_derivation(self):
        plain, key = "THISISATESTOFCRIBPOSITIONS", "ORBIT"
        for alphabet in ("standard", "kryptos"):
            letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if alphabet == "standard" else KRYPTOS_ALPHABET
            for cipher in ("vigenere", "beaufort", "variant"):
                with self.subTest(alphabet=alphabet, cipher=cipher):
                    encrypted = encrypt(plain, key, cipher, alphabet)
                    self.assertEqual(decrypt(encrypted, key, cipher, alphabet), plain)
                    fixed, conflict = derive_crib_constraints(encrypted, 5, [{"start": 2, "text": plain[1:7]}], cipher, alphabet)
                    self.assertIsNone(conflict)
                    self.assertEqual(fixed, {index: letters.index(letter) for index, letter in enumerate(key)})

    def test_crib_conflict_and_one_based_positions(self):
        fixed, conflict = derive_crib_constraints("LXFOPV", 5, [{"start": 1, "text": "ATTACK"}])
        self.assertIsNone(conflict)
        self.assertEqual(fixed[0], 11)
        _, conflict = derive_crib_constraints("LXFOPV", 1, [{"start": 1, "text": "ATTACK"}])
        self.assertIsNotNone(conflict)
        self.assertEqual(crib_match_count("ATTACK", [{"start": 1, "text": "ATT"}, {"start": 2, "text": "TTA"}]), (4, 4))

    def test_official_crib_index_invariants(self):
        self.assertEqual(len(K4_CIPHERTEXT), 97)
        self.assertEqual(K4_CIPHERTEXT[21:25], "FLRV")
        self.assertEqual(K4_CIPHERTEXT[25:34], "QQPRNGKSS")
        self.assertEqual(K4_CIPHERTEXT[63:69], "NYPVTT")
        self.assertEqual(K4_CIPHERTEXT[69:74], "MZFPK")
        self.assertEqual(sum(len(crib["text"]) for crib in DEFAULT_K4_CRIBS), 24)


class EngineTests(unittest.TestCase):
    def custom(self, **updates):
        config = {"target": "custom", "ciphertext": "LXFOPVEFRNHR", "cribs": [], "keys": ["WRONG", "LEMON", "THIRD"], "batch_size": 2}
        config.update(updates)
        return config

    def test_dictionary_batch_boundaries(self):
        config = self.custom(cribs=[{"start": 1, "text": "ATTACK"}])
        self.assertEqual(work_units(config), 3)
        self.assertEqual(total_batches(config), 2)
        first = run_batch(config, 0)
        self.assertEqual(first["evaluated"], 2)
        self.assertEqual(first["completed_units"], 2)
        self.assertFalse(first["done"])
        self.assertEqual(first["candidates"][0]["plaintext"], "ATTACKATDAWN")
        self.assertEqual(first["candidates"][0]["key"], "LEMON")
        self.assertTrue(run_batch(config, 1)["done"])
        self.assertEqual(run_batch(config, 99)["evaluated"], 0)

    def test_finite_annealing_hard_constraints_and_reproducibility(self):
        config = self.custom(method="anneal", min_period=5, max_period=5, iterations=15,
                             restarts=3, cribs=[{"start": 1, "text": "ATT"}], seed=41)
        first = run_batch(config, 0)
        self.assertEqual(first, run_batch(config, 0))
        self.assertEqual(first["evaluated"], 32)
        self.assertFalse(first["done"])
        self.assertTrue(all(candidate["plaintext"].startswith("ATT") for candidate in first["candidates"]))
        self.assertEqual(run_batch(config, 1)["completed_units"], 1)
        self.assertTrue(run_batch(config, 1)["done"])

    def test_inconsistent_periods_are_skipped(self):
        result = run_batch(self.custom(method="anneal", min_period=1, max_period=1,
                                      restarts=2, cribs=[{"start": 1, "text": "ATTACK"}]), 0)
        self.assertEqual(result["skipped"], 2)
        self.assertEqual(result["evaluated"], 0)
        self.assertEqual(result["candidates"], [])
        self.assertTrue(result["skip_reasons"])

    def test_period_inspection_explains_conflicts(self):
        rows = inspect_periods(self.custom(min_period=1, max_period=5, cribs=[{"start": 1, "text": "ATTACK"}]))
        self.assertFalse(rows[0]["feasible"])
        self.assertIn("period 1", rows[0]["reason"])
        self.assertTrue(rows[4]["feasible"])
        self.assertEqual(rows[4]["key_pattern"], "LEMON")

    def test_fully_fixed_key_needs_one_evaluation(self):
        result = run_batch(self.custom(method="anneal", min_period=5, max_period=5,
                                      restarts=1, cribs=[{"start": 1, "text": "ATTACK"}]), 0)
        self.assertEqual(result["evaluated"], 1)
        self.assertEqual(result["candidates"][0]["key"], "LEMON")
        self.assertEqual(result["candidates"][0]["plaintext"], "ATTACKATDAWN")

    def test_routes_are_bijective_for_ragged_rectangle(self):
        original = "ABCDEFGHIJK"
        self.assertEqual(_route(original, "columns", 4), "AEIBFJCGKDH")
        for width in range(2, 8):
            for forward, backward in (("columns", "inverse_columns"), ("snake_columns", "inverse_snake_columns")):
                encrypted = _route(original, forward, width)
                self.assertEqual(sorted(encrypted), sorted(original))
                self.assertEqual(_route(encrypted, backward, width), original)
        self.assertEqual(_route(_route(original, "snake_rows", 4), "snake_rows", 4), original)

    def test_route_batches_are_finite(self):
        config = self.custom(method="routes", batch_size=4096)
        result = run_batch(config, 0)
        self.assertTrue(result["done"])
        self.assertEqual(result["completed_units"], result["total_units"])
        self.assertEqual(result["evaluated"], result["total_units"])
        self.assertTrue(all(sorted(item["plaintext"]) == sorted(config["ciphertext"]) for item in result["candidates"]))

    def test_validation_rejects_bad_inputs(self):
        bad = [
            {"target": "k5"}, {"target": "custom"}, {"ciphertext": "ABC!"},
            {"iterations": -1}, {"batch_size": True}, {"max_period": 0},
            {"cribs": [{"start": 0, "text": "A"}]},
            {"cribs": [{"start": 97, "text": "AA"}]},
            {"cribs": [{"start": 1, "text": "A"}, {"start": 1, "text": "B"}]},
            {"require_cribs": "true"},
        ]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(ValueError):
                validate_config(config)

    def test_default_cribs_only_apply_to_canonical_k4(self):
        self.assertEqual(validate_config({})["cribs"], DEFAULT_K4_CRIBS)
        self.assertEqual(validate_config({"ciphertext": "ABC"})["cribs"], [])
        self.assertEqual(validate_config({"target": "k5", "ciphertext": "ABC"})["cribs"], [])

    def test_language_score_excludes_crib_positions(self):
        unconstrained = run_batch(self.custom(keys=["LEMON"]), 0)["candidates"][0]
        constrained = run_batch(self.custom(keys=["LEMON"], cribs=[{"start": 1, "text": "ATTACK"}]), 0)["candidates"][0]
        self.assertEqual(unconstrained["language_scored_characters"], 12)
        self.assertEqual(constrained["language_scored_characters"], 6)
        self.assertEqual(constrained["score"], english_score("ATDAWN"))
        self.assertGreater(english_score("THECLOCKISINBERLIN"), english_score("QZXJKVZQJKXQZXVJK"))


if __name__ == "__main__":
    unittest.main()
