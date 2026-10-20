import unittest

from kryptos.ciphers import encrypt
from kryptos.recovery import canonical_key, recover_periodic_keys, recover_transposition_routes


class RecoveryTests(unittest.TestCase):
    def test_independent_vigenere_vector_without_key_input(self):
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATTACK"}],
                                       alphabet="standard", periods=range(1, 6))
        self.assertTrue(result["complete"])
        self.assertEqual(result["work"]["models_tested"], 5)
        candidate = next(row for row in result["candidates"] if row["canonical_key"] == "LEMON")
        self.assertEqual(candidate["plaintext"], "ATTACKATDAWN")
        self.assertTrue(candidate["reencryption_matches"])

    def test_partial_key_retains_uncertainty(self):
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "A"}],
                                       alphabet="standard", periods=[5])
        candidate = result["candidates"][0]
        self.assertEqual(candidate["key_pattern"], "L????")
        self.assertEqual(candidate["free_key_positions"], 4)
        self.assertIsNone(candidate["canonical_key"])
        self.assertIsNone(candidate["canonical_period"])
        self.assertIsNone(candidate["plaintext"])
        self.assertEqual(candidate["plaintext_mask"], "A????K????W?")

    def test_complete_repeated_periods_canonicalize_without_losing_scope(self):
        plaintext = "THISISATESTOFREPEATINGKEYS"
        ciphertext = encrypt(plaintext, "DOG")
        result = recover_periodic_keys(ciphertext, [{"start": 1, "text": plaintext[:12]}],
                                       alphabet="standard", periods=[3, 6, 9])
        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["canonical_key"], "DOG")
        self.assertEqual(candidate["declared_periods"], [3, 6, 9])
        self.assertEqual(candidate["plaintext"], plaintext)
        self.assertEqual(result["work"]["equivalent_complete_key_models_merged"], 2)
        with self.assertRaises(ValueError):
            canonical_key("A?A?")

    def test_partial_repeated_pattern_does_not_collapse_the_key_family(self):
        result = recover_periodic_keys("BDBD", [{"start": 1, "text": "A"}, {"start": 3, "text": "A"}],
                                       alphabet="standard", periods=[4])
        candidate = result["candidates"][0]
        self.assertEqual(candidate["key_pattern"], "B?B?")
        self.assertEqual(candidate["free_key_positions"], 2)
        self.assertEqual(candidate["plaintext_mask"], "A?A?")
        self.assertIsNone(candidate["canonical_period"])

    def test_unused_key_slots_remain_unknown_even_with_full_plaintext(self):
        result = recover_periodic_keys("BC", [{"start": 1, "text": "AB"}],
                                       alphabet="standard", periods=[4])
        candidate = result["candidates"][0]
        self.assertEqual(candidate["key_pattern"], "BB??")
        self.assertFalse(candidate["key_complete"])
        self.assertEqual(candidate["plaintext"], "AB")
        self.assertTrue(candidate["reencryption_matches"])

    def test_route_positions_for_both_stage_orders_and_all_conventions(self):
        plaintext, key = "THISISASECRETMESSAGE", "ORBIT"
        permutation = list(range(2, len(plaintext))) + [0, 1]
        for order in ("ST", "TS"):
            for alphabet in ("standard", "kryptos"):
                for cipher in ("vigenere", "beaufort", "variant"):
                    with self.subTest(order=order, alphabet=alphabet, cipher=cipher):
                        if order == "ST":
                            intermediate = encrypt(plaintext, key, cipher, alphabet)
                            ciphertext = "".join(intermediate[i] for i in permutation)
                        else:
                            intermediate = "".join(plaintext[i] for i in permutation)
                            ciphertext = encrypt(intermediate, key, cipher, alphabet)
                        result = recover_periodic_keys(ciphertext, [{"start": 1, "text": plaintext[:10]}],
                                                       alphabet=alphabet, cipher=cipher, periods=[5],
                                                       routes=[{"name": "shift-two", "permutation": permutation, "order": order}])
                        candidate = result["candidates"][0]
                        self.assertEqual(candidate["canonical_key"], key)
                        self.assertEqual(candidate["plaintext"], plaintext)

    def test_model_limit_reports_incomplete_search(self):
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATTACK"}],
                                       alphabet="standard", periods=range(1, 6), max_models=2)
        self.assertEqual(result["status"], "truncated")
        self.assertFalse(result["complete"])
        self.assertEqual(result["work"]["models_tested"], 2)
        self.assertEqual(result["stop_reason"], "max_models")

    def test_check_budget_never_reports_half_checked_model(self):
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATTACK"}],
                                       alphabet="standard", periods=[5], max_crib_checks=5)
        self.assertFalse(result["complete"])
        self.assertEqual(result["work"]["models_tested"], 0)
        self.assertEqual(result["work"]["crib_checks"], 0)
        self.assertEqual(result["candidates"], [])

    def test_duplicate_routes_are_merged_and_inputs_preserved(self):
        routes = [{"name": "one", "permutation": list(range(12))},
                  {"name": "two", "permutation": list(range(12))}]
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATTACK"}],
                                       alphabet="standard", periods=[5], routes=routes)
        self.assertEqual(result["work"]["models_tested"], 1)
        self.assertEqual(result["candidates"][0]["route_aliases"], ["one", "two"])
        self.assertNotIn("order", routes[0])

    def test_transposition_hidden_route_and_aliases(self):
        routes = [{"name": "identity", "permutation": list(range(6))},
                  {"name": "right", "permutation": [0, 2, 3, 1, 5, 4]},
                  {"name": "same-route", "permutation": [0, 2, 3, 1, 5, 4]}]
        result = recover_transposition_routes("ACDBFE", [{"start": 1, "text": "ABC"}], routes)
        self.assertEqual(result["work"]["models_tested"], 2)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["plaintext"], "ABCDEF")
        self.assertEqual(result["candidates"][0]["route_aliases"], ["right", "same-route"])

    def test_overlapping_cribs_count_unique_positions(self):
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATT"}, {"start": 2, "text": "TTA"}],
                                       alphabet="standard", periods=[5])
        self.assertEqual(result["unique_crib_positions"], 4)
        self.assertEqual(result["work"]["crib_checks"], 4)

    def test_validation_and_conflict_certificate(self):
        for arguments in ({"cribs": [{"start": 0, "text": "A"}]},
                          {"cribs": [{"start": 1, "text": "A"}, {"start": 1, "text": "B"}]},
                          {"periods": [True]}, {"max_models": -1},
                          {"routes": [{"permutation": [0] * 12}]}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                base = {"ciphertext": "LXFOPVEFRNHR", "cribs": [], "periods": [5]}
                base.update(arguments)
                recover_periodic_keys(**base)
        result = recover_periodic_keys("LXFOPVEFRNHR", [{"start": 1, "text": "ATTACK"}],
                                       alphabet="standard", periods=[1])
        witness = result["rejections"][0]["witness"]
        self.assertEqual(witness["plaintext_positions"], [1, 2])
        self.assertEqual(witness["required_key_symbols"], ["L", "E"])


if __name__ == "__main__":
    unittest.main()
