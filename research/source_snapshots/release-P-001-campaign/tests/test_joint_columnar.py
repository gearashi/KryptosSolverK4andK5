import itertools
import math
import string
import unittest
from unittest.mock import patch

from kryptos.explanations import replay_recipe
from kryptos.joint_columnar import recover_joint_columnar


A = string.ascii_uppercase


def brute(ciphertext, cells, known, period, order, cipher, alphabet=A, reverse=False):
    """Independent exhaustive labelled orders AND numeric keys; no pruning."""
    labels = sorted({col for _, col in cells})
    answers = []
    for columns in itertools.permutations(labels):
        gather = [i for col in columns
                  for i in sorted((i for i, (_, c) in enumerate(cells) if c == col),
                                  key=lambda i: cells[i][0], reverse=reverse)]
        for key in itertools.product(range(26), repeat=min(period, len(ciphertext))):
            text = [""] * len(ciphertext)
            for j, i in enumerate(gather):
                c, k = alphabet.index(ciphertext[j]), key[(i if order == "ST" else j) % period]
                value = c - k if cipher == "vigenere" else k - c if cipher == "beaufort" else c + k
                text[i] = alphabet[value % 26]
            if all(text[i] == c for i, c in known.items()):
                answers.append((columns, key, "".join(text)))
    return answers


class JointColumnarTests(unittest.TestCase):
    def assert_oracle(self, ciphertext, cells, known, period, order, cipher, alphabet=A, reverse=False):
        result = recover_joint_columnar(ciphertext, [{"start": i + 1, "text": c} for i, c in known.items()],
                                         period=period, order=order, cipher=cipher, alphabet=alphabet, cells=cells,
                                         column_direction="bottom_to_top" if reverse else "top_to_bottom")
        expected = brute(ciphertext, cells, known, period, order, cipher, alphabet, reverse)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_order_key_assignments"], len(expected))
        self.assertEqual(result["total_column_orders"], len({row[0] for row in expected}))
        self.assertEqual(result["feasible"], bool(expected))
        distinct = len({row[2] for row in expected})
        if result["distinct_plaintext_count"] is not None:
            self.assertEqual(result["distinct_plaintext_count"], distinct)
        self.assertLessEqual(result["distinct_plaintext_lower_bound"], distinct)
        if expected:
            domains = ["".join(sorted({p[i] for _, _, p in expected})) for i in range(len(ciphertext))]
            self.assertEqual(result["plaintext_domains"], domains)
            self.assertEqual(result["forced_plaintext_mask"], "".join(d if len(d) == 1 else "?" for d in domains))
            self.assertEqual(result["column_domains"], [sorted({o[j] for o, _, _ in expected}) for j in range(len(expected[0][0]))])
            self.assertEqual(result["key_domains"], [sorted({k[j] for _, k, _ in expected}) for j in range(period)])
            self.assertEqual(result["unique_plaintext_within_family"], distinct == 1)
        for candidate in result["candidates"]:
            family = [row for row in expected if list(row[0]) == candidate["column_order"]]
            self.assertEqual(candidate["used_key_assignment_count"], len(family))
            if candidate["recipe_complete_for_message"]:
                replay = replay_recipe(candidate["plaintext"], candidate["encryption_recipe"])
                self.assertEqual(replay["ciphertext"], ciphertext)
                self.assertEqual(replay["stages"], candidate["evidence"]["stage_outputs"])
            else:
                self.assertIsNone(candidate["plaintext"])
                self.assertIsNone(candidate["evidence"]["literal_reencryption_matches"])
                self.assertIn("?", candidate["key_pattern"])
        return result

    def test_independent_exhaustive_all_rules_and_layer_orders(self):
        cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]
        for order in ("ST", "TS"):
            for cipher in ("vigenere", "beaufort", "variant"):
                with self.subTest(order=order, cipher=cipher):
                    self.assert_oracle("DCGAF", cells, {0: "A", 1: "B", 4: "E"}, 2, order, cipher)

    def test_no_cribs_factor_matching_and_keys_without_enumerating_them(self):
        result = recover_joint_columnar("A" * 40, [], period=3, width=20, max_candidates=2)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], math.factorial(20))
        self.assertEqual(result["total_order_key_assignments"], math.factorial(20) * 26 ** 3)
        self.assertEqual(result["work"]["factorized_blocks"], 1)
        self.assertEqual(result["work"]["factorial_components"], 1)
        self.assertEqual(result["work"]["branches"], 0)
        self.assertEqual(result["forced_plaintext_mask"], "?" * 40)
        self.assertEqual(len(result["candidates"]), 2)
        self.assertIsNone(result["candidates"][0]["plaintext"])

    def test_exact_branching_preserves_correlated_order_key_choices(self):
        cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
        result = self.assert_oracle("AFCGEL", cells, {0: "A", 1: "B", 2: "C"}, 2, "ST", "vigenere")
        self.assertEqual(result["total_order_key_assignments"], 2)
        self.assertGreater(result["work"]["branches"], 0)

    def test_partial_family_matches_exhaustive_keys_and_orders(self):
        cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]
        self.assert_oracle("AAABC", cells, {0: "A"}, 2, "ST", "variant")

    def test_matching_alone_is_not_joint_key_consistency(self):
        result = recover_joint_columnar("AB", [{"start": 1, "text": "AA"}], period=1, width=2, alphabet="standard")
        self.assertTrue(result["complete"])
        self.assertFalse(result["feasible"])
        self.assertEqual(result["total_order_key_assignments"], 0)
        self.assertGreater(result["work"]["matching_edge_visits"], 0)
        self.assertGreater(result["work"]["phase_support_rejections"], 0)

    def test_noninvolutive_ragged_hand_vectors(self):
        expected = {("ST", "vigenere"): "DHBFJHLFJN", ("TS", "vigenere"): "DKBIJHIFGN",
                    ("ST", "beaufort"): "ZVBXTBXDZV", ("TS", "beaufort"): "ZYBATBUDWV",
                    ("ST", "variant"): "BFZDHZDXBF", ("TS", "variant"): "BCZAHZGXEF"}
        for (order, cipher), ciphertext in expected.items():
            with self.subTest(order=order, cipher=cipher):
                result = recover_joint_columnar(ciphertext, [{"start": 1, "text": "ABCDEFGHIJ"}],
                                                 period=2, width=4, order=order, cipher=cipher, alphabet="standard")
                self.assertTrue(result["complete"])
                witness = next(c for c in result["candidates"] if c["column_order"] == [2, 0, 3, 1])
                self.assertEqual(witness["key_pattern"], "BE")
                self.assertEqual(witness["plaintext"], "ABCDEFGHIJ")
                self.assertEqual(replay_recipe(witness["plaintext"], witness["encryption_recipe"])["ciphertext"], ciphertext)

    def test_sparse_unsorted_cells_different_alphabet_and_reversed_columns(self):
        cells = [(3, -2), (1, 8), (3, 8), (1, -2), (2, 4)]
        self.assert_oracle("ABBAC", cells, {0: "A", 3: "C"}, 1, "TS", "beaufort", "BACDEFGHIJKLMNOPQRSTUVWXYZ", True)

    def test_partial_keys_remain_unknown_and_exact_assignment_count_survives(self):
        result = recover_joint_columnar("ABCDEFGH", [{"start": 1, "text": "A"}],
                                         period=3, width=2, alphabet="standard")
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], 2)
        self.assertEqual(result["total_order_key_assignments"], 2 * 26 ** 2)
        for candidate in result["candidates"]:
            self.assertEqual(candidate["key_pattern"][1:], "??")
            self.assertIsNone(candidate["plaintext"])
            self.assertIsNone(candidate["canonical_key"])
            self.assertIsNone(candidate["finite_encryption_signature"])

    def test_complete_message_with_unused_key_slots_replays(self):
        result = recover_joint_columnar("BDFCEG", [{"start": 1, "text": "ABCDEF"}],
                                         period=8, width=2, alphabet="standard")
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_order_key_assignments"], 2)
        self.assertEqual(result["distinct_plaintext_count"], 1)
        for candidate in result["candidates"]:
            self.assertTrue(candidate["key_pattern"].endswith("??"))
            self.assertEqual(candidate["unused_key_slots"], [6, 7])
            self.assertTrue(candidate["recipe_complete_for_message"])
            self.assertIsNone(candidate["canonical_key"])
            self.assertIsNotNone(candidate["finite_encryption_signature"])
            self.assertEqual(replay_recipe(candidate["plaintext"], candidate["encryption_recipe"])["ciphertext"], "BDFCEG")

    def test_repeated_keys_have_safe_cross_period_signatures(self):
        found = []
        for period in (2, 4):
            result = recover_joint_columnar("DHBFJHLFJN", [{"start": 1, "text": "ABCDEFGHIJ"}],
                                             period=period, width=4, alphabet="standard")
            found.append(next(row for row in result["candidates"] if row["column_order"] == [2, 0, 3, 1]))
        self.assertEqual(found[0]["canonical_key"], "BE")
        self.assertEqual(found[1]["canonical_key"], "BE")
        self.assertEqual(found[1]["key_pattern"], "BEBE")
        self.assertEqual(found[0]["finite_encryption_signature"], found[1]["finite_encryption_signature"])

    def test_storage_limit_does_not_stop_counting(self):
        result = recover_joint_columnar("ABCDE", [], period=2, width=3, max_candidates=1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], 6)
        self.assertEqual(result["total_order_key_assignments"], 6 * 26 ** 2)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertFalse(result["all_column_orders_stored"])

    def test_bounds_withhold_global_forcing_and_protect_lower_counts(self):
        for cap in (1, 20, 70, 200):
            result = recover_joint_columnar("ABCDEFGH", [], period=2, width=3, max_states=cap)
            self.assertLessEqual(result["column_order_lower_bound"], 6)
            self.assertLessEqual(result["order_key_assignment_lower_bound"], 6 * 26 ** 2)
            self.assertLessEqual(result["work"]["states"], cap)
            if not result["complete"]:
                self.assertIsNone(result["total_order_key_assignments"])
                self.assertIsNone(result["key_domains"])
                self.assertIsNone(result["forced_plaintext_mask"])
                self.assertIsNone(result["column_domains"])
        result = recover_joint_columnar("ABCDE", [], period=2, width=3, max_segmentations=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "max_segmentations")
        self.assertEqual(result["column_order_lower_bound"], 2)
        with patch("kryptos.joint_columnar.time.monotonic", side_effect=[0, 2]):
            result = recover_joint_columnar("ABC", [], period=1, width=3, time_limit_seconds=1)
        self.assertIsNone(result["feasible"])
        self.assertEqual(result["stop_reason"], "time_limit_seconds")

    def test_count_only_and_validation(self):
        result = recover_joint_columnar("ABC", [], period=1, width=3, max_candidates=0)
        self.assertEqual(result["total_order_key_assignments"], 6 * 26)
        self.assertEqual(result["candidates"], [])
        for kwargs in ({"period": True}, {"period": 0}, {"period": 257},
                       {"period": 1, "order": "SS"}, {"period": 1, "cipher": "unknown"},
                       {"period": 1, "alphabet": "ABC"}, {"period": 1, "max_states": False},
                       {"period": 1, "time_limit_seconds": float("nan")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                recover_joint_columnar("ABC", [], width=3, **kwargs)


if __name__ == "__main__":
    unittest.main()
