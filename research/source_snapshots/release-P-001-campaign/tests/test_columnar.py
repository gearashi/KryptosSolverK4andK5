import itertools
import math
import unittest
from unittest.mock import patch

from kryptos.columnar import recover_column_order


def brute(ciphertext, cells, known, reverse=False):
    """Independent tiny oracle: enumerate labelled orders and decrypt literally."""
    labels = sorted({cell[1] for cell in cells})
    answers = []
    for order in itertools.permutations(labels):
        pairs = [(label, row, i) for i, (row, label) in enumerate(cells)]
        gather = [i for label in order
                  for _, _, i in sorted((p for p in pairs if p[0] == label),
                                        key=lambda p: p[1], reverse=reverse)]
        plaintext = [None] * len(ciphertext)
        for j, i in enumerate(gather):
            plaintext[i] = ciphertext[j]
        plaintext = "".join(plaintext)
        if all(plaintext[i] == c for i, c in known.items()):
            answers.append((order, plaintext))
    return answers


class ColumnarTests(unittest.TestCase):
    def assert_oracle(self, ciphertext, cells, known, reverse=False, saved=1000):
        result = recover_column_order(ciphertext, [{"start": i + 1, "text": c} for i, c in known.items()],
                                      cells=cells, max_candidates=saved,
                                      column_direction="bottom_to_top" if reverse else "top_to_bottom")
        expected = brute(ciphertext, cells, known, reverse)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], len(expected))
        self.assertEqual(result["column_order_lower_bound"], len(expected))
        self.assertEqual(result["feasible"], bool(expected))
        if len(expected) <= saved:
            self.assertEqual({(tuple(row["column_order"]), row["plaintext"]) for row in result["candidates"]}, set(expected))
            self.assertEqual(result["total_distinct_plaintexts"], len({p for _, p in expected}))
        if expected:
            domains = ["".join(sorted({p[i] for _, p in expected})) for i in range(len(ciphertext))]
            self.assertEqual(result["plaintext_domains"], domains)
            self.assertEqual(result["forced_plaintext_mask"], "".join(d if len(d) == 1 else "?" for d in domains))
            self.assertEqual(result["column_domains"], [sorted({o[j] for o, _ in expected}) for j in range(len(expected[0][0]))])
        for candidate in result["candidates"]:
            self.assertEqual("".join(candidate["plaintext"][i] for i in candidate["permutation"]), ciphertext)
            self.assertTrue(candidate["reencryption_matches"])
            self.assertFalse(candidate["authenticated"])
            self.assertEqual(candidate["recipe"]["stages"][0]["operation"], "gather")
        return result

    def test_noninvolutive_ragged_hand_vector(self):
        result = recover_column_order("CGAEIDHBFJ", [{"start": 1, "text": "ABCD"}], width=4)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["column_order"], [2, 0, 3, 1])
        self.assertEqual(candidate["permutation"], [2, 6, 0, 4, 8, 3, 7, 1, 5, 9])
        self.assertEqual(candidate["plaintext"], "ABCDEFGHIJ")
        self.assertEqual(result["distinct_length_segmentations"], 6)

    def test_independent_small_exhaustive_oracle(self):
        # 3 to 6 occupied columns; nonuniform, repeated and fully distinct letters.
        for n, width, ciphertext in ((6, 3, "BECFAD"), (10, 4, "CGAEIDHBFJ"),
                                     (11, 5, "ABACABACAAB"), (8, 6, "HGFEDCBA")):
            cells = [(i // width, i % width) for i in range(n)]
            for known in ({}, {0: ciphertext[-1]}, {0: "A", n - 1: "B"}):
                with self.subTest(n=n, width=width, known=known):
                    self.assert_oracle(ciphertext, cells, known)

    def test_explicit_occupancy_and_reversed_columns(self):
        cells = [(3, -2), (1, 8), (3, 8), (1, -2), (2, 4)]
        for ciphertext, reverse in (("BCDAE", False), ("CBADE", True)):
            result = self.assert_oracle(ciphertext, cells, dict(enumerate("ABCDE")), reverse)
            self.assertEqual(result["candidates"][0]["column_order"], [8, -2, 4])

    def test_supported_edge_propagation_forces_remaining_column(self):
        # Initial domains: slot0={0,1}, slot1={0,2}, slot2={0}.
        result = recover_column_order("ACDBEF", [{"start": 2, "text": "A"}, {"start": 6, "text": "B"}], width=3)
        self.assertEqual(result["total_column_orders"], 1)
        self.assertEqual(result["work"]["supported_edges_removed"], 2)
        self.assertEqual(result["forced_plaintext_mask"], "EADFCB")

    def test_storage_cap_is_not_count_cap(self):
        result = recover_column_order("BECFAD", [], width=3, max_candidates=1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], 6)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertFalse(result["candidates_complete"])
        self.assertIsNone(result["total_distinct_plaintexts"])
        self.assertFalse(result["unique_plaintext_within_family"])

    def test_factorial_shortcut_and_plaintext_order_distinction(self):
        result = recover_column_order("A" * 40, [], width=20, max_candidates=2)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], math.factorial(20))
        self.assertEqual(result["total_distinct_plaintexts"], 1)
        self.assertTrue(result["unique_plaintext_within_family"])
        self.assertEqual(result["forced_plaintext_mask"], "A" * 40)
        self.assertEqual(result["work"]["factorial_components"], 1)
        self.assertLess(result["work"]["count_states"], 50)

    def test_count_only_and_no_mutation(self):
        cribs = [{"start": 1, "text": "a b"}]
        cells = [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]]
        result = recover_column_order("be cf ad", cribs, cells=cells, max_candidates=0)
        self.assertEqual(result["total_column_orders"], 1)
        self.assertEqual(result["forced_plaintext_mask"], "ABCDEF")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(cribs, [{"start": 1, "text": "a b"}])
        self.assertEqual(cells[0], [0, 0])

    def test_ragged_segmentation_limit_withholds_global_forcing(self):
        result = recover_column_order("ABCDE", [], width=3, max_segmentations=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "max_segmentations")
        self.assertEqual(result["column_order_lower_bound"], 2)
        self.assertIsNone(result["total_column_orders"])
        self.assertIsNone(result["forced_plaintext_mask"])
        self.assertIsNone(result["column_domains"])
        self.assertTrue(result["feasible"])

    def test_state_truncation_before_and_after_a_witness(self):
        result = recover_column_order("ABCDEFGH", [], width=4, max_states=1)
        self.assertIsNone(result["feasible"])
        self.assertEqual(result["column_order_lower_bound"], 0)
        self.assertEqual(result["work"]["states"], 1)
        result = recover_column_order("ABCDEFGH", [], width=4, max_states=50, max_candidates=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "max_states")
        self.assertTrue(result["feasible"])
        self.assertEqual(result["column_order_lower_bound"], 1)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertIsNone(result["forced_columns"])

    def test_timeout_is_inconclusive(self):
        with patch("kryptos.columnar.time.monotonic", side_effect=[0, 2]):
            result = recover_column_order("ABC", [], width=3, time_limit_seconds=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "time_limit_seconds")
        self.assertIsNone(result["feasible"])

    def test_inventory_rejection_needs_no_search(self):
        result = recover_column_order("ABCDEF", [{"start": 1, "text": "AA"}], width=3, max_states=1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total_column_orders"], 0)
        self.assertEqual(result["work"]["states"], 0)
        self.assertEqual(result["inventory_rejection"], [{"letter": "A", "required_by_cribs": 2, "available_in_ciphertext": 1}])

    def test_wrong_geometry_is_not_silently_widened(self):
        result = recover_column_order("CGAEIDHBFJ", [{"start": 1, "text": "ABCDEFGHIJ"}], width=5)
        self.assertTrue(result["complete"])
        self.assertFalse(result["feasible"])
        self.assertEqual(result["total_column_orders"], 0)

    def test_input_validation(self):
        for kwargs in ({}, {"width": True}, {"width": 0}, {"width": 4},
                       {"width": 3, "cells": [(0, 0)] * 3},
                       {"cells": [(0, 0)] * 3}, {"cells": [(0, 0)]},
                       {"width": 3, "max_states": False}, {"width": 3, "max_candidates": -1},
                       {"width": 3, "time_limit_seconds": float("nan")},
                       {"width": 3, "column_direction": "random"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                recover_column_order("ABC", [], **kwargs)
        for ciphertext, cribs in (("AßC", []), ("ABC", [{"start": 0, "text": "A"}]),
                                  ("ABC", [{"start": 3, "text": "AB"}]),
                                  ("ABC", [{"start": 1, "text": "A"}, {"start": 1, "text": "B"}])):
            with self.assertRaises(ValueError):
                recover_column_order(ciphertext, cribs, width=3)


if __name__ == "__main__":
    unittest.main()
