"""Independent literal-stage and small exhaustive controls for compiled plans."""
import unittest
from kryptos.layer_plan import compile_layer_plan
from research.layer_constraints import apply_layers, check_layers

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class LayerPlanTests(unittest.TestCase):
    def test_hand_vector_and_partial_enumeration(self):
        route = [0, 2, 3, 1, 5, 4]
        known = {0: "A", 1: "B", 3: "D"}
        plan = compile_layer_plan(6, known, "STS", route, 2, 3)
        result = plan.solve("DKSHQQ", known, A)["solution"]
        self.assertEqual(result.prediction_mask(), "AB?DE?")
        self.assertEqual(plan.plaintext_dimension, 1)
        self.assertEqual(result.distinct_plaintext_count, 26)
        strings = []
        for values, text in result.enumerate_plaintexts(26):
            strings.append(text)
            a, b = result.keys(values)
            self.assertEqual(apply_layers(text, a, b, A, "STS", route), "DKSHQQ")
        self.assertEqual(len(set(strings)), 26)
        self.assertIn("ABCDEF", strings)
        with self.assertRaises(ValueError):
            result.enumerate_plaintexts(25)

    def test_all_three_orders_and_rejection(self):
        route = [2, 5, 0, 4, 1, 3]
        for order, cipher in {"SST": "IMEJHI", "STS": "GLGIHK", "TSS": "GLGJGK"}.items():
            known = dict(enumerate("ABCDEF"))
            plan = compile_layer_plan(6, known, order, route, 2, 3)
            solution = plan.solve(cipher, known, A)["solution"]
            self.assertEqual(solution.distinct_plaintext_count, 1)
            self.assertEqual(solution.plaintext(()), "ABCDEF")
            known[5] = "G"
            self.assertFalse(plan.solve(cipher, known, A)["feasible"])

    def test_disconnected_key_graph_can_force_plaintext(self):
        known = dict(enumerate("ABCD"))
        plan = compile_layer_plan(4, known, "SST", range(4), 2, 2)
        self.assertEqual(plan.component_count, 2)
        self.assertEqual(plan.full_component_count, 2)
        self.assertEqual(plan.plaintext_dimension, 0)
        self.assertEqual(plan.solve("DFFH", known, A)["solution"].plaintext(()), "ABCD")

    def test_empty_cribs_match_exhaustive_keys(self):
        plan = compile_layer_plan(3, [], "SST", range(3), 1, 1)
        solution = plan.solve("ABC", {}, A)["solution"]
        expected = set()
        for a in range(26):
            for b in range(26):
                expected.add("".join(A[(i - a - b) % 26] for i in range(3)))
        self.assertEqual({text for _, text in solution.enumerate_plaintexts(26)}, expected)

    def test_agrees_with_independent_solver(self):
        route = [0, 2, 3, 1, 5, 4]
        known = {0: "A", 2: "C", 3: "D", 5: "F"}
        for order in ("SST", "STS", "TSS"):
            for a in range(1, 5):
                for b in range(1, 5):
                    plan = compile_layer_plan(6, known, order, route, a, b)
                    old = check_layers("DKSHQQ", known, A, order, route, a, b)
                    new = plan.solve("DKSHQQ", known, A)
                    self.assertEqual(old["feasible"], new["feasible"])
                    if new["feasible"]:
                        self.assertEqual(old["free_components"], plan.component_count)

    def test_invalid_bounds_and_positions(self):
        with self.assertRaises(ValueError):
            compile_layer_plan(6, [0, 0], "STS", range(6), 2, 3)
        with self.assertRaises(ValueError):
            compile_layer_plan(6, [0], "STS", range(6), True, 3)
        plan = compile_layer_plan(2, [1], "SST", range(2), 1, 1)
        for known in ({True: "A"}, {1.0: "A"}, {1: 2}, [], None):
            with self.assertRaises(ValueError):
                plan.solve("BC", known, A)

    def test_unused_key_slots_do_not_add_plaintexts(self):
        plan = compile_layer_plan(1, [0], "SST", [0], 4, 5)
        self.assertEqual(plan.component_count, 8)
        self.assertEqual(plan.full_component_count, 8)
        self.assertEqual(plan.solve("D", {0: "A"}, A)["solution"].distinct_plaintext_count, 1)


if __name__ == "__main__":
    unittest.main()
