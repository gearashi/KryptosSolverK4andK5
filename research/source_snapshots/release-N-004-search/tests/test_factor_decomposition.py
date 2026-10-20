"""Independent exhaustive oracle for exact residual elimination and fallback."""
import itertools
import math
from pathlib import Path
import random
import unittest
from unittest.mock import patch
import uuid

from kryptos.factor_decomposition import exact_decomposition
from kryptos.search_runtime import SCHEMA, optimize_lazy


def score(problem, point):
    total = 1
    for f in problem["factors"]:
        number = 0
        for v in f["scope"]:
            number = number * problem["domains"][v] + point[v]
        total *= f["values"][number] ** f.get("power", 1)
    return total


def oracle(problem, partial):
    points = itertools.product(*(range(d) if v < 0 else (v,) for d, v in zip(problem["domains"], partial)))
    return min(((score(problem, p), p) for p in points), key=lambda row: (-row[0], row[1]))


class DecompositionTests(unittest.TestCase):
    def test_random_residuals_match_exhaustive_original_coordinate_ties(self):
        rng = random.Random(483)
        for _ in range(60):
            domains = [2, 3, 2, 2, 2]
            factors = []
            for number in range(5):
                scope = sorted(rng.sample(range(5), rng.randrange(4)))
                factors.append({"kind": "table", "scope": scope,
                    "values": [rng.randrange(4) for _ in range(math.prod(domains[i] for i in scope))],
                    "power": number % 3 + 1})
            p = {"schema": SCHEMA, "domains": domains, "factors": factors}
            partial = [rng.randrange(d) if rng.random() < .3 else -1 for d in domains]
            expected = oracle(p, partial)
            actual = exact_decomposition(p, partial)
            self.assertTrue(actual["complete"])
            self.assertEqual((actual["score"], tuple(actual["assignment"])), expected)

    def test_zero_annihilation_and_isolated_variables(self):
        p = {"schema": SCHEMA, "domains": [2, 2, 3], "factors": [
            {"kind": "table", "scope": [0], "values": [1, 8]},
            {"kind": "table", "scope": [1], "values": [0, 0]}]}
        result = exact_decomposition(p, [-1, -1, 2])
        self.assertEqual(result["assignment"], [0, 0, 2])
        self.assertEqual(result["score"], 0)
        p["factors"][1] = {"kind": "table", "scope": [], "values": [0]}
        result = exact_decomposition(p, max_entries=1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["stop_reason"], "constant_zero")
        self.assertEqual(exact_decomposition({"schema": SCHEMA, "domains": [2, 3], "factors": []})["assignment"], [0, 0])

    def test_chain_and_disconnected_components_exact_without_global_frontier(self):
        p = {"schema": SCHEMA, "domains": [2] * 14, "factors": [
            {"kind": "table", "scope": [i, i+1], "values": [1, 2, 2, 5]}
            for i in range(12) if i != 5]}
        actual = exact_decomposition(p)
        self.assertEqual(actual["assignment"], [1] * 13 + [0])
        self.assertEqual(actual["work"]["components"], 2)
        self.assertLessEqual(actual["work"]["max_separator_variables"], 1)
        self.assertLess(actual["work"]["factor_evaluations"], 2**14)
        optimized = optimize_lazy(p, decomposition="auto", max_nodes=1)
        self.assertTrue(optimized["complete"])
        self.assertTrue(optimized["tie_break_proven"])
        self.assertEqual(optimized["decomposition"]["solved_residuals"], 1)
        self.assertEqual(optimized["assignment"], actual["assignment"])

    def test_entry_and_operation_caps_are_inconclusive_safe_fallbacks(self):
        p = {"schema": SCHEMA, "domains": [2, 2, 2], "factors": [
            {"kind": "table", "scope": [0, 1, 2], "values": [1, 4, 2, 2, 3, 9, 3, 1]}]}
        for options in ({"max_entries": 1}, {"max_operations": 1}):
            result = exact_decomposition(p, **options)
            self.assertFalse(result["complete"])
            self.assertIsNone(result["assignment"])
            self.assertIsNone(result["score"])
        result = optimize_lazy(p, decomposition="auto", decomposition_max_entries=1,
                               decomposition_max_operations=1000)
        expected = oracle(p, [-1] * 3)
        self.assertTrue(result["complete"])
        self.assertEqual((result["score"], tuple(result["assignment"])), expected)
        self.assertGreater(result["decomposition"]["fallbacks"].get("entry_limit", 0), 0)

    def test_ngram_powers_equal_independent_literal_arithmetic(self):
        alphabet = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
        p = {"schema": SCHEMA, "domains": [2, 13], "model": {
            "alphabet": alphabet, "order": 2, "counts": {"AB": 9, "DC": 4}, "p": 1, "q": 2, "id": "hand"},
             "factors": [{"kind": "ngram", "scope": [0, 1], "base": [0, 1], "columns": [[13, 0], [2, 4]], "power": 3}]}
        expected = []
        for a, b in itertools.product(range(2), range(13)):
            word = alphabet[(13*a+2*b) % 26] + alphabet[(1+4*b) % 26]
            expected.append(((p["model"]["counts"].get(word, 0)*2+1)**3, (a, b)))
        result = exact_decomposition(p)
        self.assertEqual((result["score"], tuple(result["assignment"])), min(expected, key=lambda v: (-v[0], v[1])))

    def test_checkpoint_resume_and_decomposition_identity(self):
        folder = Path("research") / ("test-decomposition-" + uuid.uuid4().hex)
        folder.mkdir()
        p = {"schema": SCHEMA, "domains": [2, 2], "factors": [
            {"kind": "table", "scope": [0, 1], "values": [1, 2, 3, 9]}]}
        try:
            first = optimize_lazy(p, max_nodes=0, decomposition="auto", checkpoint_path=folder/"a.json")
            self.assertFalse(first["complete"])
            final = optimize_lazy(p, max_nodes=1, decomposition="auto", resume_path=folder/"a.json", checkpoint_path=folder/"b.json")
            self.assertTrue(final["complete"])
            self.assertEqual(final["nodes_total"], 1)
            again = optimize_lazy(p, decomposition="auto", resume_path=folder/"b.json")
            self.assertEqual(again["nodes"], 0)
            self.assertEqual(again["assignment"], [1, 1])
            with self.assertRaises(ValueError):
                optimize_lazy(p, decomposition="off", resume_path=folder/"a.json")
        finally:
            for file in folder.iterdir():
                file.unlink()
            folder.rmdir()

    def test_decomposition_timeout_restores_whole_parent(self):
        p = {"schema": SCHEMA, "domains": [2, 2], "factors": [
            {"kind": "table", "scope": [0, 1], "values": [1, 2, 3, 9]}]}
        clock = [0.0]
        def cut_short(*args, **kwargs):
            clock[0] = 2.0
            return {"complete": False, "stop_reason": "time_limit", "work": {
                "operations": 1, "factor_evaluations": 0, "max_separator_variables": 0,
                "components": 1, "planned_entries": 0}}
        with patch("kryptos.search_runtime.time.monotonic", side_effect=lambda: clock[0]), \
             patch("kryptos.factor_decomposition.exact_decomposition", side_effect=cut_short):
            result = optimize_lazy(p, decomposition="auto", time_limit_seconds=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "time_limit")
        self.assertEqual(result["frontier_nodes"], 1)
        self.assertEqual(result["nodes"], 1)
        self.assertEqual(result["requeued_nodes"], 1)
        self.assertEqual(result["frontier_progress_nodes"], 0)
        self.assertEqual(result["upper_bound"], 9)
        self.assertEqual(result["lower_bound"], 1)


if __name__ == "__main__":
    unittest.main()
