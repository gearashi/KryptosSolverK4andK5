"""Small exact-delta controls, independent of any Kryptos authenticity claim."""
import itertools
import math
import random
import unittest

from kryptos.guided_search import guided_seeds
from kryptos.search_runtime import SCHEMA


def direct(problem, point):
    result = 1
    for f in problem["factors"]:
        if f["kind"] == "table":
            place = 0
            for v in f["scope"]:
                place = place * problem["domains"][v] + point[v]
            value = f["values"][place]
        else:
            model = problem["model"]
            letters = []
            for j, base in enumerate(f["base"]):
                shifted = base
                for v, col in zip(f["scope"], f["columns"]):
                    shifted += point[v] * col[j]
                letters.append(model["alphabet"][shifted % 26])
            value = model["counts"].get("".join(letters), 0) * model["q"] + model["p"]
        result *= value ** f.get("power", 1)
    return result


class GuidedSearchTests(unittest.TestCase):
    def test_delta_scores_zeros_constants_powers_and_determinism(self):
        rng = random.Random(71)
        for _ in range(16):
            p = {"schema": SCHEMA, "domains": [2, 3, 2, 2], "factors": [
                {"kind": "table", "scope": [0, 1], "values": [rng.randrange(5) for _ in range(6)], "power": 2},
                {"kind": "table", "scope": [1, 2], "values": [rng.randrange(5) for _ in range(6)]},
                {"kind": "table", "scope": [], "values": [3]}]}
            a = guided_seeds(p, seed=19, restarts=5, max_evaluations=37, top=20)
            b = guided_seeds(p, seed=19, restarts=5, max_evaluations=37, top=20)
            self.assertEqual(a["candidates"], b["candidates"])
            self.assertEqual(a["work"], b["work"])
            self.assertLessEqual(a["work"]["objective_evaluations"], 37)
            for row in a["candidates"]:
                self.assertEqual(int(row["score_hex"], 16), direct(p, row["assignment"]))
            self.assertFalse(a["optimality_claimed"])

    def test_ngram_delta_nonstandard_alphabet_and_budget(self):
        p = {"schema": SCHEMA, "domains": [2, 13], "model": {
            "alphabet": "BACDEFGHIJKLMNOPQRSTUVWXYZ", "order": 2, "counts": {"AB": 8, "YA": 3},
            "p": 2, "q": 3, "id": "hand"}, "factors": [
            {"kind": "ngram", "scope": [0, 1], "base": [1, 0], "columns": [[13, 0], [2, 4]], "power": 2},
            {"kind": "ngram", "scope": [1], "base": [0, 1], "columns": [[2, 2]]}]}
        result = guided_seeds(p, max_evaluations=60, restarts=4, top=10, seed=4)
        for row in result["candidates"]:
            self.assertEqual(int(row["score_hex"], 16), direct(p, row["assignment"]))
        cutoff = guided_seeds(p, max_factor_evaluations=1)
        self.assertEqual(cutoff["stop_reason"], "factor_evaluation_limit")
        self.assertEqual(cutoff["candidates"], [])
        self.assertEqual(cutoff["work"]["factor_evaluations"], 0)

    def test_full_factor_delta_savings_and_unscored_domain(self):
        p = {"schema": SCHEMA, "domains": [2] * 12, "factors": [
            {"kind": "table", "scope": [i], "values": [1, 2]} for i in range(11)]}
        result = guided_seeds(p, restarts=1, max_evaluations=100)
        self.assertEqual(result["candidates"][0]["assignment"], [1] * 11 + [0])
        self.assertEqual(int(result["candidates"][0]["score_hex"], 16), 2**11)
        self.assertGreater(result["work"]["full_factor_evaluations_avoided"], 100)
        empty = guided_seeds({"schema": SCHEMA, "domains": [], "factors": []})
        self.assertEqual(empty["candidates"], [{"assignment": [], "score_hex": "0x1"}])

    def test_equal_evaluation_discriminator_and_no_universal_improvement(self):
        # The contiguous baseline varies the last four coordinates first.
        # Coordinate search can inspect the important leading coordinate.
        p = {"schema": SCHEMA, "domains": [2] * 8,
             "factors": [{"kind": "table", "scope": [0], "values": [1, 9]}]}
        result = guided_seeds(p, seed=2, restarts=8, max_evaluations=8)
        used = result["work"]["objective_evaluations"]
        contiguous = list(itertools.islice(itertools.product(*[range(2)] * 8), used))
        self.assertGreater(int(result["candidates"][0]["score_hex"], 16), max(direct(p, v) for v in contiguous))
        # A two-coordinate move is needed to reach011 from000. Four local
        # evaluations miss it while four contiguous evaluations include it.
        trap = {"schema": SCHEMA, "domains": [2, 2, 2],
                "factors": [{"kind": "table", "scope": [0, 1, 2], "values": [2, 1, 1, 9, 1, 1, 1, 1]}]}
        local = guided_seeds(trap, restarts=1, max_evaluations=4)
        self.assertEqual(local["work"]["objective_evaluations"], 4)
        baseline = list(itertools.islice(itertools.product(*[range(2)] * 3), 4))
        self.assertLess(int(local["candidates"][0]["score_hex"], 16), max(direct(trap, p) for p in baseline))

    def test_validation(self):
        p = {"schema": SCHEMA, "domains": [2], "factors": []}
        for args in ({"seed": True}, {"max_evaluations": 0}, {"restarts": 0},
                     {"initial_assignments": [[2]]}, {"time_limit_seconds": float("nan")}):
            with self.assertRaises(ValueError):
                guided_seeds(p, **args)


if __name__ == "__main__":
    unittest.main()
