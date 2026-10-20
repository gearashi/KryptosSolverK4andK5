"""Independent small exhaustive audit; does not import the runtime evaluator."""
from itertools import product
from random import Random
import unittest

from kryptos.factor_decomposition import exact_decomposition
from kryptos.guided_search import guided_seeds


class IndependentStrategyAudit(unittest.TestCase):
    def test_small_residual_optima_and_guided_scores(self):
        rng = Random(51013)
        for case in range(160):
            dimensions = rng.randrange(0, 6)
            domains = [rng.randrange(1, 4) for _ in range(dimensions)]
            factors = []
            for _ in range(rng.randrange(0, 8)):
                scope = sorted(rng.sample(range(dimensions), rng.randrange(dimensions + 1)))
                rows = list(product(*(range(domains[i]) for i in scope)))
                factors.append(dict(kind="table", scope=scope,
                    values=[rng.randrange(0, 5) for _ in rows], power=rng.randrange(1, 4)))

            def score(point):
                answer = 1
                for factor in factors:
                    row = 0
                    for i in factor["scope"]:
                        row = row * domains[i] + point[i]
                    answer *= factor["values"][row] ** factor["power"]
                return answer

            problem = dict(schema="kryptos.lazy-product.v1", domains=domains, factors=factors)
            fixed = [rng.randrange(domains[i]) if rng.randrange(3) == 0 else -1
                     for i in range(dimensions)]
            points = [x for x in product(*(range(d) for d in domains))
                      if all(v < 0 or x[i] == v for i, v in enumerate(fixed))]
            expected = min(points, key=lambda x: (-score(x), x))
            with self.subTest(case=case):
                actual = exact_decomposition(problem, fixed, max_entries=20000,
                    max_operations=200000, time_limit_seconds=5)
                self.assertTrue(actual["complete"])
                self.assertEqual(tuple(actual["assignment"]), expected)
                self.assertEqual(actual["score"], score(expected))
                hints = guided_seeds(problem, seed=case, restarts=3, max_evaluations=40,
                    max_sweeps=3, top=5, max_factor_evaluations=500, time_limit_seconds=5)
                ranks = []
                for row in hints["candidates"]:
                    point, value = tuple(row["assignment"]), int(row["score_hex"], 16)
                    self.assertEqual(value, score(point))
                    ranks.append((-value, point))
                self.assertEqual(ranks, sorted(ranks))
                self.assertEqual(len({point for _, point in ranks}), len(ranks))


if __name__ == "__main__":
    unittest.main()
