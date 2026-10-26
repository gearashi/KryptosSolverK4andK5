"""Independent finite score/tie oracles for phase P component reuse and gates."""
from itertools import product
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from kryptos.factor_decomposition import ResidualComponentCache
from kryptos.search_runtime import SCHEMA, _Evaluator, optimize_lazy


def table(scope, values, power=1):
    return {"kind": "table", "scope": scope, "values": values, "power": power}


def literal(problem, point):
    answer = 1
    for factor in problem["factors"]:
        if factor["kind"] == "table":
            slot = 0
            for v in factor["scope"]:
                slot = slot * problem["domains"][v] + point[v]
            value = factor["values"][slot]
        else:
            model = problem["model"]
            word = "".join(model["alphabet"][(b + sum(point[v]*column[j] for v, column in zip(factor["scope"], factor["columns"]))) % 26]
                           for j, b in enumerate(factor["base"]))
            value = model["counts"].get(word, 0)*model["q"]+model["p"]
        answer *= value ** factor.get("power", 1)
    return answer


def oracle(problem, partial=None):
    partial = [-1]*len(problem["domains"]) if partial is None else partial
    points = product(*(range(d) if v < 0 else (v,) for d, v in zip(problem["domains"], partial)))
    point = min(points, key=lambda p: (-literal(problem, p), p))
    return point, literal(problem, point)


def repeated_problem():
    return {"schema": SCHEMA, "domains": [2]*5,
            "factors": [table([0,1,2], [2,3,1,8,4,9,2,7]), table([3,4], [2,1,1,9])]}


def cheap_problem():
    return {"schema": SCHEMA, "domains": [2]*4, "factors": [table([0], [100,1]),
            table([1,2], [9,1,1,9]), table([2,3], [9,1,1,9]), table([1,3], [1,9,9,1])]}


class ResidualCacheTests(unittest.TestCase):
    def test_all_partial_assignments_with_zeros_powers_and_constants(self):
        rng = random.Random(71082026)
        for _ in range(8):
            problem = {"schema": SCHEMA, "domains": [2,3,2], "factors": [
                table([], [rng.randrange(5)], rng.randrange(1,4)),
                table([0,1], [rng.randrange(5) for _ in range(6)], rng.randrange(1,4)),
                table([1,2], [rng.randrange(5) for _ in range(6)], rng.randrange(1,4))]}
            memo = ResidualComponentCache(problem)
            for partial in product(*[range(-1,d) for d in problem["domains"]]):
                expected, value = oracle(problem, partial)
                actual = memo.solve(partial)
                self.assertTrue(actual["complete"])
                self.assertEqual((tuple(actual["assignment"]), actual["score"]), (expected, value))

    def test_component_reuse_has_same_answer_and_less_factor_work(self):
        problem = repeated_problem()
        cached = ResidualComponentCache(problem, max_assignments=4)
        plain = ResidualComponentCache(problem, max_assignments=4, max_entries=0)
        partials = [(-1,)*5, (0,-1,-1,-1,-1), (1,-1,-1,-1,-1)]
        for partial in partials:
            left, right = cached.solve(partial), plain.solve(partial)
            self.assertEqual(left, right)
            if left["complete"]:
                expected, score = oracle(problem, partial)
                self.assertEqual((tuple(left["assignment"]),left["score"]),(expected,score))
        self.assertGreater(cached.stats["cache_hits"],0)
        self.assertLess(cached.stats["factor_evaluations"],plain.stats["factor_evaluations"])
        self.assertEqual(cached.stats["witness_factor_evaluations"],plain.stats["witness_factor_evaluations"])

    def test_boundary_changes_never_reuse_similar_component(self):
        problem={"schema":SCHEMA,"domains":[2,2],"factors":[table([0,1],[9,1,1,8])]}
        memo=ResidualComponentCache(problem)
        for partial in ((0,-1),(1,-1)):
            point,value=oracle(problem,partial)
            got=memo.solve(partial)
            self.assertEqual((tuple(got["assignment"]),got["score"]),(point,value))
        self.assertEqual(memo.stats["cache_hits"],0)

    def test_zero_component_does_not_force_other_component_optimum(self):
        problem={"schema":SCHEMA,"domains":[2,2,3],"factors":[table([0],[1,9]),table([1],[0,0])]}
        memo=ResidualComponentCache(problem)
        for _ in range(2):
            got=memo.solve([-1,-1,-1])
            self.assertEqual(got["assignment"],[0,0,0])
            self.assertEqual(got["score"],0)
            self.assertTrue(got["complete"])

    def test_frozen_objective_and_new_invocation_do_not_share_cache(self):
        problem={"schema":SCHEMA,"domains":[2],"factors":[table([0],[1,9])]}
        memo=ResidualComponentCache(problem)
        self.assertEqual(memo.solve([-1])["assignment"],[1])
        problem["factors"][0]["values"][:]=[10,1]
        self.assertEqual(memo.solve([-1])["assignment"],[1])
        fresh=ResidualComponentCache(problem)
        self.assertEqual(fresh.solve([-1])["assignment"],[0])
        self.assertEqual(fresh.stats["cache_hits"],0)

    def test_corrupt_cached_witness_is_rejected_and_invalidated(self):
        memo=ResidualComponentCache({"schema":SCHEMA,"domains":[2],"factors":[table([0],[1,9])]})
        memo.solve([-1]); key=next(iter(memo.cache)); memo.cache[key]=(9,(0,))
        with self.assertRaisesRegex(AssertionError,"original-factor"):
            memo.solve([-1])
        self.assertNotIn(key,memo.cache)
        self.assertEqual(memo.stats["cache_invalidations"],1)

    def test_component_caps_are_inconclusive_then_search_falls_back(self):
        problem=repeated_problem(); expected,value=oracle(problem)
        for options in ({"residual_cache_max_assignments":1},{"residual_cache_max_operations":1}):
            actual=optimize_lazy(problem,residual_cache="components",**options)
            self.assertTrue(actual["complete"])
            self.assertEqual((tuple(actual["assignment"]),actual["score"]),(expected,value))

    def test_ngram_powers_nonstandard_alphabet_and_unused_variable(self):
        problem={"schema":SCHEMA,"domains":[2,3,2],"model":{"alphabet":"BACDEFGHIJKLMNOPQRSTUVWXYZ",
            "counts":{"BB":5,"AC":9},"p":1,"q":2,"order":2,"id":"hand"},
            "factors":[{"kind":"ngram","scope":[0,1],"base":[0,0],"columns":[[1,0],[0,1]],"power":2}]}
        expected,value=oracle(problem); got=ResidualComponentCache(problem).solve([-1]*3)
        self.assertEqual((tuple(got["assignment"]),got["score"]),(expected,value))


class CheapGateTests(unittest.TestCase):
    def test_every_rejected_partial_cannot_beat_score_or_lexical_tie(self):
        problem=cheap_problem(); incumbent=(0,0,0,0); score=literal(problem,incumbent)
        evaluator=_Evaluator(problem,1000,1,2,64,cheap_bound_first=True)
        for partial in product((-1,0,1),repeat=4):
            if evaluator.cheap_reject(partial,score,incumbent):
                point,value=oracle(problem,partial)
                self.assertTrue(value<score or value==score and point>=incumbent)

    def test_cheap_gate_saves_expensive_factor_work(self):
        problem=cheap_problem()
        options=dict(ordering="natural",factor_group_size=2,max_cache_entries=0,
                     elimination_bound="mini_bucket",elimination_bucket_entries=1)
        baseline=optimize_lazy(problem,**options)
        faster=optimize_lazy(problem,cheap_bound_first=True,**options)
        self.assertEqual((baseline["score"],baseline["assignment"]),(faster["score"],faster["assignment"]))
        self.assertGreater(faster["work"]["cheap_bound_rejections"],0)
        self.assertLess(faster["work"]["factor_evaluations"],baseline["work"]["factor_evaluations"])

    def test_zero_and_positive_ties_keep_smaller_assignment(self):
        for values in ([0,0],[5,5]):
            problem={"schema":SCHEMA,"domains":[2],"factors":[table([0],values)]}
            got=optimize_lazy(problem,initial_assignments=[[1]],cheap_bound_first=True,residual_cache="components")
            self.assertEqual(got["assignment"],[0]);self.assertTrue(got["tie_break_proven"])

    def test_full_bounds_survive_resume_and_option_changes_are_rejected(self):
        problem=cheap_problem();options=dict(cheap_bound_first=True,residual_cache="components",
            residual_cache_max_assignments=1,ordering="natural",factor_group_size=2)
        expected=optimize_lazy(problem,**options)
        with tempfile.TemporaryDirectory() as folder:
            previous=None
            for number in range(50):
                path=Path(folder)/f'{number}.json'
                result=optimize_lazy(problem,max_nodes=1,resume_path=previous,checkpoint_path=path,**options)
                payload=json.loads(path.read_text())["payload"]
                evaluator=_Evaluator(problem,0,64,2)
                for row in payload["frontier"]:
                    self.assertEqual(row["upper_hex"],hex(evaluator.upper(tuple(row["assignment"]))))
                previous=path
                if result["complete"]:break
            self.assertTrue(result["complete"])
            self.assertEqual((result["score"],result["assignment"]),(expected["score"],expected["assignment"]))
            with self.assertRaisesRegex(ValueError,"different problem"):
                optimize_lazy(problem,resume_path=previous,**{**options,"cheap_bound_first":False})

    def test_residual_timeout_restores_parent_obligation(self):
        problem=repeated_problem()
        clock=[0]
        def cutoff(*args,**kwargs):
            clock[0]=2
            return {"complete":False,"stop_reason":"time_limit"}
        with patch("kryptos.factor_decomposition.ResidualComponentCache.solve",side_effect=cutoff), \
             patch("kryptos.search_runtime.time.monotonic",side_effect=lambda:clock[0]):
            result=optimize_lazy(problem,residual_cache="components",time_limit_seconds=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["frontier_nodes"],1)
        self.assertEqual(result["requeued_nodes"],1)


if __name__=="__main__":
    unittest.main()
