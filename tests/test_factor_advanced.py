"""Cartesian oracles independent of the factor implementations."""
import itertools
import math
import random
import unittest

from kryptos.factor_advanced import (ContextSolver, DecisionDiagram, JunctionQueries,
    chain_solve, cutset_solve, run_factor_request, Work, compile_tables)
from kryptos.factor_bounds import certified_bounds, matching_upper, threshold_domains
from kryptos.search_runtime import SCHEMA
from kryptos.search_runtime import optimize_lazy
from kryptos.search_guidance_q import (factor_search, independent_top_k,
    neighborhood_seed, repair_relaxation_witness, multiobjective_search,
    joint_neighborhood, portfolio_search, parallel_search, score_until)


def literal_score(problem, point):
    value = 1
    for factor in problem["factors"]:
        if factor["kind"] == "table":
            index = 0
            for variable in factor["scope"]:
                index = index * problem["domains"][variable] + point[variable]
            raw = factor["values"][index]
        else:
            model = problem["model"]
            text = ""
            for j, base in enumerate(factor["base"]):
                letter = base
                for variable, column in zip(factor["scope"], factor["columns"]):
                    letter += column[j] * point[variable]
                text += model["alphabet"][letter % 26]
            raw = model["counts"].get(text, 0) * model["q"] + model["p"]
        value *= raw ** factor.get("power", 1)
    return value


def exhaustive(problem, partial=None):
    partial = [-1] * len(problem["domains"]) if partial is None else partial
    rows = [(literal_score(problem, point), point)
            for point in itertools.product(*(range(d) if a < 0 else (a,)
                                             for a, d in zip(partial, problem["domains"])))]
    return sorted(rows, key=lambda row: (-row[0], row[1]))


def random_problem(rng, domains=(2, 3, 2, 2)):
    factors = []
    for number in range(5):
        scope = sorted(rng.sample(range(len(domains)), rng.randrange(min(3, len(domains)) + 1)))
        factors.append(dict(kind="table", scope=scope,
            values=[rng.randrange(5) for _ in range(math.prod(domains[i] for i in scope))],
            power=number % 2 + 1))
    return dict(schema=SCHEMA, domains=list(domains), factors=factors)


class AdvancedFactorsTests(unittest.TestCase):
    def test_exact_methods_against_independent_random_oracle(self):
        rng = random.Random(31061)
        for case in range(30):
            p = random_problem(rng)
            partial = [rng.randrange(d) if rng.random() < .3 else -1 for d in p["domains"]]
            expected = exhaustive(p, partial)
            for solver in (ContextSolver(p), JunctionQueries(p)):
                actual = solver.query(partial)
                self.assertTrue(actual["complete"], (case, actual))
                self.assertEqual((actual["score"], tuple(actual["assignment"])), expected[0], (case, type(solver)))
            for actual in (chain_solve(p, partial), cutset_solve(p, partial)):
                self.assertTrue(actual["complete"], (case, actual))
                self.assertEqual((actual["score"], tuple(actual["assignment"])), expected[0], case)
            actual = DecisionDiagram(p).top_k(7, partial)
            self.assertTrue(actual["complete"])
            self.assertEqual([(r["score"], tuple(r["assignment"])) for r in actual["candidates"]], expected[:7], case)

    def test_zero_annihilation_and_irrelevant_coordinates(self):
        p = dict(schema=SCHEMA, domains=[2, 2, 3], factors=[
            dict(kind="table", scope=[0], values=[0, 0]),
            dict(kind="table", scope=[1], values=[1, 9])])
        expected = exhaustive(p)
        self.assertEqual(DecisionDiagram(p).top_k(12)["candidates"],
            [dict(score=s, assignment=list(a)) for s, a in expected])
        for cls in (ContextSolver, JunctionQueries):
            self.assertEqual(cls(p).query()["assignment"], [0, 0, 0])

    def test_junction_reuses_unaffected_separator_subtrees(self):
        p = dict(schema=SCHEMA, domains=[2] * 8, factors=[
            dict(kind="table", scope=[i, i+1], values=[1, 2, 3, 5]) for i in range(7)])
        solver = JunctionQueries(p)
        first = solver.query()
        second = solver.query([1] + [-1] * 7)
        third = solver.query([1] + [-1] * 7)
        self.assertTrue(first["complete"] and second["complete"] and third["complete"])
        self.assertEqual((second["score"], tuple(second["assignment"])), exhaustive(p, [1] + [-1] * 7)[0])
        self.assertGreater(third["query_work"].get("separator_message_hits", 0), 0)
        self.assertEqual(third["query_work"].get("junction_factor_lookups", 0), 0)

    def test_all_bounds_are_admissible_with_ties_zeros_powers(self):
        rng = random.Random(31062)
        techniques = ["overlap", "adaptive", "cycles", "reparameterization", "mod2", "mod13"]
        for case in range(30):
            p = random_problem(rng)
            partial = [rng.randrange(d) if rng.random() < .3 else -1 for d in p["domains"]]
            expected = exhaustive(p, partial)[0][0]
            actual = certified_bounds(p, partial, techniques=techniques)
            self.assertTrue(actual["bound_available"])
            for name, upper in actual["bounds"].items():
                self.assertGreaterEqual(upper, expected, (case, name, actual))
            self.assertLessEqual(actual["upper_bound"], actual["bounds"]["independent"])

    def test_overlap_and_cycle_reduce_incompatible_local_maxima(self):
        p = dict(schema=SCHEMA, domains=[2, 2, 2], factors=[
            dict(kind="table", scope=[0, 1], values=[9, 1, 1, 9]),
            dict(kind="table", scope=[1, 2], values=[9, 1, 1, 9]),
            dict(kind="table", scope=[0, 2], values=[1, 9, 9, 1])])
        result = certified_bounds(p, techniques=["overlap", "cycles", "reparameterization"])
        self.assertEqual(result["bounds"]["cycles"], exhaustive(p)[0][0])
        self.assertLess(result["bounds"]["cycles"], result["bounds"]["independent"])

    def test_threshold_domains_retain_every_qualifying_assignment(self):
        rng = random.Random(31063)
        for _ in range(20):
            p = random_problem(rng)
            rows = exhaustive(p)
            threshold = rows[len(rows) // 3][0]
            result = threshold_domains(p, threshold)
            self.assertTrue(result["complete"])
            for score, assignment in rows:
                if score >= threshold:
                    self.assertTrue(all(v in d for v, d in zip(assignment, result["domains"])))

    def test_matching_bound_equals_permutation_oracle(self):
        weights = [[9, 2, 1], [8, 1, 4], [7, 6, 2]]
        expected = max(math.prod(weights[i][v] for i, v in enumerate(p)) for p in itertools.permutations(range(3)))
        actual = matching_upper(weights)
        self.assertTrue(actual["bound_available"])
        self.assertEqual(actual["upper_bound"], expected)
        self.assertLess(expected, math.prod(max(row) for row in weights))
        self.assertFalse(matching_upper(weights, [[0], [0], [1, 2]])["matching_exists"])

    def test_limits_are_inconclusive_or_keep_a_previously_certified_bound(self):
        p = dict(schema=SCHEMA, domains=[2, 2], factors=[dict(kind="table", scope=[0, 1], values=[1, 2, 3, 9])])
        self.assertFalse(run_factor_request(dict(problem=p, options=dict(max_entries=1)))["complete"])
        self.assertFalse(chain_solve(p, max_width=0)["complete"])
        self.assertFalse(cutset_solve(p, max_operations=1)["complete"])
        self.assertFalse(certified_bounds(p, max_entries=1)["bound_available"])
        self.assertFalse(matching_upper([[1, 2], [2, 1]], max_operations=1)["bound_available"])

    def test_guidance_orders_and_relation_complements_preserve_exact_optimum(self):
        rng = random.Random(31064)
        for case in range(20):
            p = random_problem(rng)
            expected = exhaustive(p)[0]
            for ordering in ("natural", "strong", "pseudocost", "conflict", "separator"):
                actual = factor_search(p, ordering=ordering, relation_branching=bool(case % 2))
                self.assertTrue(actual["complete"], (case, ordering, actual))
                self.assertEqual((actual["score"], tuple(actual["assignment"])), expected)

    def test_integrated_runtime_modes_match_oracle(self):
        rng = random.Random(31065)
        for case in range(10):
            p = random_problem(rng)
            expected = exhaustive(p)[0]
            variants = [dict(decomposition=x) for x in ("and_or", "junction", "diagram", "chain", "cutset")]
            variants += [dict(ordering=x) for x in ("strong", "separator")]
            variants += [dict(elimination_bound=x) for x in ("overlap", "adaptive", "cycles", "reparameterization", "mod2", "mod13")]
            for options in variants:
                actual = optimize_lazy(p, **options)
                self.assertTrue(actual["complete"], (case, options, actual))
                self.assertEqual((actual["score"], tuple(actual["assignment"])), expected, (case, options))

    def test_component_top_k_preserves_zero_tail_lexical_ties(self):
        for values in ([1, 3, 2, 4], [1, 0, 2, 0], [0, 0, 0, 0]):
            p = dict(schema=SCHEMA, domains=[2, 2, 2, 2], factors=[
                dict(kind="table", scope=[0, 2], values=values),
                dict(kind="table", scope=[1, 3], values=[2, 1, 0, 3])])
            expected = exhaustive(p)
            actual = independent_top_k(p, 16)
            self.assertTrue(actual["complete"], actual)
            self.assertEqual([(row["score"], tuple(row["assignment"])) for row in actual["candidates"]], expected)

    def test_higher_order_neighborhood_escapes_pair_plateau(self):
        p = dict(schema=SCHEMA, domains=[2, 2, 2], factors=[
            dict(kind="table", scope=[0, 1, 2], values=[3, 1, 1, 1, 1, 1, 1, 9])])
        pairs = neighborhood_seed(p, [0, 0, 0], max_block_size=2)
        triples = neighborhood_seed(p, [0, 0, 0], max_block_size=3)
        self.assertEqual(pairs["score"], 3)
        self.assertEqual(triples["score"], 9)
        self.assertFalse(triples["optimality_claimed"])
        repaired = repair_relaxation_witness(p)
        self.assertEqual(literal_score(p, repaired["assignment"]), repaired["score"])

    def test_multiple_objective_thresholds_and_group_maximum(self):
        rng = random.Random(31066)
        for _ in range(10):
            problems = [random_problem(rng) for _ in range(3)]
            expected = [exhaustive(p)[0] for p in problems]
            all_result = multiobjective_search(problems)
            self.assertTrue(all_result["complete"])
            self.assertEqual([(r["score"], tuple(r["assignment"])) for r in all_result["candidates"]], expected)
            maximum = multiobjective_search(problems, aggregate="max")
            self.assertTrue(maximum["complete"])
            expected_best = min(((s, p, i) for i, (s, p) in enumerate(expected)), key=lambda r: (-r[0], r[1], r[2]))
            row = maximum["candidates"][0]
            self.assertEqual((row["score"], tuple(row["assignment"]), row["objective"]), expected_best)

    def test_joint_route_key_neighborhood_and_portfolio(self):
        p = dict(schema=SCHEMA, domains=[2, 2, 2], factors=[
            dict(kind="table", scope=[0, 1, 2], values=[3, 1, 1, 1, 1, 1, 1, 9])])
        q = dict(schema=SCHEMA, domains=[2, 2, 2], factors=[
            dict(kind="table", scope=[0, 1, 2], values=[4, 1, 1, 1, 1, 1, 1, 12])])
        report = joint_neighborhood([dict(id="route-a", problem=p), dict(id="route-b", problem=q)], [0, 0, 0])
        self.assertEqual(report["candidate"]["route"], "route-b")
        self.assertEqual(report["candidate"]["score"], 12)
        portfolio = portfolio_search(q)
        self.assertTrue(portfolio["complete"])
        self.assertEqual(portfolio["candidate"]["assignment"], [1, 1, 1])

    def test_actual_ciphertext_family_replays_through_integrated_modes(self):
        from kryptos.general_layers import literal_encrypt, solve_layers
        from kryptos.language import CorpusDocument, train_ngram_model
        from kryptos.search_runtime import lazy_ngram_problem
        plaintext = "SECRETTEST"
        stages = [dict(operation="substitution", period=2)]
        ciphertext = literal_encrypt(plaintext, ["AB"], stages)
        solution = solve_layers(ciphertext, {0: "S"}, stages)
        model = train_ngram_model([CorpusDocument(plaintext * 3, "authored-Q-control")],
            label="Q-control", order=2, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", normalization="identity")
        problem = lazy_ngram_problem(solution, model, [0])
        expected = exhaustive(problem)[0]
        for mode in ("and_or", "junction", "diagram", "chain", "cutset"):
            result = optimize_lazy(problem, decomposition=mode)
            self.assertTrue(result["complete"])
            self.assertEqual((result["score"], tuple(result["assignment"])), expected)
            point = result["assignment"]
            candidate = solution.candidate(point[:solution.dimensions_mod2], point[solution.dimensions_mod2:])
            self.assertEqual(candidate["reencrypted_ciphertext"], ciphertext)
        relation = factor_search(problem, relation_branching=True)
        self.assertTrue(relation["complete"])
        self.assertEqual((relation["score"], tuple(relation["assignment"])), expected)

    def test_parallel_workers_share_only_verified_global_candidates(self):
        p = dict(schema=SCHEMA, domains=[2, 2, 2], factors=[
            dict(kind="table", scope=[0, 1], values=[1, 2, 3, 9]),
            dict(kind="table", scope=[1, 2], values=[2, 1, 3, 7])])
        expected = exhaustive(p)[0]
        for sharing in (False, True):
            actual = parallel_search(p, workers=2, share_incumbents=sharing)
            self.assertTrue(actual["complete"])
            self.assertEqual(actual["partitions"], 2)
            self.assertEqual((actual["candidate"]["score"], tuple(actual["candidate"]["assignment"])), expected)

    def test_partition_seeds_and_global_incumbent_scope_are_distinct(self):
        p = dict(schema=SCHEMA, domains=[2, 2], factors=[dict(kind="table", scope=[0], values=[1, 9])])
        with self.assertRaisesRegex(ValueError, "outside the requested region"):
            factor_search(p, assignment=[0, -1], initial_assignments=[[1, 1]])
        result = factor_search(p, assignment=[0, -1], incumbent_reader=lambda: (1, 1))
        self.assertTrue(result["region_exhausted"])
        self.assertFalse(result["incumbent_in_region"])
        self.assertFalse(result["optimality_claimed"])
        self.assertEqual(result["score"], 9)

    def test_cutset_planning_cap_precedes_combinatorial_materialization(self):
        factors = [dict(kind="table", scope=[v], values=[1, 2]) for v in range(50)]
        for first in range(0, 15, 3):
            for a, b in ((first, first+1), (first+1, first+2), (first, first+2)):
                factors.append(dict(kind="table", scope=[a, b], values=[1, 2, 3, 4]))
        p = dict(schema=SCHEMA, domains=[2]*50, factors=factors)
        result = cutset_solve(p, max_cutset=6, max_operations=5000)
        self.assertFalse(result["complete"])
        self.assertEqual(result["stop_reason"], "operation_limit")
        self.assertLessEqual(result["work"]["operations"], 5000)

    def test_completed_scores_are_not_counted_as_partial_aborts(self):
        p = dict(schema=SCHEMA, domains=[2], factors=[dict(kind="table", scope=[0], values=[1, 9])])
        work = Work()
        _, tables = compile_tables(p, work)
        self.assertIsNone(score_until(tables, (0,), 9, work))
        self.assertEqual(work.counts["complete_objective_evaluations"], 1)
        self.assertEqual(work.counts["complete_scores_rejected"], 1)
        self.assertEqual(work.counts["partial_scores_aborted"], 0)
        p = dict(schema=SCHEMA, domains=[2, 2], factors=[
            dict(kind="table", scope=[0], values=[1, 9]),
            dict(kind="table", scope=[1], values=[1, 9])])
        result = independent_top_k(p, 2)
        self.assertGreaterEqual(result["work"]["complete_combination_scores"], len(result["candidates"]))

    def test_rejected_restart_portfolio_is_not_an_active_option(self):
        p = dict(schema=SCHEMA, domains=[2], factors=[dict(kind="table", scope=[0], values=[1, 9])])
        with self.assertRaisesRegex(ValueError, "restart portfolio was rejected"):
            run_factor_request(dict(method="portfolio", problem=p))


if __name__ == "__main__":
    unittest.main()
