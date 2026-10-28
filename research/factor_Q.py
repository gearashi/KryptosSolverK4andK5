"""Frozen finite work comparisons for roadmap 31--61.

Run after source freeze; output must be fresh. This script computes its oracle
directly from literal table indices / affine gram letters. It never calls the
production scorer to establish the expected result. The outer audit runner
records input hashes, versions, process ownership and before/after identity.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
from itertools import permutations, product
import json
import math
import multiprocessing
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kryptos.search_runtime import SCHEMA, lazy_ngram_problem, optimize_lazy
from kryptos.factor_advanced import ContextSolver, DecisionDiagram, JunctionQueries
from kryptos.factor_bounds import certified_bounds, matching_upper, threshold_domains, reachable_image_upper
from kryptos.search_guidance_q import (factor_search, independent_top_k, neighborhood_seed,
    multiobjective_search, joint_neighborhood, portfolio_search, parallel_search,
    repair_relaxation_witness, score_until)
from kryptos.factor_advanced import Work, compile_tables


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
            text = "".join(model["alphabet"][(base + sum(point[v] * column[j]
                for v, column in zip(factor["scope"], factor["columns"]))) % 26]
                for j, base in enumerate(factor["base"]))
            raw = model["counts"].get(text, 0) * model["q"] + model["p"]
        value *= raw ** factor.get("power", 1)
    return value


def oracle(problem, point=None):
    point = [-1] * len(problem["domains"]) if point is None else point
    return sorted(((literal_score(problem, row), row) for row in product(*(
        range(d) if a < 0 else (a,) for d, a in zip(problem["domains"], point)))),
        key=lambda row: (-row[0], row[1]))


def table_case(name, domains, factors):
    return name, dict(schema=SCHEMA, domains=domains, factors=[dict(kind="table", scope=s, values=v) for s, v in factors])


def cases():
    output = [
        table_case("chain-eight", [2]*8, [([i, i+1], [1, 2, 3, 7]) for i in range(7)]),
        table_case("disconnected-pairs", [2]*8, [([i, i+1], [1, 4, 2, 8]) for i in range(0, 8, 2)]),
        table_case("zero-annihilation", [2, 3, 2], [([0, 2], [1, 9, 8, 2]), ([1], [0, 0, 0])]),
        table_case("frustrated-triangle", [2]*3, [([0, 1], [9, 1, 1, 9]), ([1, 2], [9, 1, 1, 9]), ([0, 2], [1, 9, 9, 1])]),
        table_case("three-coordinate-plateau", [2]*3, [([0, 1, 2], [3, 1, 1, 1, 1, 1, 1, 9])]),
        table_case("constant-factors", [2]*5, [([0, 1], [2]*4), ([2, 3], [3]*4), ([4], [4]*2)]),
        table_case("center-first-wide-star", [5]*5, [([0, leaf],
            [9 if center == leaf-1 and value == leaf-1 else 2 if value == center else 1
             for center in range(5) for value in range(5)]) for leaf in range(1, 5)]),
    ]
    rng = random.Random(31061)
    for number in range(24):
        domains = [2, 3, 2, 2, 2]
        factors = []
        for index in range(6):
            scope = sorted(rng.sample(range(5), 2 + index % 2))
            factors.append(dict(kind="table", scope=scope,
                values=[rng.randrange(6) for _ in range(math.prod(domains[v] for v in scope))], power=1 + index % 2))
        output.append((f"random-{number:02}", dict(schema=SCHEMA, domains=domains, factors=factors)))
    from kryptos.general_layers import solve_layers, literal_encrypt
    from kryptos.language import CorpusDocument, train_ngram_model
    for period in (2, 3):
        text = "SECRETTESTMESSAGES"
        stages = [dict(operation="substitution", period=period)]
        ciphertext = literal_encrypt(text, ["ABC"[:period]], stages)
        solution = solve_layers(ciphertext, {0: "S"}, stages)
        model = train_ngram_model([CorpusDocument(text*3, "authored-Q-frozen-control")],
            label="Q-frozen-control", order=2, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", normalization="identity")
        output.append((f"cipher-affine-period-{period}", lazy_ngram_problem(solution, model, [0])))
    return output


VARIANTS = [("baseline", {}), ("previous-auto", dict(decomposition="auto")),
    ("previous-mini-bucket", dict(elimination_bound="mini_bucket")),
    ("previous-group-four", dict(factor_group_size=4))] + [("decomposition-" + name, dict(decomposition=name))
    for name in ("and_or", "junction", "diagram", "chain", "cutset")] + [
    ("ordering-" + name, dict(ordering=name)) for name in ("strong", "separator")] + [
    ("bound-" + name, dict(elimination_bound=name))
    for name in ("overlap", "adaptive", "cycles", "reparameterization", "mod2", "mod13")]


def work_summary(report):
    work = report["work"]
    inner = report["decomposition"].get("strategy_work", {})
    return dict(branch_decisions=work.get("branch_decisions", 0) + inner.get("branch_decisions", 0)
                + inner.get("diagram_branch_decisions", 0),
        complete_objective_evaluations=work.get("complete_objective_evaluations", 0)
                + work.get("complete_seed_replays", 0) + work.get("complete_residual_replays", 0)
                + inner.get("full_objective_table_rows", 0),
        outer_search_nodes=report["nodes"], work=work, decomposition_work=inner,
        decomposition=report["decomposition"])


def run_case(item):
    name, problem = item
    expected = oracle(problem)
    rows = []
    for variant, options in VARIANTS:
        result = optimize_lazy(problem, max_nodes=100000, time_limit_seconds=30,
                               decomposition_max_entries=100000, decomposition_max_operations=2000000,
                               elimination_max_entries=100000, elimination_max_operations=2000000, **options)
        assert result["complete"], (name, variant, result["stop_reason"])
        assert (result["score"], tuple(result["assignment"])) == expected[0], (name, variant)
        rows.append(dict(variant=variant, score_hex=hex(result["score"]), assignment=result["assignment"], **work_summary(result)))
    guided = []
    for ordering in ("natural", "strong", "pseudocost", "conflict", "separator"):
        result = factor_search(problem, ordering=ordering, max_nodes=100000, max_operations=2000000)
        assert result["complete"], (name, ordering, result)
        assert (result["score"], tuple(result["assignment"])) == expected[0]
        guided.append(dict(ordering=ordering, work=result["work"]))
    relational = factor_search(problem, ordering="natural", relation_branching=True, max_operations=2000000)
    assert relational["complete"] and (relational["score"], tuple(relational["assignment"])) == expected[0]
    natural_values = factor_search(problem, ordering="natural", value_order="natural", max_nodes=100000, max_operations=2000000)
    assert natural_values["complete"] and (natural_values["score"], tuple(natural_values["assignment"])) == expected[0]
    return dict(case=name, assignment_space=math.prod(problem["domains"]), oracle_complete_evaluations=len(expected),
                variants=rows, guidance=guided, relational_work=relational["work"],
                natural_value_order_work=natural_values["work"])


def mechanisms(all_cases):
    by_name = dict(all_cases)
    chain = by_name["chain-eight"]
    contexts = ContextSolver(chain)
    messages = JunctionQueries(chain)
    repeated_context = [contexts.query(), contexts.query()]
    repeated_messages = [messages.query(), messages.query([1] + [-1]*7), messages.query([1] + [-1]*7)]
    triangle = by_name["frustrated-triangle"]
    bounds = certified_bounds(triangle, techniques=["overlap", "adaptive", "cycles", "reparameterization", "mod2", "mod13"])
    expected = oracle(triangle)[0][0]
    assert all(v >= expected for v in bounds["bounds"].values())
    thresholds = threshold_domains(chain, oracle(chain)[0][0])
    for score, point in oracle(chain):
        if score >= thresholds["threshold"]:
            assert all(a in d for a, d in zip(point, thresholds["domains"]))
    weights = [[9, 2, 1], [8, 1, 4], [7, 6, 2]]
    matching = matching_upper(weights)
    assert matching["upper_bound"] == max(math.prod(weights[i][v] for i, v in enumerate(row)) for row in permutations(range(3)))
    matching["independent_upper"] = math.prod(max(row) for row in weights)
    components = independent_top_k(by_name["disconnected-pairs"], 10)
    assert [(r["score"], tuple(r["assignment"])) for r in components["candidates"]] == oracle(by_name["disconnected-pairs"])[:10]
    plateau = by_name["three-coordinate-plateau"]
    neighborhood = {str(size): neighborhood_seed(plateau, [0, 0, 0], max_block_size=size) for size in (2, 3)}
    repaired = repair_relaxation_witness(triangle)
    assert repaired["score"] == literal_score(triangle, repaired["assignment"])
    different = json.loads(json.dumps(plateau))
    different["factors"][0]["values"][-1] = 12
    joint = joint_neighborhood([dict(id="a", problem=plateau), dict(id="b", problem=different)], [0, 0, 0])
    assert joint["candidate"]["route"] == "b" and joint["candidate"]["score"] == 12
    objectives = [by_name[f"random-{i:02}"] for i in range(3)]
    multi = multiobjective_search(objectives)
    bank = multiobjective_search(objectives, aggregate="max")
    assert multi["complete"] and bank["complete"]
    assert [(r["score"], tuple(r["assignment"])) for r in multi["candidates"]] == [oracle(p)[0] for p in objectives]
    portfolio = []
    for name, problem in all_cases:
        if not name.startswith("random-"):
            continue
        report = portfolio_search(problem, rounds=4, nodes_per_round=2)
        assert report["candidate"]["score"] == literal_score(problem, report["candidate"]["assignment"])
        if report["complete"]:
            assert (report["candidate"]["score"], tuple(report["candidate"]["assignment"])) == oracle(problem)[0]
        portfolio.append(dict(case=name, report=report))
    work = Work()
    _, tables = compile_tables(chain, work)
    abort = score_until(tables, (0,)*8, oracle(chain)[0][0], work, lexical_can_improve=True)
    assert abort is None
    image_problem = dict(schema=SCHEMA, domains=[13]*4,
        model=dict(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", counts={"AA":9,"CC":5,"AB":100},p=1,q=1,order=2,id="Q-image"),
        factors=[dict(kind="ngram",scope=[0,1,2,3],base=[0,0],columns=[[2,2]]*4)])
    images = reachable_image_upper(image_problem)
    assert images["upper_bound"] == oracle(image_problem)[0][0]
    return dict(repeated_context=repeated_context, repeated_messages=repeated_messages,
        bounds=bounds, threshold=thresholds, matching=matching, independent_top_k=components,
        neighborhood=neighborhood, relaxation_repair=repaired, joint_neighborhood=joint,
        multiobjective=multi, hypothesis_bank=bank, portfolio=portfolio,
        partial_score_abort=dict(value=abort, work=dict(work.counts)), reachable_images=images)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--shared-workers", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.workers <= 64 or not 1 <= args.shared_workers <= 64:
        parser.error("workers must be in 1..64")
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("preserve earlier evidence; output exists")
    frozen = cases()
    canonical = json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
    if args.workers == 1:
        rows = [run_case(case) for case in frozen]
    else:
        with ProcessPoolExecutor(max_workers=args.workers, mp_context=multiprocessing.get_context("spawn")) as pool:
            rows = list(pool.map(run_case, frozen))
    controls = mechanisms(frozen)
    sharing = {}
    problem = dict(frozen)["chain-eight"]
    expected = oracle(problem)[0]
    for enabled in (False, True):
        report = parallel_search(problem, workers=args.shared_workers, share_incumbents=enabled)
        assert report["complete"]
        assert (report["candidate"]["score"], tuple(report["candidate"]["assignment"])) == expected
        sharing[str(enabled)] = report
    outcome = dict(schema="kryptos.Q-factor-work.v1", seed=31061, case_count=len(frozen),
        case_sha256=hashlib.sha256(canonical).hexdigest(), workers=args.workers,
        assertion_tested="Every completed finite variant equals the literal Cartesian maximum and original-coordinate lexical tie",
        interpretation="Finite controls only. Internal branching, full table rows, preprocessing, probes and replay are charged separately; no universal reduction or Kryptos decipherment.",
        cases=rows, mechanisms=controls, incumbent_sharing=sharing)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(outcome, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(case_count=len(rows), exact_variant_checks=len(rows)*len(VARIANTS), output=str(output))))


if __name__ == "__main__":
    main()
