"""Explicitly bounded guidance; all exclusions use certified integer bounds."""
from fractions import Fraction
from itertools import combinations, product
import heapq
import math

from .factor_advanced import (Limit, Table, Work, compile_tables, components,
    condition, separator_variable, ContextSolver, DecisionDiagram)


def _value(table, point, work):
    key = tuple(point[v] for v in table.scope)
    # The original finite table is immutable. Keep this read in the work count
    # even when a Python lookup table accelerates its implementation.
    work.add("factor_evaluations")
    for row, value in table.rows:
        if row == key:
            return value
    raise AssertionError("complete point missing from a factor")


def _upper(tables, point, work):
    upper = 1
    for table in tables:
        maximum = 0
        for row, value in table.rows:
            work.add("bound_table_rows")
            if all(point[v] < 0 or point[v] == a for v, a in zip(table.scope, row)):
                maximum = max(maximum, value)
        upper *= maximum
    if -1 not in point:
        work.add("complete_objective_evaluations")
    return upper


def score_until(tables, point, threshold, work, *, lexical_can_improve=True):
    """Stop scoring only when the exact remaining-max product loses."""
    maxima = [table.maximum for table in tables]
    suffix = [1] * (len(tables) + 1)
    for i in range(len(tables) - 1, -1, -1):
        suffix[i] = suffix[i + 1] * maxima[i]
        work.add("score_abort_preparation")
    score = 1
    for index, table in enumerate(tables):
        score *= _value(table, point, work)
        upper = score * suffix[index + 1]
        if upper < threshold or (upper == threshold and not lexical_can_improve):
            if index + 1 == len(tables):
                work.add("complete_objective_evaluations")
                work.add("complete_scores_rejected")
            else:
                work.add("partial_scores_aborted")
            return None
    work.add("complete_objective_evaluations")
    return score


def factor_search(problem, *, ordering="strong", value_order="bound", max_nodes=10000,
                  max_operations=2000000, max_entries=100000, probe_variables=4,
                  reliability=2, relation_branching=False, initial_assignments=(),
                  assignment=None, incumbent_reader=None, incumbent_writer=None):
    """Depth-first exact search with measured, non-excluding order heuristics.

    Strong probes, pseudocost observations and conflict weights only choose an
    ordering. The relation branch emits one complete factor row and an explicit
    complementary 'other rows' branch, so no row is silently dropped.
    """
    from .search_runtime import _integer
    if ordering not in ("natural", "strong", "pseudocost", "conflict", "separator"):
        raise ValueError("unknown factor search ordering")
    if value_order not in ("natural", "bound") or type(relation_branching) is not bool:
        raise ValueError("invalid value order or relation branching")
    _integer(max_nodes, "max_nodes", 0, 1000000)
    _integer(probe_variables, "probe_variables", 1, 16)
    _integer(reliability, "reliability", 1, 100)
    if not isinstance(initial_assignments, (list, tuple)) or len(initial_assignments) > 100:
        raise ValueError("at most 100 initial assignments are allowed")
    work = Work(max_operations, max_entries)
    best, best_score, complete, stop = None, None, False, "operation_limit"
    frontier = []
    try:
        domains, tables = compile_tables(problem, work)
        from .factor_advanced import partial_point
        root = partial_point(domains, assignment)
        best = tuple(max(0, a) for a in root)
        best_score = _upper(tables, best, work)
        if incumbent_writer is not None:
            incumbent_writer(best, best_score)
        for seed in initial_assignments:
            if (not isinstance(seed, (list, tuple)) or len(seed) != len(domains)
                    or any(type(v) is not int or not 0 <= v < d for v, d in zip(seed, domains))):
                raise ValueError("invalid initial assignment")
            candidate = tuple(seed)
            if any(value >= 0 and candidate[i] != value for i, value in enumerate(root)):
                raise ValueError("initial assignment lies outside the requested region")
            score = score_until(tables, candidate, best_score, work, lexical_can_improve=candidate < best)
            if score is not None and (-score, candidate) < (-best_score, best):
                best_score, best = score, candidate
                if incumbent_writer is not None:
                    incumbent_writer(best, best_score)
        frontier = [(root, (), _upper(tables, root, work), False)]
        pseudocost = {v: [] for v in range(len(domains))}
        weights = [1] * len(tables)
        bound_cache = {}
        def bound(point):
            if point in bound_cache:
                work.add("probe_bound_reuses")
                return bound_cache[point]
            value = _upper(tables, point, work)
            bound_cache[point] = value
            return value
        def violates(point, exclusions):
            return any(all(point[v] >= 0 and point[v] == a for v, a in forbidden) for forbidden in exclusions)
        def lex_min(point):
            return tuple(max(0, v) for v in point)
        last_external = None
        while frontier:
            if work.counts["search_nodes"] >= max_nodes:
                stop = "node_limit"
                break
            if incumbent_reader is not None:
                external = incumbent_reader()
                if external is not None and external != last_external:
                    candidate = tuple(external)
                    if (len(candidate) != len(domains)
                            or any(type(v) is not int or not 0 <= v < d for v, d in zip(candidate, domains))):
                        raise ValueError("shared incumbent violates global domain")
                    # A global incumbent need not lie in this worker's region.
                    # Its score is always recomputed, never trusted remotely.
                    score = _upper(tables, candidate, work)
                    work.add("shared_incumbent_replays")
                    last_external = candidate
                    if (-score, candidate) < (-best_score, best):
                        best_score, best = score, candidate
            point, exclusions, upper, relation_used = frontier.pop()
            work.add("search_nodes")
            if violates(point, exclusions):
                work.add("complement_relation_rejections")
                continue
            if upper < best_score or (upper == best_score and lex_min(point) >= best):
                work.add("score_exclusions")
                for i, table in enumerate(tables):
                    if any(point[v] >= 0 for v in table.scope):
                        weights[i] += 1
                continue
            if -1 not in point:
                if (-upper, point) < (-best_score, best):
                    best_score, best = upper, point
                    if incumbent_writer is not None:
                        incumbent_writer(best, best_score)
                continue
            if relation_branching and not relation_used:
                candidates = [(t.maximum - min(v for _, v in t.rows), -i, t)
                              for i, t in enumerate(tables) if sum(point[v] < 0 for v in t.scope) >= 2]
                if candidates:
                    selected = max(candidates, key=lambda row: row[:2])
                    table = selected[2]
                    factor = problem["factors"][-selected[1]]
                    feasible = [(row, value) for row, value in table.rows
                                if all(point[v] < 0 or point[v] == a for v, a in zip(table.scope, row))]
                    preferred = min(feasible, key=lambda row: (-row[1], row[0]))[0]
                    preferred_rows = [preferred]
                    if factor["kind"] == "ngram":
                        def image(row):
                            work.add("relation_image_coordinates", len(row) * len(factor["base"]))
                            return tuple((b + sum(c[j]*v for c, v in zip(factor["columns"], row))) % 26
                                         for j, b in enumerate(factor["base"]))
                        target = image(preferred)
                        preferred_rows = [row for row, _ in feasible if image(row) == target]
                    relations = tuple(tuple(zip(table.scope, row)) for row in preferred_rows)
                    work.add("relation_branch_decisions")
                    frontier.append((point, exclusions + relations, upper, True))
                    for relation in reversed(relations):
                        trial = list(point)
                        for v, a in relation:
                            trial[v] = a
                        frontier.append((tuple(trial), exclusions, bound(tuple(trial)), True))
                    continue
            unknown = [v for v, a in enumerate(point) if a < 0]
            involved = lambda v: sum(weights[i] for i, t in enumerate(tables) if v in t.scope)
            if ordering == "natural":
                variable = unknown[0]
            elif ordering == "conflict":
                variable = max(unknown, key=lambda v: (Fraction(involved(v), domains[v]), -v))
            elif ordering == "separator":
                residual = tuple(Table(tuple(v for v in t.scope if point[v] < 0), ()) for t in tables
                                 if any(point[v] < 0 for v in t.scope))
                variable = separator_variable(residual, domains, work) if residual else unknown[0]
            else:
                reliable = [v for v in unknown if len(pseudocost[v]) >= reliability]
                if ordering == "pseudocost" and len(reliable) == len(unknown):
                    variable = max(unknown, key=lambda v: (sum(pseudocost[v]) / len(pseudocost[v]), -v))
                    work.add("pseudocost_choices")
                else:
                    choices = []
                    for v in sorted(unknown, key=lambda v: (-involved(v), domains[v], v))[:probe_variables]:
                        values = []
                        for a in range(domains[v]):
                            trial = list(point)
                            trial[v] = a
                            work.add("strong_branch_probes")
                            values.append(bound(tuple(trial)))
                        gain = Fraction(upper - max(values), max(1, upper))
                        pseudocost[v].append(gain)
                        choices.append((max(values), sum(values), domains[v], v))
                    variable = min(choices)[-1]
            work.add("branch_decisions")
            children = []
            for a in range(domains[variable]):
                trial = list(point)
                trial[variable] = a
                child = tuple(trial)
                child_upper = bound(child)
                pseudocost[variable].append(Fraction(upper - child_upper, max(1, upper)))
                children.append((child, exclusions, child_upper, relation_used))
            if value_order == "bound":
                children.sort(key=lambda row: (-row[2], lex_min(row[0])))
            frontier.extend(reversed(children))
        else:
            complete, stop = True, "exhausted"
    except Limit as exc:
        stop = str(exc)
    regional_witness = best is not None and all(value < 0 or best[i] == value for i, value in enumerate(root))
    return dict(complete=complete, score=best_score, assignment=list(best) if best is not None else None,
                stop_reason=stop, work=dict(work.counts), ordering=ordering, value_order=value_order,
                frontier_nodes=len(frontier), optimality_claimed=complete and regional_witness,
                region_exhausted=complete, incumbent_in_region=regional_witness,
                interpretation="A reverified shared incumbent may be outside this partition; region exhaustion then proves no improvement over that global incumbent, not a regional optimum.")


def neighborhood_seed(problem, initial, *, variables=None, max_block_size=4,
                      max_blocks=32, max_operations=2000000, max_entries=100000):
    """Larger exact block repair; the outside coordinates remain fixed.

    Each neighborhood uses an exact context solver instead of evaluating every
    full candidate. This is only incumbent guidance for the full problem.
    """
    from .search_runtime import _integer
    from .factor_advanced import partial_point
    _integer(max_block_size, "max_block_size", 1, 16)
    _integer(max_blocks, "max_blocks", 1, 256)
    solver = ContextSolver(problem, max_operations=max_operations, max_entries=max_entries)
    point = partial_point(solver.domains, initial)
    if -1 in point:
        raise ValueError("neighborhood seed must be a complete assignment")
    if variables is None:
        variables = list(range(len(point)))
    if (not isinstance(variables, list) or len(set(variables)) != len(variables)
            or any(type(v) is not int or not 0 <= v < len(point) for v in variables)):
        raise ValueError("invalid neighborhood variable set")
    best = solver.query(point)
    if not best["complete"]:
        return dict(best, neighborhood_trials=0, optimality_claimed=False)
    trials = 0
    for size in range(min(max_block_size, len(variables)), 0, -1):
        for block in combinations(variables, size):
            if trials >= max_blocks:
                return dict(best, neighborhood_trials=trials, optimality_claimed=False)
            partial = list(best["assignment"])
            for variable in block:
                partial[variable] = -1
            result = solver.query(partial)
            trials += 1
            if not result["complete"]:
                return dict(best, neighborhood_trials=trials, stop_reason=result["stop_reason"],
                            work=dict(solver.work.counts), optimality_claimed=False)
            if (-result["score"], result["assignment"]) < (-best["score"], best["assignment"]):
                best = result
    return dict(best, neighborhood_trials=trials, work=dict(solver.work.counts), optimality_claimed=False)


def repair_relaxation_witness(problem, *, max_operations=2000000, max_entries=100000, max_block_size=4):
    """Vote on inconsistent local maximizers, then verify and repair the seed."""
    work = Work(max_operations, max_entries)
    domains, tables = compile_tables(problem, work)
    votes = [[0] * d for d in domains]
    for table in tables:
        row, _ = min(table.rows, key=lambda item: (-item[1], item[0]))
        for variable, value in zip(table.scope, row):
            work.add("relaxation_witness_votes")
            votes[variable][value] += 1
    seed = [max(range(d), key=lambda a: (votes[v][a], -a)) for v, d in enumerate(domains)]
    remaining = max_operations - work.counts["operations"]
    if remaining < 1:
        return dict(complete=False, assignment=None, score=None, stop_reason="operation_limit", work=dict(work.counts))
    report = neighborhood_seed(problem, seed, max_operations=remaining, max_entries=max_entries,
                               max_block_size=max_block_size)
    report["relaxation_seed"] = seed
    report["proposal_work"] = dict(work.counts)
    report["optimality_claimed"] = False
    return report


def independent_top_k(problem, k=10, *, max_operations=2000000, max_entries=100000):
    """Lazy positive-score product merge of exact independent component lists.

    Zero-product ties need special treatment: component score order does not
    imply global lexical order after annihilation. The zero tail is therefore
    generated in original-coordinate lexical order and charged explicitly.
    """
    from .search_runtime import _integer, SCHEMA
    _integer(k, "top", 1, 10000)
    work = Work(max_operations, max_entries)
    output = []
    try:
        domains, tables = compile_tables(problem, work)
        groups = components(tuple(t for t in tables if t.scope), work)
        constant = math.prod(t.rows[0][1] for t in tables if not t.scope)
        involved = {v for t in tables for v in t.scope}
        for v in range(len(domains)):
            if v not in involved:
                groups.append((Table((v,), tuple(((a,), 1) for a in range(domains[v]))),))
        lists, scopes = [], []
        for group in groups:
            scope = sorted({v for t in group for v in t.scope})
            renaming = {v: i for i, v in enumerate(scope)}
            factors = [dict(kind="table", scope=[renaming[v] for v in t.scope],
                            values=[value for _, value in t.rows]) for t in group]
            component_problem = dict(schema=SCHEMA, domains=[domains[v] for v in scope], factors=factors)
            remaining = max_operations - work.counts["operations"]
            if remaining < 1:
                raise Limit("operation_limit")
            solver = DecisionDiagram(component_problem, max_operations=remaining, max_entries=max_entries)
            report = solver.top_k(k)
            for field, value in solver.work.counts.items():
                if field != "operations":
                    work.add("component_" + field, value)
            if not report["complete"]:
                raise Limit(report["stop_reason"])
            lists.append(report["candidates"])
            scopes.append(scope)
        def merged(indices):
            work.add("complete_combination_scores")
            score, assignment = constant, [0] * len(domains)
            for i, index in enumerate(indices):
                row = lists[i][index]
                score *= row["score"]
                for v, a in zip(scopes[i], row["assignment"]):
                    assignment[v] = a
            return score, tuple(assignment)
        indices = (0,) * len(lists)
        score, point = merged(indices)
        heap, seen = [(-score, point, indices)], {indices}
        while heap and len(output) < k:
            negative, point, indices = heapq.heappop(heap)
            work.add("component_merge_pops")
            if negative == 0:
                break
            output.append(dict(score=-negative, assignment=list(point)))
            for i in range(len(indices)):
                if indices[i] + 1 >= len(lists[i]):
                    continue
                nxt = indices[:i] + (indices[i] + 1,) + indices[i+1:]
                if nxt not in seen:
                    seen.add(nxt)
                    value, assignment = merged(nxt)
                    heapq.heappush(heap, (-value, assignment, nxt))
        if len(output) < k:
            for point in product(*(range(d) for d in domains)):
                work.add("zero_tail_candidates")
                value = math.prod(_value(t, point, work) for t in tables)
                work.add("complete_objective_evaluations")
                if value == 0:
                    output.append(dict(score=0, assignment=list(point)))
                    if len(output) == k:
                        break
        return dict(complete=True, candidates=output, work=dict(work.counts), stop_reason="exact_component_top_k")
    except Limit as exc:
        return dict(complete=False, candidates=output, work=dict(work.counts), stop_reason=str(exc))


def multiobjective_search(problems, *, aggregate="all", max_nodes=10000,
                          max_operations=2000000, max_entries=100000):
    """One frontier for several declared product objectives with own thresholds.

    'all' preserves a separate exact optimum for every language/objective.
    'max' searches a finite group of comparable hypotheses for its single best
    product. The caller, not this engine, supplies that comparability model.
    Identical factor tables share conditional bound lookups across objectives.
    """
    from .search_runtime import _integer
    if not isinstance(problems, list) or not 1 <= len(problems) <= 64:
        raise ValueError("problems must contain 1..64 objectives")
    if aggregate not in ("all", "max"):
        raise ValueError("aggregate must be all or max")
    _integer(max_nodes, "max_nodes", 0, 1000000)
    work = Work(max_operations, max_entries)
    best, best_scores, frontier = [], [], []
    try:
        compiled = [compile_tables(p, work) for p in problems]
        domains = compiled[0][0]
        if any(d != domains for d, _ in compiled):
            raise ValueError("shared frontier requires identical coordinate domains")
        objectives = [tables for _, tables in compiled]
        cache = {}
        def bounds(point):
            values = []
            for tables in objectives:
                value = 1
                for table in tables:
                    key = table, tuple(point[v] for v in table.scope)
                    work.add("objective_shared_factor_lookups")
                    if key in cache:
                        work.add("objective_shared_factor_hits")
                        maximum = cache[key]
                    else:
                        maximum = 0
                        for row, score in table.rows:
                            work.add("objective_bound_rows")
                            if all(point[v] < 0 or point[v] == a for v, a in zip(table.scope, row)):
                                maximum = max(maximum, score)
                        cache[key] = maximum
                    value *= maximum
                values.append(value)
            if -1 not in point:
                work.add("complete_candidate_points")
                work.add("complete_objective_evaluations", len(objectives))
            return values
        zero = tuple(0 for _ in domains)
        best_scores = bounds(zero)
        best = [zero for _ in objectives]
        root = tuple(-1 for _ in domains)
        frontier = [(root, bounds(root))]
        stop = "exhausted"
        while frontier:
            if work.counts["search_nodes"] >= max_nodes:
                stop = "node_limit"
                break
            point, upper = frontier.pop()
            work.add("search_nodes")
            minimum = tuple(max(0, v) for v in point)
            if aggregate == "all":
                prune = all(value < incumbent or (value == incumbent and minimum >= witness)
                            for value, incumbent, witness in zip(upper, best_scores, best))
            else:
                champion = min(range(len(best)), key=lambda i: (-best_scores[i], best[i], i))
                prune = max(upper) < best_scores[champion] or (
                    max(upper) == best_scores[champion] and minimum > best[champion])
            if prune:
                work.add("whole_group_exclusions")
                continue
            if -1 not in point:
                for i, value in enumerate(upper):
                    if (-value, point) < (-best_scores[i], best[i]):
                        best_scores[i], best[i] = value, point
                continue
            variable = next(v for v, a in enumerate(point) if a < 0)
            work.add("branch_decisions")
            children = []
            for value in range(domains[variable]):
                child = point[:variable] + (value,) + point[variable + 1:]
                child_bounds = bounds(child)
                children.append((child, child_bounds))
            children.sort(key=lambda row: (-max(row[1]), row[0]))
            frontier.extend(reversed(children))
        complete = not frontier
    except Limit as exc:
        complete, stop = False, str(exc)
    champions = [dict(objective=i, score=score, assignment=list(point))
                 for i, (score, point) in enumerate(zip(best_scores, best))]
    if aggregate == "max" and champions:
        champions = [min(champions, key=lambda row: (-row["score"], row["assignment"], row["objective"]))]
    return dict(complete=complete, stop_reason=stop, candidates=champions, work=dict(work.counts),
                aggregate=aggregate, optimality_claimed=complete,
                interpretation="Separate objectives for all; max requires a declared cross-hypothesis comparable product objective.")


def joint_neighborhood(routes, initial, *, max_block_size=4, max_operations=2000000,
                       max_entries=100000):
    """Repair keys jointly across an explicit finite bank of route neighbors."""
    if (not isinstance(routes, list) or not 1 <= len(routes) <= 64
            or any(not isinstance(row, dict) or set(row) != {"id", "problem"}
                   or not isinstance(row["id"], str) for row in routes)
            or len({row["id"] for row in routes}) != len(routes)):
        raise ValueError("routes require 1..64 distinct id/problem pairs")
    reports, used, best = [], 0, None
    for route in routes:
        if used >= max_operations:
            break
        report = neighborhood_seed(route["problem"], initial, max_block_size=max_block_size,
                                   max_operations=max_operations-used, max_entries=max_entries)
        used += report["work"].get("operations", 0)
        report = dict(report, route=route["id"])
        reports.append(report)
        if report.get("assignment") is not None and (best is None or
                (-report["score"], report["assignment"], report["route"]) <
                (-best["score"], best["assignment"], best["route"])):
            best = report
    return dict(candidate=best, reports=reports, routes_attempted=len(reports), operations=used,
                optimality_claimed=False, scope="only supplied route neighbors and bounded key neighborhoods")


def portfolio_search(problem, *, strategies=("natural", "separator", "strong", "conflict"),
                     rounds=2, nodes_per_round=16, max_operations=2000000, max_entries=100000):
    """Schedule bounded strategies by observed score exclusions per operation.

    Each activation receives the current verified seed. This implementation
    counts replayed nodes when a strategy restarts; it does not claim saved
    frontiers or an unmeasured parallel speedup.
    """
    from .search_runtime import _integer
    _integer(rounds, "rounds", 1, 20)
    _integer(nodes_per_round, "nodes_per_round", 1, 10000)
    if (not isinstance(strategies, (tuple, list)) or not 1 <= len(strategies) <= 8
            or any(s not in ("natural", "separator", "strong", "conflict", "pseudocost") for s in strategies)):
        raise ValueError("invalid portfolio strategy list")
    reports, rates, best, used = [], {}, None, 0
    for round_number in range(rounds):
        order = list(strategies) if not round_number else sorted(strategies, key=lambda s: (-rates.get(s, Fraction(0)), s))
        for strategy in order:
            if used >= max_operations:
                return dict(complete=False, candidate=best, reports=reports, operations=used, stop_reason="operation_limit")
            report = factor_search(problem, ordering=strategy,
                max_nodes=nodes_per_round * (round_number + 1), max_operations=max_operations-used,
                max_entries=max_entries, initial_assignments=[best["assignment"]] if best else [])
            used += report["work"].get("operations", 0)
            rates[strategy] = Fraction(report["work"].get("score_exclusions", 0), max(1, report["work"].get("operations", 0)))
            reports.append(dict(report, activation_round=round_number, proof_progress_per_operation=str(rates[strategy])))
            if report["assignment"] is not None and (best is None or (-report["score"], report["assignment"]) < (-best["score"], best["assignment"])):
                best = report
            if report["complete"]:
                return dict(complete=True, candidate=best, reports=reports, operations=used, stop_reason="one_strategy_proved_optimum")
    return dict(complete=False, candidate=best, reports=reports, operations=used, stop_reason="round_limit")


def _parallel_worker(payload):
    problem, points, shared, lock, options = payload
    def read():
        with lock:
            row = shared.get("best")
            return tuple(row[1]) if row is not None else None
    def write(point, score):
        with lock:
            old = shared.get("best")
            if old is None or (-score, point) < (-int(old[0], 16), tuple(old[1])):
                shared["best"] = hex(score), list(point)
    reports = []
    for point in points:
        report = factor_search(problem, assignment=point, incumbent_reader=read if shared is not None else None,
                               incumbent_writer=write if shared is not None else None, **options)
        reports.append(report)
    return reports


def parallel_search(problem, *, workers=2, share_incumbents=True, max_nodes=10000,
                    max_operations=2000000, max_entries=100000, ordering="strong"):
    """Disjoint prefix workers with reverified shared global incumbents.

    Limits are explicitly per partition. Cooperative sharing can change work
    counts with scheduling, so this API makes no deterministic-work claim.
    A completed global proof requires every disjoint partition to complete.
    """
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    from .search_runtime import _integer, _validate
    _integer(workers, "workers", 1, 64)
    if type(share_incumbents) is not bool:
        raise ValueError("share_incumbents must be boolean")
    domains, _ = _validate(problem)
    depth, size = 0, 1
    while depth < len(domains) and size < workers:
        size *= domains[depth]
        depth += 1
    prefixes = [tuple(row) + (-1,) * (len(domains) - depth) for row in product(*(range(d) for d in domains[:depth]))]
    buckets = [prefixes[i::min(workers, len(prefixes))] for i in range(min(workers, len(prefixes)))]
    options = dict(max_nodes=max_nodes, max_operations=max_operations, max_entries=max_entries, ordering=ordering)
    context = multiprocessing.get_context("spawn")
    with context.Manager() as manager:
        shared = manager.dict() if share_incumbents else None
        lock = manager.Lock() if share_incumbents else None
        with ProcessPoolExecutor(max_workers=len(buckets), mp_context=context) as executor:
            results = list(executor.map(_parallel_worker, [(problem, bucket, shared, lock, options) for bucket in buckets]))
    reports = [report for group in results for report in group]
    candidates = [r for r in reports if r["assignment"] is not None]
    best = min(candidates, key=lambda r: (-r["score"], r["assignment"])) if candidates else None
    return dict(complete=all(r["complete"] for r in reports), candidate=best, reports=reports,
                workers=len(buckets), partitions=len(prefixes), sharing=share_incumbents,
                total_operations=sum(r["work"].get("operations", 0) for r in reports),
                optimality_claimed=all(r["complete"] for r in reports) and best is not None,
                scope="complete disjoint prefix cover; per-partition caps; every shared candidate independently rescored")
