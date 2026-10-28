"""Certified finite-factor relaxations and score-threshold propagation.

All bounds maximize over supersets or use an exact product-preserving change
of factors. They are bounds on a declared score, never cipher infeasibility.
"""
from fractions import Fraction
from itertools import combinations, product
import math

from .factor_advanced import (Limit, Table, Work, compile_tables, condition,
                              eliminate_tables, partial_point)


def reachable_image_upper(problem, assignment=None, *, max_operations=2000000, max_entries=100000):
    """Enumerate reachable joint letter images, never Cartesian key tuples.

    After each affine generator, equal whole grams are merged. This preserves
    every attainable gram even when generator domains are not subgroup cycles.
    It supplies an independent-factor bound, not joint consistency of windows.
    """
    from .search_runtime import _validate
    work = Work(max_operations, max_entries)
    try:
        domains, factors = _validate(problem)
        point = partial_point(domains, assignment)
        upper = 1
        for factor in factors:
            if factor["kind"] == "table":
                maximum = 0
                for row, value in zip(product(*(range(domains[v]) for v in factor["scope"])), factor["values"]):
                    work.add("table_bound_rows")
                    if all(point[v] < 0 or point[v] == a for v, a in zip(factor["scope"], row)):
                        maximum = max(maximum, value)
            else:
                images = {tuple(factor["base"])}
                for variable, column in zip(factor["scope"], factor["columns"]):
                    following = set()
                    for image in images:
                        for value in range(domains[variable]) if point[variable] < 0 else (point[variable],):
                            work.add("reachable_image_transitions")
                            result = tuple((a + b * value) % 26 for a, b in zip(image, column))
                            if result not in following:
                                work.add("allocated_entries")
                                following.add(result)
                    images = following
                maximum, model = 0, problem["model"]
                for image in sorted(images):
                    work.add("distinct_joint_images_scored")
                    word = "".join(model["alphabet"][v] for v in image)
                    maximum = max(maximum, model["counts"].get(word, 0) * model["q"] + model["p"])
            upper *= maximum ** factor.get("power", 1)
        return dict(complete=True, bound_available=True, upper_bound=upper,
                    optimality_claimed=False, work=dict(work.counts), stop_reason="reachable_joint_images")
    except Limit as exc:
        return dict(complete=False, bound_available=False, upper_bound=None,
                    optimality_claimed=False, work=dict(work.counts), stop_reason=str(exc))


def _tree_bound(tables, work, *, adaptive=False):
    """A factor-tree consistency relaxation with exact separator messages."""
    if not tables:
        return 1, []
    if len(tables) > 512:
        raise Limit("overlap_factor_limit")
    parents = list(range(len(tables)))
    def find(v):
        while parents[v] != v:
            v = parents[v]
        return v
    edges = []
    for i, j in combinations(range(len(tables)), 2):
        common = tuple(sorted(set(tables[i].scope) & set(tables[j].scope)))
        work.add("overlap_edge_planning")
        if not common:
            continue
        conflicts = 0
        if adaptive:
            projections = []
            for table in (tables[i], tables[j]):
                indices = [table.scope.index(v) for v in common]
                maximum = table.maximum
                projected = set()
                for row, value in table.rows:
                    work.add("maximizer_conflict_checks")
                    if value == maximum:
                        projected.add(tuple(row[k] for k in indices))
                projections.append(projected)
            conflicts = int(not (projections[0] & projections[1]))
        edges.append((-conflicts, -len(common), i, j, common))
    graph = [[] for _ in tables]
    for _, _, i, j, common in sorted(edges):
        work.add("overlap_forest_edges")
        a, b = find(i), find(j)
        if a != b:
            parents[a] = b
            graph[i].append((j, common))
            graph[j].append((i, common))

    def visit(index, parent, separator):
        table = tables[index]
        children = [(common, visit(child, index, common)) for child, common in graph[index] if child != parent]
        positions = [table.scope.index(v) for v in separator]
        output = {}
        for row, value in table.rows:
            filled = dict(zip(table.scope, row))
            witness = [(index, row)]
            for common, messages in children:
                work.add("overlap_message_products")
                multiplier, child_witness = messages[tuple(filled[v] for v in common)]
                value *= multiplier
                witness.extend(child_witness)
            key = tuple(row[i] for i in positions)
            candidate = value, tuple(sorted(witness))
            if key not in output or (-value, candidate[1]) < (-output[key][0], output[key][1]):
                output[key] = candidate
        work.add("allocated_entries", len(output))
        return output

    upper, witness = 1, []
    for root in sorted({find(i) for i in range(len(tables))}):
        value, rows = visit(root, -1, ())[()]
        upper *= value
        witness.extend(rows)
    return upper, sorted(witness)


def _merge_tables(tables, domains, work):
    scope = tuple(sorted({v for t in tables for v in t.scope}))
    work.add("allocated_entries", math.prod(domains[v] for v in scope))
    lookups = [(t.scope, dict(t.rows)) for t in tables]
    rows = []
    for row in product(*(range(domains[v]) for v in scope)):
        fixed, value = dict(zip(scope, row)), 1
        for local, lookup in lookups:
            work.add("cycle_cluster_products")
            value *= lookup[tuple(fixed[v] for v in local)]
        rows.append((row, value))
    return Table(scope, tuple(rows))


def cycle_bound(tables, domains, work, *, max_cycle_size=3):
    """Join one bounded factor cycle exactly before taking a tree relaxation."""
    from .search_runtime import _integer
    _integer(max_cycle_size, "max_cycle_size", 3, 6)
    if len(tables) > 128:
        raise Limit("cycle_factor_limit")
    adjacency = {i: {j for j in range(len(tables)) if i != j and set(tables[i].scope) & set(tables[j].scope)}
                 for i in range(len(tables))}
    cycles = []
    def walk(path):
        if len(path) >= 3 and path[0] in adjacency[path[-1]]:
            cycles.append(tuple(path))
        if len(path) == max_cycle_size:
            return
        for nxt in sorted(adjacency[path[-1]]):
            work.add("cycle_discovery_edges")
            if nxt > path[0] and nxt not in path:
                walk(path + [nxt])
    for root in adjacency:
        walk([root])
    if not cycles:
        return _tree_bound(tables, work)[0], []
    chosen = min(cycles, key=lambda c: (
        math.prod(domains[v] for v in {v for i in c for v in tables[i].scope}), c))
    selected = set(chosen)
    merged = _merge_tables([tables[i] for i in chosen], domains, work)
    remainder = [t for i, t in enumerate(tables) if i not in selected] + [merged]
    return _tree_bound(tuple(remainder), work)[0], list(chosen)


def reparameterized_bound(tables, work, *, rounds=2):
    """Exact rational max-marginal transfer, retaining every best upper bound.

    For each overlap s, divide F_i by m(s)=max F_i and multiply F_j by
    m(s). Their product is unchanged pointwise. A zero m(s) uses divisor one:
    F_i and the transformed product are then both zero on that context.
    """
    from .search_runtime import _integer
    _integer(rounds, "rounds", 1, 20)
    current = [Table(t.scope, tuple((row, Fraction(v)) for row, v in t.rows)) for t in tables]
    best = math.prod(t.maximum for t in current)
    pairs = []
    for i in range(len(current)):
        for j in range(len(current)):
            work.add("reparameterization_pair_planning")
            if i != j:
                common = tuple(sorted(set(current[i].scope) & set(current[j].scope)))
                if common:
                    work.add("allocated_entries")
                    pairs.append((i, j, common))
    for _ in range(rounds):
        for i, j, common in pairs:
            work.add("reparameterization_pair_checks")
            if not common:
                continue
            source, target = current[i], current[j]
            si = [source.scope.index(v) for v in common]
            tj = [target.scope.index(v) for v in common]
            marginal = {}
            for row, value in source.rows:
                work.add("reparameterization_maxima")
                key = tuple(row[k] for k in si)
                marginal[key] = max(marginal.get(key, Fraction(0)), value)
            source_rows, target_rows = [], []
            for row, value in source.rows:
                work.add("rational_reparameterizations")
                divisor = marginal[tuple(row[k] for k in si)]
                source_rows.append((row, value / (divisor or 1)))
            for row, value in target.rows:
                work.add("rational_reparameterizations")
                target_rows.append((row, value * marginal[tuple(row[k] for k in tj)]))
            current[i], current[j] = Table(source.scope, tuple(source_rows)), Table(target.scope, tuple(target_rows))
            best = min(best, math.prod(t.maximum for t in current))
    # The objective is an integer. Flooring a rational upper bound is safe.
    return best.numerator // best.denominator


def projection_bound(tables, domains, work, *, modulus=2):
    """Max-project each factor to coordinate residues, then solve jointly."""
    if modulus not in (2, 13):
        raise ValueError("modulus must be 2 or 13")
    projected = []
    for table in tables:
        rows = {}
        for key, value in table.rows:
            work.add("modular_projection_rows")
            residue = tuple(v % modulus for v in key)
            rows[residue] = max(rows.get(residue, 0), value)
        projected.append(Table(table.scope, tuple(sorted(rows.items()))))
    return eliminate_tables(tuple(min(d, modulus) for d in domains), tuple(projected), work)[0]


def matching_upper(weights, allowed=None, *, max_operations=2000000):
    """Exact assignment relaxation for unresolved route-to-column weights.

    The caller must supply a certified nonnegative upper weight for each
    route/column pairing. Enforcing one-to-one matching is tighter than taking
    each row's independent maximum. The numeric optimum is not a route/key
    witness unless these weights are the actual objective.
    """
    if (not isinstance(weights, list) or not 1 <= len(weights) <= 20
            or any(not isinstance(row, list) or len(row) != len(weights)
                   or any(type(v) is not int or v < 0 for v in row) for row in weights)):
        raise ValueError("weights must be a square 1..20 nonnegative integer matrix")
    n = len(weights)
    if allowed is None:
        allowed = [list(range(n)) for _ in weights]
    if (not isinstance(allowed, list) or len(allowed) != n
            or any(not isinstance(row, list) or len(set(row)) != len(row)
                   or any(type(v) is not int or not 0 <= v < n for v in row) for row in allowed)):
        raise ValueError("invalid allowed route columns")
    work = Work(max_operations)
    frontier = {0: (1, (), ())}
    try:
        for row in range(n):
            next_frontier = {}
            for mask, (score, witness, minimum) in frontier.items():
                for column in allowed[row]:
                    work.add("matching_transitions")
                    bit = 1 << column
                    if mask & bit:
                        continue
                    new_mask = mask | bit
                    value = score * weights[row][column]
                    candidate = value, (witness if value else minimum) + (column,)
                    lexical = minimum + (column,)
                    old = next_frontier.get(new_mask)
                    if old is None:
                        next_frontier[new_mask] = candidate + (lexical,)
                    else:
                        best = candidate if (-candidate[0], candidate[1]) < (-old[0], old[1]) else old[:2]
                        next_frontier[new_mask] = best + (min(lexical, old[2]),)
            frontier = next_frontier
        result = frontier.get((1 << n) - 1)
        return dict(bound_available=True, upper_bound=result[0] if result else 0,
                    matching=list(result[1]) if result else None, matching_exists=result is not None,
                    work=dict(work.counts))
    except Limit as exc:
        return dict(bound_available=False, upper_bound=None, matching=None,
                    stop_reason=str(exc), work=dict(work.counts))


def certified_bounds(problem, assignment=None, *, techniques=("overlap",), max_operations=2000000,
                     max_entries=100000, rounds=2):
    """Take the minimum of independently admissible finite relaxations."""
    allowed = {"overlap", "adaptive", "cycles", "reparameterization", "mod2", "mod13"}
    if not isinstance(techniques, (tuple, list)) or not set(techniques) <= allowed:
        raise ValueError("unknown bound technique")
    work = Work(max_operations, max_entries)
    result = {"bound_available": False, "upper_bound": None, "bounds": {}, "work": {}}
    try:
        domains, tables = compile_tables(problem, work)
        point = partial_point(domains, assignment)
        tables = condition(tables, {i: v for i, v in enumerate(point) if v >= 0}, work)
        independent = math.prod(t.maximum for t in tables)
        result.update(bound_available=True, upper_bound=independent, stop_reason="completed")
        result["bounds"]["independent"] = independent
        for technique in techniques:
            if technique in ("overlap", "adaptive"):
                bound, witness = _tree_bound(tables, work, adaptive=technique == "adaptive")
                result["relaxation_rows"] = [[i, list(row)] for i, row in witness]
            elif technique == "cycles":
                # Conditioning has removed fixed variables; remaining rows
                # still span their complete original coordinate domains.
                bound, cycle = cycle_bound(tables, domains, work)
                result["joined_cycle"] = cycle
            elif technique == "reparameterization":
                bound = reparameterized_bound(tables, work, rounds=rounds)
            else:
                bound = projection_bound(tables, domains, work, modulus=2 if technique == "mod2" else 13)
            if type(bound) is not int or bound < 0:
                raise AssertionError("invalid certified integer bound")
            result["bounds"][technique] = bound
            result["upper_bound"] = min(result["upper_bound"], bound)
    except Limit as exc:
        result["stop_reason"] = str(exc)
    result["work"] = dict(work.counts)
    result["complete"] = result.get("stop_reason") == "completed"
    result["optimality_claimed"] = False
    return result


def threshold_domains(problem, threshold, assignment=None, *, max_operations=2000000, max_entries=100000):
    """Fixed-point domain pruning for a score threshold, retaining equality.

    A value is removed only when the product of its conditional factor maxima
    is strictly below threshold. This is a score exclusion, not a cipher
    contradiction. Work caps return the safely reduced domains already proved.
    """
    if type(threshold) is not int or threshold < 0:
        raise ValueError("threshold must be a nonnegative integer")
    work = Work(max_operations, max_entries)
    result = dict(complete=False, domains=None, threshold=threshold, removed=0)
    try:
        domains, tables = compile_tables(problem, work)
        point = partial_point(domains, assignment)
        allowed = [set(range(d)) if point[i] < 0 else {point[i]} for i, d in enumerate(domains)]
        result["domains"] = [sorted(v) for v in allowed]
        changed = True
        while changed:
            changed = False
            for variable in range(len(domains)):
                for value in sorted(allowed[variable]):
                    work.add("threshold_value_probes")
                    bound = 1
                    for table in tables:
                        maximum = 0
                        for row, score in table.rows:
                            work.add("threshold_factor_rows")
                            if all(a in allowed[v] and (v != variable or a == value) for v, a in zip(table.scope, row)):
                                maximum = max(maximum, score)
                        bound *= maximum
                    if bound < threshold:
                        allowed[variable].remove(value)
                        result["removed"] += 1
                        changed = True
                        result["domains"] = [sorted(v) for v in allowed]
        result.update(complete=True, stop_reason="fixed_point")
    except Limit as exc:
        result["stop_reason"] = str(exc)
    result["work"] = dict(work.counts)
    return result
