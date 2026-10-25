"""Exact bounded max-product elimination on residual factor components.

Each message stores its best product and the mixed-radix lexical cost of its
eliminated coordinates. Eliminated subtrees are disjoint, so costs add. A zero
global maximum means every completion scores zero: return the original-space
lexical minimum, not arbitrary back-pointers from positive subproblems.
"""
from itertools import product
import math
import time


class _Stop(Exception):
    pass


def mini_bucket_upper(problem, assignment=None, *, bucket_entries=256,
                      max_entries=20000, max_operations=200000):
    """Deterministic bounded relaxation of nonnegative max-product elimination.

    Split an overlarge elimination bucket into smaller groups. For each fixed
    separator assignment, max_x(prod_g F_g(x)) <= prod_g(max_x F_g(x)).
    Repeating this inequality gives an admissible upper bound, including zeros
    and powered factors. No witness or lexical optimum follows from the bound.
    A resource cutoff returns None, so callers retain their previous bound.
    Caps are deterministic (no wall clock), allowing checkpoint reconstruction.
    """
    from .search_runtime import _integer, _validate, evaluate_factor
    domains, factors = _validate(problem)
    _integer(bucket_entries, "elimination_bucket_entries", 1, 100000)
    _integer(max_entries, "elimination_max_entries", 1, 1000000)
    _integer(max_operations, "elimination_max_operations", 1, 10000000)
    point = tuple(-1 for _ in domains) if assignment is None else assignment
    if not isinstance(point, (tuple, list)) or len(point) != len(domains) or any(type(v) is not int or not -1 <= v < d for v, d in zip(point, domains)):
        raise ValueError("invalid residual assignment")
    work = dict(operations=0, factor_evaluations=0, product_multiplications=0,
                planning_operations=0, allocated_entries=0, split_buckets=0,
                eliminated_variables=0, max_bucket_entries=0)

    def tick(kind, count=1):
        if work["operations"] + count > max_operations:
            raise _Stop("operation_limit")
        work["operations"] += count
        work[kind] += count

    def size(scope):
        return math.prod(domains[v] for v in scope)

    def reserve(count):
        if count > bucket_entries:
            raise _Stop("bucket_entry_limit")
        if work["allocated_entries"] + count > max_entries:
            raise _Stop("entry_limit")
        work["allocated_entries"] += count

    try:
        tables = []
        for f in factors:
            scope = tuple(v for v in f["scope"] if point[v] < 0)
            reserve(size(scope))
            values = {}
            for row in product(*(range(domains[v]) for v in scope)):
                tick("factor_evaluations")
                filled = dict(zip(scope, row))
                value = evaluate_factor(f, tuple(filled[v] if point[v] < 0 else point[v] for v in f["scope"]), domains, problem.get("model"))
                values[row] = value ** f.get("power", 1)
            tables.append((scope, values))
        for variable in sorted({v for scope, _ in tables for v in scope}):
            bucket, rest = [], []
            for table in tables:
                tick("planning_operations")
                (bucket if variable in table[0] else rest).append(table)
            groups = []
            for table in bucket:
                placed = False
                for joined, items in groups:
                    tick("planning_operations")
                    union = joined | set(table[0])
                    if size(union) <= bucket_entries:
                        joined.update(table[0])
                        items.append(table)
                        placed = True
                        break
                if not placed:
                    groups.append((set(table[0]), [table]))
            if len(groups) > 1:
                work["split_buckets"] += 1
            for joined, items in groups:
                work["max_bucket_entries"] = max(work["max_bucket_entries"], size(joined))
                separator = tuple(sorted(joined - {variable}))
                reserve(size(separator))
                output = {}
                for row in product(*(range(domains[v]) for v in separator)):
                    filled = dict(zip(separator, row))
                    best = 0
                    for value in range(domains[variable]):
                        filled[variable] = value
                        score = 1
                        for scope, table in items:
                            tick("product_multiplications")
                            score *= table[tuple(filled[v] for v in scope)]
                        best = max(best, score)
                    output[row] = best
                rest.append((separator, output))
            tables = rest
            work["eliminated_variables"] += 1
        upper = 1
        for scope, table in tables:
            assert not scope
            tick("product_multiplications")
            upper *= table[()]
        return dict(bound_available=True, upper_bound=upper, stop_reason="bounded_elimination", work=work)
    except _Stop as exc:
        return dict(bound_available=False, upper_bound=None, stop_reason=str(exc), work=work)


def exact_decomposition(problem, assignment=None, *, max_entries=20000,
                        max_operations=200000, time_limit_seconds=5):
    """Solve one residual domain, or return inconclusive without exclusions.

    The entry cap bounds cumulative allocated factor/message rows. Operations
    count planning memberships, factor values, and message row products.
    Greedy minimum-bucket-cardinality ordering exploits small separators;
    it does not promise minimum treewidth. Input state is never modified.
    """
    from .search_runtime import _integer, _validate, evaluate_factor
    domains, factors = _validate(problem)
    _integer(max_entries, "decomposition_max_entries", 1, 1000000)
    _integer(max_operations, "decomposition_max_operations", 1, 10000000)
    if type(time_limit_seconds) not in (int, float) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time_limit_seconds must be in (0,600]")
    point = tuple(-1 for _ in domains) if assignment is None else assignment
    if not isinstance(point, (tuple, list)) or len(point) != len(domains) or any(type(v) is not int or not -1 <= v < d for v, d in zip(point, domains)):
        raise ValueError("invalid residual assignment")
    point = tuple(point)
    started = time.monotonic()
    work = {"operations": 0, "planning_operations": 0, "factor_evaluations": 0,
            "product_multiplications": 0, "allocated_entries": 0,
            "planned_entries": 0, "components": 0, "eliminated_variables": 0,
            "max_separator_variables": 0, "max_bucket_entries": 0}

    def tick(kind, count=1):
        if time.monotonic() - started >= time_limit_seconds:
            raise _Stop("time_limit")
        if work["operations"] + count > max_operations:
            raise _Stop("operation_limit")
        work["operations"] += count
        work[kind] += count

    def reserve(count, planned=False):
        field = "planned_entries" if planned else "allocated_entries"
        if work[field] + count > max_entries:
            raise _Stop("entry_limit")
        work[field] += count

    def finish(complete, reason, answer=None, score=None):
        return {"method": "component_separator_max_product_elimination", "complete": complete,
                "stop_reason": reason, "assignment": list(answer) if answer is not None else None,
                "score": score, "work": work, "runtime_seconds": time.monotonic() - started,
                "bounds": {"max_entries": max_entries, "max_operations": max_operations,
                           "time_limit_seconds": time_limit_seconds},
                "interpretation": "Exact score and original-coordinate lexical optimum only when complete; a resource cutoff makes no exclusion."}

    minimum = tuple(max(0, value) for value in point)
    scopes = {number: frozenset(v for v in f["scope"] if point[v] < 0)
              for number, f in enumerate(factors)}
    try:
        # Constants are checked before planning. One zero factor proves that
        # every remaining completion has zero score, regardless of topology.
        constants, active = {}, {}
        for number, scope in scopes.items():
            if scope:
                active[number] = scope
            else:
                tick("factor_evaluations")
                f = factors[number]
                constants[number] = evaluate_factor(f, tuple(point[v] for v in f["scope"]), domains, problem.get("model")) ** f.get("power", 1)
                if constants[number] == 0:
                    return finish(True, "constant_zero", minimum, 0)
        parent = {}
        def find(v):
            while parent[v] != v:
                parent[v] = parent[parent[v]]
                v = parent[v]
            return v
        for scope in active.values():
            ordered = sorted(scope)
            for v in ordered:
                tick("planning_operations")
                parent.setdefault(v, v)
                parent[find(v)] = find(ordered[0])
        work["components"] = len({find(v) for v in parent})
        for scope in scopes.values():
            reserve(math.prod(domains[v] for v in scope), planned=True)
        # Plan all intermediate scopes before allocating any nonconstant table.
        plans = []
        next_id = len(factors)
        while active:
            adjacency = {}
            for number, scope in active.items():
                for v in scope:
                    tick("planning_operations")
                    adjacency.setdefault(v, []).append(number)
            choices = []
            for v, bucket in adjacency.items():
                joined = set()
                for number in bucket:
                    tick("planning_operations", len(active[number]))
                    joined.update(active[number])
                size = math.prod(domains[i] for i in joined)
                choices.append((size, len(joined), v, tuple(sorted(joined)), tuple(bucket)))
            size, _, variable, joined, bucket = min(choices)
            separator = tuple(v for v in joined if v != variable)
            reserve(math.prod(domains[v] for v in separator), planned=True)
            work["max_separator_variables"] = max(work["max_separator_variables"], len(separator))
            work["max_bucket_entries"] = max(work["max_bucket_entries"], size)
            plans.append((variable, separator, bucket, next_id))
            for number in bucket:
                del active[number]
            if separator:
                active[next_id] = frozenset(separator)
            next_id += 1
        weights = [1] * len(domains)
        for i in range(len(domains) - 2, -1, -1):
            weights[i] = weights[i + 1] * domains[i + 1]
        tables = {}
        for number, f in enumerate(factors):
            scope = tuple(sorted(scopes[number]))
            values = {}
            reserve(math.prod(domains[v] for v in scope))
            if not scope:
                values[()] = (constants[number], 0)
            else:
                for row in product(*(range(domains[v]) for v in scope)):
                    tick("factor_evaluations")
                    filled = dict(zip(scope, row))
                    raw = evaluate_factor(f, tuple(filled[v] if point[v] < 0 else point[v] for v in f["scope"]), domains, problem.get("model"))
                    values[row] = (raw ** f.get("power", 1), 0)
            tables[number] = (scope, values)
        for variable, separator, bucket, number in plans:
            reserve(math.prod(domains[v] for v in separator))
            output = {}
            for row in product(*(range(domains[v]) for v in separator)):
                filled = dict(zip(separator, row))
                best_score, best_cost = -1, None
                for value in range(domains[variable]):
                    filled[variable] = value
                    score, cost = 1, value * weights[variable]
                    for item in bucket:
                        tick("product_multiplications")
                        scope, table = tables[item]
                        multiplier, child_cost = table[tuple(filled[v] for v in scope)]
                        score *= multiplier
                        cost += child_cost
                    if score > best_score or (score == best_score and cost < best_cost):
                        best_score, best_cost = score, cost
                # Nonnegative objective: a conditional maximum of zero means
                # all its eliminated coordinates may take their minimum0.
                output[row] = (best_score, best_cost if best_score else 0)
            for item in bucket:
                del tables[item]
            tables[number] = (separator, output)
            work["eliminated_variables"] += 1
        final_score, final_cost = 1, sum(v * weights[i] for i, v in enumerate(point) if v >= 0)
        for scope, table in tables.values():
            assert not scope
            tick("product_multiplications")
            score, cost = table[()]
            final_score *= score
            final_cost += cost
        answer = minimum if final_score == 0 else tuple((final_cost // weights[i]) % domains[i] for i in range(len(domains)))
        return finish(True, "exact_elimination", answer, final_score)
    except _Stop as exc:
        return finish(False, str(exc))
