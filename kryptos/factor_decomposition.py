"""Exact bounded max-product elimination on residual factor components.

Each message stores its best product and the mixed-radix lexical cost of its
eliminated coordinates. Eliminated subtrees are disjoint, so costs add. A zero
global maximum means every completion scores zero: return the original-space
lexical minimum, not arbitrary back-pointers from positive subproblems.
"""
from itertools import product
import math
import time
from types import MappingProxyType


class _Stop(Exception):
    pass


class ResidualComponentCache:
    """Invocation-local exact component optima, with a frozen objective.

    A key names original factors, remaining variables and every fixed boundary
    coordinate. It deliberately does not identify isomorphic or merely similar
    components. Completed zero maxima are score facts, never infeasibility.
    Caches are disposable and never imported from a checkpoint.
    """
    def __init__(self, problem, *, max_entries=256, max_assignments=256,
                 max_operations=200000):
        from .search_runtime import _integer, _validate
        self.domains, factors = _validate(problem)
        self.max_entries = _integer(max_entries, "residual_cache_max_entries", 0, 10000)
        self.max_assignments = _integer(max_assignments, "residual_cache_max_assignments", 1, 100000)
        self.max_operations = _integer(max_operations, "residual_cache_max_operations", 1, 10000000)
        # No mutable caller-owned factor/model data remains reachable here.
        snapshot_items = 0
        def freeze(value):
            nonlocal snapshot_items
            snapshot_items += 1
            if isinstance(value, dict):
                return MappingProxyType({k: freeze(v) for k, v in value.items()})
            if isinstance(value, list):
                return tuple(freeze(v) for v in value)
            return value
        self.factors = tuple(freeze(f) for f in factors)
        self.model = freeze(problem.get("model"))
        self.cache = {}
        self.stats = dict(calls=0, operations=0, planning_operations=0,
                          objective_snapshot_items=snapshot_items,
                          factor_evaluations=0, witness_factor_evaluations=0,
                          enumerated_assignments=0, cache_lookups=0, cache_hits=0,
                          cache_stores=0, cache_capacity_skips=0, cache_invalidations=0,
                          components_over_cap=0, complete_residuals=0,
                          zero_score_residuals=0, budget_fallbacks=0)

    def solve(self, assignment, *, time_limit_seconds=5):
        from .search_runtime import evaluate_factor
        if (not isinstance(assignment, (tuple, list)) or len(assignment) != len(self.domains)
                or any(type(v) is not int or not -1 <= v < d for v, d in zip(assignment, self.domains))):
            raise ValueError("invalid residual assignment")
        if type(time_limit_seconds) not in (int, float) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
            raise ValueError("residual time limit must be in (0,600]")
        point = tuple(assignment)
        minimum = tuple(max(0, v) for v in point)
        started = time.monotonic()
        self.stats["calls"] += 1

        def tick(field, count=1):
            if time.monotonic() - started >= time_limit_seconds:
                raise _Stop("time_limit")
            if self.stats["operations"] + count > self.max_operations:
                raise _Stop("operation_limit")
            self.stats["operations"] += count
            self.stats[field] += count

        def score(ids, values, verification=False):
            result = 1
            for number in ids:
                tick("witness_factor_evaluations" if verification else "factor_evaluations")
                factor = self.factors[number]
                result *= evaluate_factor(factor, tuple(values[v] for v in factor["scope"]),
                                          self.domains, self.model) ** factor.get("power", 1)
            return result

        def finish(complete, reason, answer=None, value=None):
            if complete:
                self.stats["complete_residuals"] += 1
                self.stats["zero_score_residuals"] += int(value == 0)
            return dict(complete=complete, stop_reason=reason,
                        assignment=list(answer) if answer is not None else None, score=value)

        try:
            active, constants, parent = [], [], {}
            def find(v):
                while parent[v] != v:
                    parent[v] = parent[parent[v]]
                    v = parent[v]
                return v
            for number, factor in enumerate(self.factors):
                tick("planning_operations", 1 + len(factor["scope"]))
                free = tuple(v for v in factor["scope"] if point[v] < 0)
                if not free:
                    constants.append(number)
                    continue
                active.append((number, free))
                for v in free:
                    parent.setdefault(v, v)
                    parent[find(v)] = find(free[0])
            constant = score(constants, point)
            if constant == 0:
                return finish(True, "constant_zero_score", minimum, 0)
            components = {}
            for number, free in active:
                tick("planning_operations")
                components.setdefault(find(free[0]), []).append(number)
            answer, value, skipped = list(minimum), constant, False
            for ids in sorted(components.values(), key=lambda group: tuple(group)):
                scope = tuple(sorted({v for number in ids for v in self.factors[number]["scope"]}))
                variables = tuple(v for v in scope if point[v] < 0)
                tick("planning_operations", len(scope) + len(ids))
                size = math.prod(self.domains[v] for v in variables)
                if size > self.max_assignments:
                    self.stats["components_over_cap"] += 1
                    skipped = True
                    continue
                key = (tuple(ids), tuple((v, self.domains[v]) for v in variables),
                       tuple((v, point[v]) for v in scope if point[v] >= 0))
                tick("cache_lookups")
                cached = self.cache.get(key)
                if cached is not None:
                    self.stats["cache_hits"] += 1
                    best, witness = cached
                else:
                    best, witness = -1, None
                    completed = list(point)
                    for values in product(*(range(self.domains[v]) for v in variables)):
                        for v, a in zip(variables, values):
                            completed[v] = a
                        tick("enumerated_assignments")
                        current = score(ids, completed)
                        # product() visits original-variable lexical order.
                        if current > best:
                            best, witness = current, values
                if (type(best) is not int or best < 0 or not isinstance(witness, tuple)
                        or len(witness) != len(variables)
                        or any(type(a) is not int or not 0 <= a < self.domains[v] for v, a in zip(variables, witness))):
                    self.cache.pop(key, None)
                    self.stats["cache_invalidations"] += 1
                    raise AssertionError("invalid cached component witness")
                completed = list(point)
                for v, a in zip(variables, witness):
                    completed[v] = a
                # Always verify, including hits, against the frozen original
                # factors. Never use another cached score for this check.
                if score(ids, completed, verification=True) != best:
                    self.cache.pop(key, None)
                    self.stats["cache_invalidations"] += 1
                    raise AssertionError("component witness failed original-factor verification")
                if cached is None:
                    if len(self.cache) < self.max_entries:
                        self.cache[key] = (best, witness)
                        self.stats["cache_stores"] += 1
                    else:
                        self.stats["cache_capacity_skips"] += 1
                if best == 0:
                    # One independently zero component makes every full
                    # completion zero, including lexically smaller nonoptima
                    # of the other components.
                    return finish(True, "component_zero_score", minimum, 0)
                value *= best
                for v, a in zip(variables, witness):
                    answer[v] = a
            if skipped:
                return finish(False, "component_assignment_limit")
            return finish(True, "exact_components", answer, value)
        except _Stop as error:
            self.stats["budget_fallbacks"] += 1
            return finish(False, str(error))


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
