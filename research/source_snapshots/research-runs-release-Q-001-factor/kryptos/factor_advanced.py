"""Bounded exact algorithms for the existing finite integer-factor domain.

These are alternatives, not a promise that compiling a graph costs less than
searching it. Work includes materialization, planning and repeated queries.
No incomplete result may be used as an exclusion or an optimum certificate.
"""
from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations, product
import heapq
import math


class Limit(Exception):
    pass


class Work:
    def __init__(self, max_operations=2000000, max_entries=100000):
        from .search_runtime import _integer
        self.limit = _integer(max_operations, "max_operations", 1, 10000000)
        self.entry_limit = _integer(max_entries, "max_entries", 1, 1000000)
        self.counts = defaultdict(int)

    def add(self, kind, count=1):
        if self.counts["operations"] + count > self.limit:
            raise Limit("operation_limit")
        if kind == "allocated_entries" and self.counts[kind] + count > self.entry_limit:
            raise Limit("entry_limit")
        self.counts["operations"] += count
        self.counts[kind] += count


@dataclass(frozen=True)
class Table:
    scope: tuple
    rows: tuple

    @property
    def maximum(self):
        return max((v for _, v in self.rows), default=0)


def partial_point(domains, assignment=None):
    point = tuple(-1 for _ in domains) if assignment is None else assignment
    if (not isinstance(point, (list, tuple)) or len(point) != len(domains)
            or any(type(v) is not int or not -1 <= v < d for v, d in zip(point, domains))):
        raise ValueError("invalid partial assignment")
    return tuple(point)


def compile_tables(problem, work):
    """Materialize finite factors, sharing score lookup for equal n-gram images.

    Every coordinate row is still charged. For an affine gram, equal joint
    letter images are scored once rather than treating marginal letters as
    independent. This is useful only when the bounded table fits.
    """
    from .search_runtime import _validate, evaluate_factor
    domains, factors = _validate(problem)
    if len(domains) > 128:
        raise Limit("advanced_variable_limit")
    tables = []
    for f in factors:
        size = math.prod(domains[v] for v in f["scope"])
        work.add("allocated_entries", size)
        rows, images = [], {}
        for values in product(*(range(domains[v]) for v in f["scope"])):
            work.add("materialized_rows")
            if len(factors) == 1 and f["scope"] == list(range(len(domains))):
                work.add("full_objective_table_rows")
            if f["kind"] == "ngram":
                word = tuple((b + sum(col[j] * x for col, x in zip(f["columns"], values))) % 26
                             for j, b in enumerate(f["base"]))
                work.add("joint_image_coordinates", len(values) * len(word))
                if word in images:
                    score = images[word]
                    work.add("joint_image_reuses")
                else:
                    score = evaluate_factor(f, values, domains, problem.get("model"))
                    images[word] = score
                    work.add("factor_evaluations")
            else:
                score = evaluate_factor(f, values, domains, problem.get("model"))
                work.add("factor_evaluations")
            rows.append((values, score ** f.get("power", 1)))
        tables.append(Table(tuple(f["scope"]), tuple(rows)))
    return domains, tuple(tables)


def condition(tables, fixed, work):
    """Exact restriction, with original coordinate labels preserved."""
    output = []
    for table in tables:
        keep = tuple(i for i, v in enumerate(table.scope) if v not in fixed)
        rows = []
        for key, value in table.rows:
            work.add("conditioning_rows")
            if all(key[i] == fixed[v] for i, v in enumerate(table.scope) if v in fixed):
                rows.append((tuple(key[i] for i in keep), value))
        output.append(Table(tuple(table.scope[i] for i in keep), tuple(rows)))
    return tuple(output)


def simplify(tables, work):
    """Remove a coordinate only after every equal-context slice agrees."""
    output, constant = [], 1
    for original in tables:
        table = original
        for variable in tuple(table.scope):
            index = table.scope.index(variable)
            groups, independent = {}, True
            for key, value in table.rows:
                work.add("simplification_rows")
                reduced = key[:index] + key[index + 1:]
                if reduced in groups and groups[reduced] != value:
                    independent = False
                    break
                groups[reduced] = value
            if independent:
                table = Table(table.scope[:index] + table.scope[index + 1:], tuple(sorted(groups.items())))
                work.add("functionally_removed_coordinates")
        if table.scope:
            output.append(table)
        else:
            constant *= table.rows[0][1] if table.rows else 0
    return tuple(sorted(output, key=lambda t: (t.scope, t.rows))), constant


def components(tables, work):
    pending = list(tables)
    result = []
    while pending:
        group = [pending.pop(0)]
        scope = set(group[0].scope)
        changed = True
        while changed:
            changed = False
            rest = []
            for table in pending:
                work.add("component_memberships", max(1, len(table.scope)))
                if scope.intersection(table.scope):
                    scope.update(table.scope)
                    group.append(table)
                    changed = True
                else:
                    rest.append(table)
            pending = rest
        result.append(tuple(group))
    return result


def separator_variable(tables, domains, work):
    """Bounded articulation-oriented variable choice, with measured planning."""
    variables = sorted({v for t in tables for v in t.scope})
    options = []
    for variable in variables:
        stripped = tuple(Table(tuple(v for v in t.scope if v != variable), ())
                         for t in tables if any(v != variable for v in t.scope))
        groups = components(stripped, work)
        sizes = [len({v for t in g for v in t.scope}) for g in groups]
        degree = sum(variable in t.scope for t in tables)
        options.append((max(sizes, default=0), -len(groups), -degree, domains[variable], variable))
    return min(options)[-1]


class ContextSolver:
    """Exact AND/OR search with immutable residual-function messages.

    AND nodes split disconnected factors; OR nodes choose a coordinate. The
    cache key is the complete residual function, so repeated separator queries
    can reuse a proof regardless of the unrelated fixed outside coordinates.
    """
    def __init__(self, problem, *, max_operations=2000000, max_entries=100000,
                 max_cache_entries=10000, ordering="separator"):
        from .search_runtime import _integer
        if ordering not in ("separator", "natural"):
            raise ValueError("ordering must be separator or natural")
        self.work = Work(max_operations, max_entries)
        self.domains, self.tables = compile_tables(problem, self.work)
        self.cache_limit = _integer(max_cache_entries, "max_cache_entries", 0, 100000)
        self.cache = {}
        self.ordering = ordering

    def _solve(self, raw):
        tables, constant = simplify(raw, self.work)
        if not constant:
            return 0, ()
        if not tables:
            return constant, ()
        self.work.add("context_lookups")
        if tables in self.cache:
            self.work.add("context_hits")
            score, witness = self.cache[tables]
            return constant * score, witness
        self.work.add("context_nodes")
        groups = components(tables, self.work)
        if len(groups) > 1:
            self.work.add("and_nodes")
            score, witness = 1, []
            for group in groups:
                value, coordinates = self._solve(group)
                score *= value
                witness.extend(coordinates)
            result = (score, tuple(sorted(witness))) if score else (0, ())
        else:
            self.work.add("branch_decisions")
            variable = (min(v for t in tables for v in t.scope) if self.ordering == "natural"
                        else separator_variable(tables, self.domains, self.work))
            choices = []
            all_variables = sorted({v for t in tables for v in t.scope})
            for value in range(self.domains[variable]):
                score, coordinates = self._solve(condition(tables, {variable: value}, self.work))
                values = dict(coordinates)
                values[variable] = value
                witness = tuple((v, values.get(v, 0)) for v in all_variables)
                choices.append((score, witness))
            result = min(choices, key=lambda row: (-row[0], row[1]))
            if result[0] == 0:
                result = (0, ())
        if len(self.cache) < self.cache_limit:
            self.cache[tables] = result
            self.work.add("context_stores")
        return constant * result[0], result[1]

    def query(self, assignment=None):
        point = partial_point(self.domains, assignment)
        before = dict(self.work.counts)
        try:
            score, values = self._solve(condition(self.tables, {i: v for i, v in enumerate(point) if v >= 0}, self.work))
            answer = [max(0, v) for v in point]
            if score:
                for variable, value in values:
                    answer[variable] = value
            return {"complete": True, "score": score, "assignment": answer,
                    "stop_reason": "exact_context_graph", "query_work": self._delta(before),
                    "work": dict(self.work.counts), "cache_entries": len(self.cache)}
        except Limit as exc:
            return {"complete": False, "score": None, "assignment": None,
                    "stop_reason": str(exc), "query_work": self._delta(before),
                    "work": dict(self.work.counts), "cache_entries": len(self.cache)}

    def _delta(self, before):
        return {k: v - before.get(k, 0) for k, v in self.work.counts.items()}


def plan_elimination(domains, tables, work, *, beam_width=8):
    """Keep several bounded elimination prefixes, minimizing peak row size."""
    from .search_runtime import _integer
    _integer(beam_width, "beam_width", 1, 32)
    scopes = tuple(sorted(set(t.scope for t in tables if t.scope)))
    states = [(0, 0, (), scopes)]
    while states and states[0][3]:
        successors = {}
        for peak, total, order, active in states:
            for variable in sorted({v for s in active for v in s}):
                work.add("order_planning_memberships", len(active))
                joined = set().union(*(set(s) for s in active if variable in s))
                size = math.prod(domains[v] for v in joined)
                remaining = [s for s in active if variable not in s]
                separator = tuple(sorted(joined - {variable}))
                if separator:
                    remaining.append(separator)
                residual = tuple(sorted(set(remaining)))
                candidate = (max(peak, size), total + size, order + (variable,), residual)
                if residual not in successors or candidate < successors[residual]:
                    successors[residual] = candidate
        states = sorted(successors.values())[:beam_width]
    return min(states)[2] if states else ()


def eliminate_tables(domains, tables, work, *, order=None):
    """Exact max-product messages with original-coordinate tie witnesses."""
    tables, constant = simplify(tables, work)
    if not constant:
        return 0, ()
    if order is None:
        order = plan_elimination(domains, tables, work)
    messages = [(t.scope, {row: (value, ()) for row, value in t.rows}) for t in tables]
    for variable in order:
        bucket = [(scope, rows) for scope, rows in messages if variable in scope]
        messages = [(scope, rows) for scope, rows in messages if variable not in scope]
        if not bucket:
            continue
        separator = tuple(sorted(set().union(*(set(scope) for scope, _ in bucket)) - {variable}))
        work.add("allocated_entries", math.prod(domains[v] for v in separator))
        output = {}
        for row in product(*(range(domains[v]) for v in separator)):
            fixed = dict(zip(separator, row))
            best = None
            for value in range(domains[variable]):
                fixed[variable] = value
                score, witness = 1, [(variable, value)]
                for scope, rows in bucket:
                    work.add("message_products")
                    multiplier, prior = rows[tuple(fixed[v] for v in scope)]
                    score *= multiplier
                    witness.extend(prior)
                candidate = score, tuple(sorted(witness))
                if best is None or (-candidate[0], candidate[1]) < (-best[0], best[1]):
                    best = candidate
            if best[0] == 0:
                best = (0, tuple((v, 0) for v, _ in best[1]))
            output[row] = best
        messages.append((separator, output))
        work.add("eliminated_variables")
    score, witness = constant, []
    for scope, rows in messages:
        if scope:
            raise ValueError("elimination order omitted variables")
        value, coordinates = rows[()]
        score *= value
        witness.extend(coordinates)
    return (score, tuple(sorted(witness))) if score else (0, ())


class JunctionQueries:
    """Reusable separator messages for exact conditional max queries.

    A fixed elimination tree is compiled once. Each query caches a subtree
    message by only the evidence intersecting that subtree; outside evidence
    cannot change its conditional function. This is distinct from memoizing
    the complete query result.
    """
    def __init__(self, problem, *, max_operations=2000000, max_entries=100000, beam_width=8):
        self.work = Work(max_operations, max_entries)
        self.domains, self.tables = compile_tables(problem, self.work)
        self.order = plan_elimination(self.domains, self.tables, self.work, beam_width=beam_width)
        rank = {v: i for i, v in enumerate(self.order)}
        self.buckets = {v: [] for v in self.order}
        self.children = {v: [] for v in self.order}
        self.scopes, self.subtrees, self.roots, self.constants = {}, {}, [], []
        for i, table in enumerate(self.tables):
            if table.scope:
                self.buckets[min(table.scope, key=lambda v: rank[v])].append(i)
            else:
                self.constants.append(i)
        for variable in self.order:
            joined = {v for i in self.buckets[variable] for v in self.tables[i].scope}
            subtree = set(joined)
            for child in self.children[variable]:
                joined.update(self.scopes[child])
                subtree.update(self.subtrees[child])
            separator = tuple(sorted(joined - {variable}))
            self.scopes[variable] = separator
            self.subtrees[variable] = frozenset(subtree | {variable})
            if separator:
                self.children[min(separator, key=lambda v: rank[v])].append(variable)
            else:
                self.roots.append(variable)
        self.cache = {}

    def _message(self, variable, point):
        context = tuple((v, point[v]) for v in sorted(self.subtrees[variable]) if point[v] >= 0)
        key = variable, context
        self.work.add("separator_message_lookups")
        if key in self.cache:
            self.work.add("separator_message_hits")
            return self.cache[key]
        children = [(self.scopes[c], self._message(c, point)) for c in self.children[variable]]
        originals = [(self.tables[i].scope, dict(self.tables[i].rows)) for i in self.buckets[variable]]
        separator = self.scopes[variable]
        choices = [range(self.domains[v]) if point[v] < 0 else (point[v],) for v in separator]
        self.work.add("allocated_entries", math.prod(len(c) for c in choices))
        output = {}
        for row in product(*choices):
            filled = dict(zip(separator, row))
            best = None
            for value in range(self.domains[variable]) if point[variable] < 0 else (point[variable],):
                filled[variable] = value
                score, witness = 1, [(variable, value)]
                for scope, table in originals:
                    self.work.add("junction_factor_lookups")
                    score *= table[tuple(filled[v] for v in scope)]
                for scope, table in children:
                    self.work.add("junction_message_products")
                    multiplier, prior = table[tuple(filled[v] for v in scope)]
                    score *= multiplier
                    witness.extend(prior)
                candidate = score, tuple(sorted(witness))
                if best is None or (-candidate[0], candidate[1]) < (-best[0], best[1]):
                    best = candidate
            if best[0] == 0:
                best = 0, tuple((v, max(0, point[v])) for v, _ in best[1])
            output[row] = best
        self.cache[key] = output
        self.work.add("separator_message_stores")
        return output

    def query(self, assignment=None):
        point = partial_point(self.domains, assignment)
        before = dict(self.work.counts)
        try:
            score = math.prod(self.tables[i].rows[0][1] for i in self.constants)
            answer = [max(0, v) for v in point]
            for root in self.roots:
                value, witness = self._message(root, point)[()]
                score *= value
                for v, a in witness:
                    answer[v] = a
            if score == 0:
                answer = [max(0, v) for v in point]
            return dict(complete=True, score=score, assignment=answer, stop_reason="junction_messages",
                        work=dict(self.work.counts), query_work={k: v - before.get(k, 0) for k, v in self.work.counts.items()})
        except Limit as exc:
            return dict(complete=False, score=None, assignment=None, stop_reason=str(exc), work=dict(self.work.counts))


def cutset_solve(problem, assignment=None, *, max_cutset=2, max_operations=2000000, max_entries=100000):
    """Condition a small primal-graph cycle cutset, then use exact messages."""
    from .search_runtime import _integer
    _integer(max_cutset, "max_cutset", 0, 6)
    work = Work(max_operations, max_entries)
    try:
        domains, tables = compile_tables(problem, work)
        point = partial_point(domains, assignment)
        tables = condition(tables, {v: a for v, a in enumerate(point) if a >= 0}, work)
        variables = sorted({v for t in tables for v in t.scope})
        edges = set(pair for t in tables for pair in combinations(t.scope, 2))
        def forest(removed):
            parent = {v: v for v in variables if v not in removed}
            def find(v):
                while parent[v] != v:
                    v = parent[v]
                return v
            for u, v in sorted(edges):
                work.add("cutset_edge_checks")
                if u in removed or v in removed:
                    continue
                a, b = find(u), find(v)
                if a == b:
                    return False
                parent[a] = b
            return True
        cutset = None
        for size in range(min(max_cutset, len(variables)) + 1):
            # Stream a bounded planner: materializing C(128,6) candidates
            # before checking the operation cap would defeat the cap itself.
            preferred = sorted(variables, key=lambda v: (domains[v], v))
            for candidate in combinations(preferred, size):
                work.add("cutset_candidates")
                if forest(set(candidate)):
                    cutset = tuple(sorted(candidate))
                    break
            if cutset is not None:
                break
        if cutset is None:
            return dict(complete=False, score=None, assignment=None, stop_reason="cutset_size_limit", work=dict(work.counts))
        best = None
        for row in product(*(range(domains[v]) for v in cutset)):
            work.add("cutset_assignments")
            fixed = dict(zip(cutset, row))
            score, witness = eliminate_tables(domains, condition(tables, fixed, work), work)
            answer = [max(0, v) for v in point]
            if score:
                for v, a in list(witness) + list(fixed.items()):
                    answer[v] = a
            else:
                for v, a in fixed.items():
                    answer[v] = a
            candidate = score, tuple(answer)
            if best is None or (-score, tuple(answer)) < (-best[0], best[1]):
                best = candidate
        return dict(complete=True, score=best[0], assignment=list(best[1]), cutset=list(cutset),
                    stop_reason="exact_cutset", work=dict(work.counts))
    except Limit as exc:
        return dict(complete=False, score=None, assignment=None, stop_reason=str(exc), work=dict(work.counts))


class DecisionDiagram:
    """Reduced ordered weighted decision diagram of a finite factor function."""
    def __init__(self, problem, *, max_operations=2000000, max_entries=100000):
        self.work = Work(max_operations, max_entries)
        self.domains, tables = compile_tables(problem, self.work)
        self.nodes, self.intern, self.residuals = [], {}, {}
        # A terminal contains the exact suffix score. Nodes retain every level,
        # including irrelevant coordinates, to preserve top-k lexical ties.
        self.root = self._build(0, tables)
        self.best_cache = {}

    def _build(self, level, raw):
        tables, scalar = simplify(raw, self.work)
        key = level, tables, scalar
        self.work.add("diagram_context_lookups")
        if key in self.residuals:
            self.work.add("diagram_context_hits")
            return self.residuals[key]
        if level == len(self.domains):
            node = ("terminal", scalar)
        else:
            self.work.add("diagram_branch_decisions")
            children = tuple(self._build(level + 1, condition(tables, {level: value}, self.work))
                             for value in range(self.domains[level]))
            node = (level, scalar, children)
        if node not in self.intern:
            self.work.add("allocated_entries")
            self.intern[node] = len(self.nodes)
            self.nodes.append(node)
        index = self.intern[node]
        self.residuals[key] = index
        return index

    def _best(self, node_id, point):
        node = self.nodes[node_id]
        if node[0] == "terminal":
            return node[1], ()
        level, scalar, children = node
        context = node_id, point[level:]
        self.work.add("diagram_message_lookups")
        if context in self.best_cache:
            self.work.add("diagram_message_hits")
            return self.best_cache[context]
        choices = []
        for value in range(self.domains[level]) if point[level] < 0 else (point[level],):
            score, suffix = self._best(children[value], point)
            choices.append((scalar * score, (value,) + suffix))
        result = min(choices, key=lambda row: (-row[0], row[1]))
        if result[0] == 0:
            result = 0, tuple(max(0, v) for v in point[level:])
        self.best_cache[context] = result
        return result

    def top_k(self, k=1, assignment=None):
        from .search_runtime import _integer
        _integer(k, "top", 1, 10000)
        point = partial_point(self.domains, assignment)
        before = dict(self.work.counts)
        candidates = []
        try:
            upper, witness = self._best(self.root, point)
            heap = [(-upper, witness, self.root, (), 1)]
            while heap and len(candidates) < k:
                neg, _, node_id, prefix, scalar = heapq.heappop(heap)
                self.work.add("diagram_frontier_pops")
                node = self.nodes[node_id]
                if node[0] == "terminal":
                    candidates.append({"score": -neg, "assignment": list(prefix)})
                    self.work.add("complete_objective_outputs")
                    continue
                level, multiplier, children = node
                for value in range(self.domains[level]) if point[level] < 0 else (point[level],):
                    score, suffix = self._best(children[value], point)
                    total = scalar * multiplier * score
                    start = prefix + (value,)
                    # A zero prefix annihilates all suffix scores. Rank its
                    # completions by the true original-coordinate lexical min.
                    lexical = start + (suffix if total else tuple(max(0, v) for v in point[level + 1:]))
                    heapq.heappush(heap, (-total, lexical, children[value], start, scalar * multiplier))
            return dict(complete=True, candidates=candidates, nodes=len(self.nodes),
                        stop_reason="exact_top_k", work=dict(self.work.counts),
                        query_work={key: value - before.get(key, 0) for key, value in self.work.counts.items()})
        except Limit as exc:
            return dict(complete=False, candidates=candidates, nodes=len(self.nodes),
                        stop_reason=str(exc), work=dict(self.work.counts))


def chain_solve(problem, assignment=None, *, max_width=4, max_operations=2000000, max_entries=100000):
    """Exact natural-order strip DP when every live separator fits max_width."""
    from .search_runtime import _integer
    _integer(max_width, "max_width", 0, 32)
    work = Work(max_operations, max_entries)
    try:
        domains, tables = compile_tables(problem, work)
        point = partial_point(domains, assignment)
        tables = condition(tables, {v: a for v, a in enumerate(point) if a >= 0}, work)
        order = sorted({v for t in tables for v in t.scope})
        scopes = [set(t.scope) for t in tables if t.scope]
        peak = 0
        for v in order:
            work.add("strip_scope_planning", len(scopes))
            joined = set().union(*(s for s in scopes if v in s))
            separator = joined - {v}
            peak = max(peak, len(separator))
            if len(separator) > max_width:
                return dict(complete=False, score=None, assignment=None, stop_reason="strip_width_limit", work=dict(work.counts))
            scopes = [s for s in scopes if v not in s]
            if separator:
                scopes.append(separator)
        score, witness = eliminate_tables(domains, tables, work, order=order)
        answer = [max(0, v) for v in point]
        if score:
            for v, a in witness:
                answer[v] = a
        return dict(complete=True, score=score, assignment=answer, max_separator_width=peak,
                    stop_reason="exact_strip_dp", work=dict(work.counts))
    except Limit as exc:
        return dict(complete=False, score=None, assignment=None, stop_reason=str(exc), work=dict(work.counts))


def run_factor_request(request):
    """JSON-facing bounded dispatch; defaults never enable speculative pruning."""
    if not isinstance(request, dict) or set(request) - {"method", "problem", "problems", "routes", "initial",
            "weights", "allowed", "threshold", "options", "assignments", "top"}:
        raise ValueError("invalid advanced factor request")
    method, problem = request.get("method", "and_or"), request.get("problem")
    options = request.get("options", {})
    assignments = request.get("assignments", [None])
    if not isinstance(options, dict) or not isinstance(assignments, list) or not 1 <= len(assignments) <= 100:
        raise ValueError("options must be an object and assignments must contain 1..100 queries")
    try:
        if method in ("and_or", "junction", "diagram"):
            classes = {"and_or": ContextSolver, "junction": JunctionQueries, "diagram": DecisionDiagram}
            solver = classes[method](problem, **options)
            reports = [solver.top_k(request.get("top", 1), a) if method == "diagram" else solver.query(a) for a in assignments]
            return dict(method=method, reports=reports, work=dict(solver.work.counts))
        if method in ("cutset", "chain"):
            function = cutset_solve if method == "cutset" else chain_solve
            return dict(method=method, reports=[function(problem, a, **options) for a in assignments])
        if method == "search":
            from .search_guidance_q import factor_search
            return factor_search(problem, **options)
        if method == "bounds":
            from .factor_bounds import certified_bounds
            return dict(method=method, reports=[certified_bounds(problem, a, **options) for a in assignments])
        if method == "images":
            from .factor_bounds import reachable_image_upper
            return dict(method=method, reports=[reachable_image_upper(problem, a, **options) for a in assignments])
        if method in ("multiobjective", "hypotheses"):
            from .search_guidance_q import multiobjective_search
            return multiobjective_search(request.get("problems"), aggregate="all" if method == "multiobjective" else "max", **options)
        if method == "neighborhood":
            from .search_guidance_q import neighborhood_seed
            return neighborhood_seed(problem, request.get("initial"), **options)
        if method == "joint_neighborhood":
            from .search_guidance_q import joint_neighborhood
            return joint_neighborhood(request.get("routes"), request.get("initial"), **options)
        if method == "repair":
            from .search_guidance_q import repair_relaxation_witness
            return repair_relaxation_witness(problem, **options)
        if method == "top_k_components":
            from .search_guidance_q import independent_top_k
            return independent_top_k(problem, request.get("top", 10), **options)
        if method == "portfolio":
            from .search_guidance_q import portfolio_search
            return portfolio_search(problem, **options)
        if method == "parallel":
            from .search_guidance_q import parallel_search
            return parallel_search(problem, **options)
        if method == "matching":
            from .factor_bounds import matching_upper
            return matching_upper(request.get("weights"), request.get("allowed"), **options)
        if method == "threshold":
            from .factor_bounds import threshold_domains
            return dict(method=method, reports=[threshold_domains(problem, request.get("threshold"), a, **options) for a in assignments])
        raise ValueError("unknown advanced factor method")
    except Limit as exc:
        return dict(method=method, complete=False, stop_reason=str(exc), reports=[])
