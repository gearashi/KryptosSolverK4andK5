"""Bounded exact maximization of products of nonnegative integer factors.

For a partial assignment, multiply each factor's maximum over its remaining
local assignments. Ignoring shared-variable consistency can only increase this
upper bound. All score comparisons and bounds are integers; floats are used only
for the optional elapsed-time limit. Ties select the lexicographically smallest
variable assignment, not the lexicographically smallest plaintext.
"""
from collections.abc import Mapping
from dataclasses import dataclass, field
import heapq
from itertools import product
import math
from time import monotonic
from types import MappingProxyType


class FactorBudgetExceeded(ValueError):
    """No factor problem was constructed within its declared table-size cap."""


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


@dataclass(frozen=True)
class IntegerFactor:
    scope: tuple
    values: Mapping
    name: str = ""
    power: int = 1

    def __post_init__(self):
        scope = tuple(self.scope)
        if any(type(i) is not int or i < 0 for i in scope) or tuple(sorted(set(scope))) != scope:
            raise ValueError("factor scope must be distinct sorted nonnegative variable indices")
        if not isinstance(self.values, Mapping):
            raise ValueError("factor values must be a complete tuple-keyed finite table")
        values = dict(self.values)
        if any(not isinstance(key, tuple) or len(key) != len(scope)
               or any(type(i) is not int or i < 0 for i in key)
               or type(value) is not int or value < 0 for key, value in values.items()):
            raise ValueError("factor entries require integer tuples and nonnegative integer scores")
        if not isinstance(self.name, str):
            raise ValueError("factor name must be a string")
        _integer(self.power, "factor power", 1, 4096)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "values", MappingProxyType(values))


@dataclass(frozen=True)
class FactorProblem:
    domains: tuple
    factors: tuple
    metadata: Mapping = field(default_factory=dict)


def _validate(domains, factors):
    if not isinstance(domains, (list, tuple)) or len(domains) > 1024:
        raise ValueError("domains must be at most 1024 finite domain sizes")
    domains = tuple(_integer(v, "domain size", 1, 26) for v in domains)
    if not isinstance(factors, (list, tuple)) or len(factors) > 4096:
        raise ValueError("factors must be a finite list of at most 4096 factors")
    for factor in factors:
        if not isinstance(factor, IntegerFactor) or any(i >= len(domains) for i in factor.scope):
            raise ValueError("factor scope is outside the declared variables")
        expected = math.prod(domains[i] for i in factor.scope)
        if len(factor.values) != expected or any(any(v >= domains[i] for i, v in zip(factor.scope, key)) for key in factor.values):
            raise ValueError("factor table must cover its complete declared Cartesian domain")
    return domains, tuple(factors)


def product_score(domains, factors, assignment):
    """Evaluate the exact objective at one complete assignment."""
    domains, factors = _validate(domains, factors)
    if (not isinstance(assignment, (list, tuple)) or len(assignment) != len(domains)
            or any(type(value) is not int or not 0 <= value < size for value, size in zip(assignment, domains))):
        raise ValueError("assignment does not match finite domains")
    return math.prod(f.values[tuple(assignment[i] for i in f.scope)] ** f.power for f in factors)


def optimize_product(domains, factors, *, max_nodes=100_000, time_limit_seconds=10.0,
                     max_cache_entries=200_000):
    """Best-first exact branch-and-bound with an always valid incumbent/bound.

    A node is a prefix in variable-index order. The node limit counts popped
    nodes. The time limit is checked between complete node expansions; it is a
    cooperative limit, not a hard runtime guarantee. Initial validation/bounds
    are included in elapsed time but must finish before an incumbent is returned.
    An interrupted result can prove the objective optimum while lexicographic
    tie resolution remains unfinished; these statuses are reported separately.
    """
    started = monotonic()
    domains, factors = _validate(domains, factors)
    _integer(max_nodes, "max_nodes", 0, 10_000_000)
    _integer(max_cache_entries, "max_cache_entries", 0, 2_000_000)
    if (isinstance(time_limit_seconds, bool) or not isinstance(time_limit_seconds, (int, float))
            or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 3600):
        raise ValueError("time_limit_seconds must be finite and in (0,3600]")
    caches = [{} for _ in factors]
    cache_count = hits = scans = 0

    def upper(prefix):
        nonlocal cache_count, hits, scans
        value = 1
        for number, factor in enumerate(factors):
            key = tuple(prefix[i] for i in factor.scope if i < len(prefix))
            if key in caches[number]:
                local = caches[number][key]
                hits += 1
            elif len(key) == len(factor.scope):
                local = factor.values[key]
            else:
                local = 0
                for assignment, score in factor.values.items():
                    scans += 1
                    if assignment[:len(key)] == key and score > local:
                        local = score
            if key not in caches[number] and cache_count < max_cache_entries:
                caches[number][key] = local
                cache_count += 1
            value *= local ** factor.power
        return value

    best_assignment = (0,) * len(domains)
    best_score = math.prod(f.values[tuple(best_assignment[i] for i in f.scope)] ** f.power for f in factors)
    initial_upper = upper(())
    frontier = [(-initial_upper, ())]
    nodes = leaves = pruned = 0
    stop_reason = "exhausted"
    while frontier:
        if nodes >= max_nodes:
            stop_reason = "node_budget"
            break
        if monotonic() - started >= time_limit_seconds:
            stop_reason = "time_budget"
            break
        negative_bound, prefix = heapq.heappop(frontier)
        bound = -negative_bound
        nodes += 1
        lex_minimum = prefix + (0,) * (len(domains) - len(prefix))
        if bound < best_score or (bound == best_score and lex_minimum >= best_assignment):
            pruned += 1
            continue
        if len(prefix) == len(domains):
            leaves += 1
            if bound > best_score or (bound == best_score and prefix < best_assignment):
                best_score, best_assignment = bound, prefix
            continue
        for value in range(domains[len(prefix)]):
            child = prefix + (value,)
            child_bound = upper(child)
            child_minimum = child + (0,) * (len(domains) - len(child))
            if child_bound < best_score or (child_bound == best_score and child_minimum >= best_assignment):
                pruned += 1
            else:
                heapq.heappush(frontier, (-child_bound, child))
    remaining_upper = max(best_score, -frontier[0][0] if frontier else best_score)
    tie_proven = not any(-bound >= best_score and prefix + (0,) * (len(domains) - len(prefix)) < best_assignment
                         for bound, prefix in frontier)
    return {"assignment": list(best_assignment), "score": best_score,
            "lower_bound": best_score, "upper_bound": remaining_upper,
            "absolute_gap": remaining_upper - best_score,
            "complete": not frontier, "optimal": remaining_upper == best_score,
            "tie_break_proven": remaining_upper == best_score and tie_proven,
            "stop_reason": stop_reason, "nodes": nodes, "leaf_nodes": leaves,
            "pruned_nodes": pruned, "frontier_nodes": len(frontier),
            "factor_cache_entries": cache_count, "factor_cache_hits": hits,
            "factor_table_entries_scanned": scans,
            "assignment_space_size": math.prod(domains), "factor_count": len(factors),
            "tie_policy": "lexicographically smallest complete variable assignment",
            "bound_method": "product of exact nonnegative integer factor maxima over local completions",
            "bounds": {"max_nodes": max_nodes, "time_limit_seconds": time_limit_seconds,
                       "max_cache_entries": max_cache_entries},
            "runtime_seconds": monotonic() - started}


def ngram_problem(solution, model, excluded_positions=(), *, max_factor_entries=200_000):
    """Turn a generalized affine plaintext family into exact n-gram factors.

    Every window touching a mask is excluded, without concatenating gaps.
    Model alpha uses its stored IEEE value's exact rational p/q. For the fixed
    text length, alphabet and mask, all candidates have the same denominator
    and window count, so maximizing product(count*q+p) is exactly the same
    ordering as the model's mathematical probability (without floating ties).
    Construction refuses the whole problem if its local-table cap is exceeded.
    """
    from .language import CharacterNgramModel
    if not isinstance(model, CharacterNgramModel):
        raise ValueError("model must be a validated CharacterNgramModel from an explicitly supplied corpus")
    _integer(max_factor_entries, "max_factor_entries", 1, 2_000_000)
    affine = solution.affine_plaintext()
    alphabet, base, columns, domains = (affine[k] for k in ("alphabet", "base", "columns", "domains"))
    if set(model.alphabet) != set(alphabet) or model.normalization not in ("identity", "upper-single"):
        raise ValueError("the model must support every fixed shared-alphabet symbol under identity/upper-single normalization")
    mask = tuple(excluded_positions)
    if any(type(i) is not int or not 0 <= i < len(base) for i in mask):
        raise ValueError("excluded positions must be zero-based positions inside the plaintext")
    mask = frozenset(mask)
    windows = [tuple(range(start, start + model.order)) for start in range(len(base) - model.order + 1)
               if not any(i in mask for i in range(start, start + model.order))]
    layouts, total = [], 0
    for window in windows:
        scope = tuple(i for i, column in enumerate(columns) if any(column[position] for position in window))
        entries = math.prod(domains[i] for i in scope)
        total += entries
        if total > max_factor_entries:
            raise FactorBudgetExceeded(f"ngram factor tables require more than {max_factor_entries} entries; no partial problem created")
        layouts.append((window, scope))
    numerator, denominator = float(model.alpha).as_integer_ratio()
    factors = []
    for window, scope in layouts:
        table = {}
        for assignment in product(*(range(domains[i]) for i in scope)):
            gram = "".join(alphabet[(base[position] + sum(columns[i][position] * value for i, value in zip(scope, assignment))) % 26]
                           for position in window)
            table[assignment] = model.counts.get(gram, 0) * denominator + numerator
        factors.append(IntegerFactor(scope, table, "positions:" + ",".join(map(str, window))))
    metadata = {"model_id": model.model_id, "model_label": model.label, "order": model.order,
                "alpha_rational": {"numerator": numerator, "denominator": denominator,
                                   "convention": "exact rational of saved IEEE float, not exact decimal spelling"},
                "excluded_positions": sorted(mask), "window_positions": [list(w) for w in windows],
                "windows": len(windows), "score_available": bool(windows),
                "factor_table_entries": total, "max_factor_entries": max_factor_entries,
                "objective": "product(count*q+p); fixed common probability denominator omitted",
                "comparison_scope": "one fixed model, plaintext family, normalization and mask only",
                "authentication": "not established"}
    return FactorProblem(tuple(domains), tuple(factors), MappingProxyType(metadata))


def optimize_ngrams(solution, model, excluded_positions=(), *, max_factor_entries=200_000,
                    max_nodes=100_000, time_limit_seconds=10.0, max_cache_entries=200_000):
    excluded_positions = tuple(excluded_positions)
    problem = ngram_problem(solution, model, excluded_positions, max_factor_entries=max_factor_entries)
    result = optimize_product(problem.domains, problem.factors, max_nodes=max_nodes,
                              time_limit_seconds=time_limit_seconds, max_cache_entries=max_cache_entries)
    point = result["assignment"]
    candidate = solution.candidate(point[:solution.dimensions_mod2], point[solution.dimensions_mod2:])
    score = model.score(candidate["plaintext"], excluded_positions)
    if score.windows != problem.metadata["windows"]:
        raise AssertionError("n-gram adapter window count differs from model scoring")
    return {"search": result, "scoring": dict(problem.metadata), "candidate": candidate,
            "display_model_score": score.to_dict(), "authenticated_solution": False}
