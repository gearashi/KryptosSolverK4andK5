"""Fixed correlated-window discriminator; no K4 search or source mutation."""
import argparse
from hashlib import sha256
import heapq
import itertools
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.correlated_bound import CorrelatedNgramBound
from kryptos.search_runtime import _Evaluator

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
INPUT_PATHS = ("research/correlated_bound_benchmark.py", "kryptos/correlated_bound.py", "kryptos/search_runtime.py")


def branch(bound, domains, literal_score):
    best = tuple(0 for _ in domains)
    score = literal_score(best)
    heap = [(-bound(tuple(-1 for _ in domains)), tuple(-1 for _ in domains))]
    expanded = bound_calls = 1
    while heap:
        neg, point = heapq.heappop(heap)
        if -neg < score or (-neg == score and tuple(max(0, v) for v in point) >= best):
            continue
        if -1 not in point:
            actual = literal_score(point)
            assert actual == -neg
            if actual > score or (actual == score and point < best):
                best, score = point, actual
            continue
        variable = point.index(-1)
        expanded += 1
        for value in range(domains[variable]):
            child = point[:variable] + (value,) + point[variable + 1:]
            heapq.heappush(heap, (-bound(child), child))
            bound_calls += 1
    return {"best": list(best), "score": score, "partial_nodes_expanded_including_root_setup": expanded,
            "bound_calls": bound_calls}


def run():
    before = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUT_PATHS}
    started = perf_counter()
    counts = {"AB": 1000, "CC": 5, "DQ": 9}
    domains, base, columns = [2, 26], [0, 0], [[0, 13], [1, 1]]
    model = {"alphabet": A, "counts": counts, "p": 1, "q": 10, "order": 2, "id": "fixed-correlated-window"}
    problem = {"schema": "kryptos.lazy-product.v1", "domains": domains,
               "factors": [{"kind": "ngram", "scope": [0, 1], "base": base, "columns": columns}], "model": model}
    original = _Evaluator(problem, 0, 1)
    helper = CorrelatedNgramBound(A, counts, 1, 10)
    def literal_score(point):
        gram = A[point[1]] + A[(point[1] + 13 * point[0]) % 26]
        return counts.get(gram, 0) * 10 + 1
    work = {"observed_grams_checked": 0, "basis_row_reductions": 0}
    def correlated(point):
        result = helper.upper(base, columns, domains, point)
        assert result["applicable"]
        for name in work:
            work[name] += result[name]
        return result["upper"]
    rows = []
    for point in itertools.product(range(-1, 2), range(-1, 26)):
        completions = itertools.product(*(range(d) if v < 0 else (v,) for d, v in zip(domains, point)))
        brute = max(literal_score(x) for x in completions)
        old, new = original.upper(point), correlated(point)
        assert old >= brute and new == brute and new <= old
        rows.append({"partial_assignment": list(point), "exact": brute, "independent_letter_upper": old, "correlated_upper": new})
    old_search = branch(original.upper, domains, literal_score)
    new_search = branch(correlated, domains, literal_score)
    assert old_search["best"] == new_search["best"] == [1, 3]
    assert old_search["score"] == new_search["score"] == 91
    assert new_search["bound_calls"] < old_search["bound_calls"]
    after = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUT_PATHS}
    assert before == after
    return {"schema": "kryptos.correlated-bound-discriminator.v1", "problem": problem,
            "partials": rows, "partial_assignments_checked": len(rows),
            "strictly_tighter_bounds": sum(r["correlated_upper"] < r["independent_letter_upper"] for r in rows),
            "old_branch": old_search, "correlated_branch": new_search, "correlated_work": work,
            "input_sha256_before": before, "input_sha256_after": after, "elapsed_seconds": perf_counter() - started,
            "limits": "One fixed 52-point family and all81partial assignments. Separate tiny branch harness, not an integrated runtime speed benchmark. No K4 claim."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh result path")
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ("partial_assignments_checked", "strictly_tighter_bounds", "old_branch", "correlated_branch", "elapsed_seconds")}))
