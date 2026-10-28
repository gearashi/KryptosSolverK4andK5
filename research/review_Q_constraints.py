"""Independent literal top-k / learned-clause review of the finite relation engine."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.constraint_lab import RelationSearch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("Preserve earlier review outputs")
    inputs = ["kryptos/constraint_lab.py", "kryptos/constraint_reuse.py", "research/review_Q_constraints.py"]
    hashes = lambda: {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in inputs}
    before = hashes()
    rng = random.Random(316128)
    cases = []
    for case in range(200):
        names = ["a", "b", "c", "d"]
        domains = {v: [0, 1] for v in names}
        relations = []
        for _ in range(3):
            scope = sorted(rng.sample(names, rng.randrange(1, 4)))
            rows = [list(row) for row in itertools.product(range(2), repeat=len(scope)) if rng.randrange(3)]
            relations.append(dict(scope=scope, rows=rows))
        factors = []
        for _ in range(2):
            scope = sorted(rng.sample(names, 2))
            factors.append(dict(scope=scope, rows=[list(row)+[rng.randrange(5)]
                for row in itertools.product(range(2), repeat=2)], default=0))
        expected = []
        for point in itertools.product(range(2), repeat=4):
            assignment = dict(zip(names, point))
            if all([assignment[v] for v in relation["scope"]] in relation["rows"] for relation in relations):
                score = sum(next((row[-1] for row in factor["rows"]
                    if row[:-1] == [assignment[v] for v in factor["scope"]]), factor["default"]) for factor in factors)
                expected.append((score, point))
        expected.sort(key=lambda row: (-row[0], row[1]))
        for propagation in (False, True):
            request = dict(domains=domains, relations=relations, factors=factors, top=4,
                options=dict(propagation=propagation, learning=True, minimize_conflicts=True,
                    backjump=True, probing=True, memoize=True, score_exclusions=True, isomorphic_cache=True))
            engine = RelationSearch(request)
            result = engine.run()
            actual = [(row["score"], tuple(row["assignment"][v] for v in names)) for row in result["candidates"]]
            assert result["complete"] and actual == expected[:4], (case, propagation, actual, expected)
            for clause in engine.nogoods:
                assert not any(all(dict(zip(names, point))[v] == value for v, value in clause)
                               for _, point in expected), (case, clause)
            cases.append(dict(case=case, propagation=propagation, feasible_assignments=len(expected),
                              checked_exported_nogoods=len(engine.nogoods), top_k_matches=True))
    after = hashes()
    record = dict(schema="kryptos.Q-independent-constraint-review.v1", seed=316128,
        generator="random.Random", comparisons=len(cases), literal_assignments_per_case=16,
        status="completed" if before == after else "inputs-changed", inputs_before=before, inputs_after=after,
        python=sys.version, cases=cases,
        assertion_tested="Top4 equals direct Cartesian relation membership and literal factor-sum arithmetic; every exported nogood excludes no feasible assignment",
        limits="200 authored random binary models, all feature switches together, propagation on/off. Not all configurations, product objectives, imported proofs or unbounded models.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: record[k] for k in ("comparisons", "status", "seed")}))
    if before != after:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
