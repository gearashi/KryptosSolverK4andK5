"""Exact broad slot-permutation check on the 348 prespecified layer models."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research.arbitrary_layer_constraints import check_arbitrary_layers, self_test
from research.check_mixed_alphabets import inputs
from research.phase_pair_invariants import independent_rows

PERIODS = ((3, 2), (2, 3), (10, 8), (8, 10))
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def independent_decision(rows):
    """Connect crib observations, not the engine's variables or union-find."""
    adjacency = [set() for _ in rows]
    for i, left in enumerate(rows):
        for j, right in enumerate(rows[:i]):
            if (left[2], left[4]) == (right[2], right[4]) or (left[3], left[5]) == (right[3], right[5]):
                adjacency[i].add(j)
                adjacency[j].add(i)
    unseen, components, conflict = set(range(len(rows))), [], False
    while unseen:
        pending = [min(unseen)]
        group = set(pending)
        unseen.difference_update(group)
        while pending:
            node = pending.pop()
            for neighbor in adjacency[node] & unseen:
                unseen.remove(neighbor)
                group.add(neighbor)
                pending.append(neighbor)
        components.append(group)
        for i in group:
            for j in group:
                l, r = rows[i], rows[j]
                conflict |= (l[2] == r[2] and l[4] != r[4]) or (l[3] == r[3] and l[5] != r[5])
    assert len(components) <= 26  # Every component contains at least one of 24 cribs.
    return not conflict, len(components)


def independent_encrypt(plaintext, maps, order, pi):
    text = plaintext
    slots = iter((maps["a"], maps["b"]))
    for op in order:
        if op == "T":
            text = "".join(text[i] for i in pi)
        else:
            tables = next(slots)
            assert all(len(table) == 26 and set(table) == set(AZ) for table in tables)
            text = "".join(tables[i % len(tables)][AZ.index(symbol)] for i, symbol in enumerate(text))
    return text


def analyze():
    tests = self_test()
    ciphertext, known, prior = inputs()
    previous = json.loads((ROOT / "research/runs/phase-pairs-001/results.json").read_text())
    route_map = {r["route_id"]: tuple(r["source_positions_one_based"]) for r in previous["routes"]}
    weak = {(route_map[r["route_id"]], r["order"], r["period_a"], r["period_b"]): r["passes_necessary_condition"]
            for r in previous["records"]}
    records, summary = [], defaultdict(Counter)
    for row in prior["records"]:
        pi = [i - 1 for i in row["source_positions_one_based"]]
        models = []
        for p, q in PERIODS:
            result = check_arbitrary_layers(ciphertext, known, row["order"], pi, p, q)
            rows = independent_rows(ciphertext, known, pi, row["order"], p, q)
            decision, class_count = independent_decision(rows)
            assert result["feasible"] is decision
            assert result["equivalence_class_count"] == class_count
            pair_pass = weak[tuple(row["source_positions_one_based"]), row["order"], p, q]
            assert not decision or pair_pass
            if decision:
                plain = result["representative_plaintext"]
                assert all(plain[i] == c for i, c in known.items())
                assert independent_encrypt(plain, result["maps"], row["order"], pi) == ciphertext
            group = summary[f"{row['order']}:({p},{q})"]
            group["models"] += 1
            group["fits" if decision else "contradictions"] += 1
            group["additional_contradictions_over_pair_test"] += int(pair_pass and not decision)
            models.append({"period_a": p, "period_b": q, "passes_old_pair_test": pair_pass, "result": result})
        records.append({"aliases": row["aliases"], "order": row["order"],
                        "source_positions_one_based": row["source_positions_one_based"], "models": models})
    positive_controls = 0
    for sample in prior["arbitrary_fit_examples"]:
        row = next(r for r in prior["records"] if r["aliases"] == sample["aliases"] and r["order"] == sample["order"])
        result = check_arbitrary_layers(ciphertext, known, row["order"],
                                        [i - 1 for i in row["source_positions_one_based"]], sample["period_a"], sample["period_b"])
        assert result["feasible"] is True
        positive_controls += 1
    total = sum(g["models"] for g in summary.values())
    assert total == 348 and len(records) == 87 and positive_controls == 5
    return {"checkpoint": "K4-20261012-G", "base_checkpoint": "K4-20261012-F",
            "models": total, "fits": sum(g["fits"] for g in summary.values()),
            "contradictions": sum(g["contradictions"] for g in summary.values()),
            "additional_contradictions_over_pair_test": sum(g["additional_contradictions_over_pair_test"] for g in summary.values()),
            "independent_observation_graph_checks": total, "previous_positive_controls": positive_controls,
            "self_tests": tests, "summary": dict(summary), "records": records,
            "scope": "Arbitrary independent bijective substitution maps per key phase, 29 fixed routes, 3 layer placements, 4 declared period pairs, 24 literal crib letters.",
            "non_claims": ["Fits do not establish additive shifts or a shared keyed alphabet", "Completed maps and plaintexts are arbitrary representatives", "No language/semantic ranking or authentic decipherment", "No arbitrary-transposition or period exclusion"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh output path.")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("models", "fits", "contradictions", "additional_contradictions_over_pair_test", "independent_observation_graph_checks", "previous_positive_controls")}))
