"""Necessary equality invariant for the fixed, recorded two-substitution models.

No alphabet/key enumeration or full cipher feasibility test is performed.
Run from the repository root: python research/phase_pair_invariants.py
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("kryptos/data.py", "research/runs/layers-001/results.json",
          "research/phase_pair_invariants.py")
PERIODS = ((3, 2), (2, 3), (10, 8), (8, 10))
ORDERS = ("SST", "STS", "TSS")
OUT = "research/runs/phase-pairs-001/results.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def phase_rows(ciphertext, known, permutation, order, a, b):
    """Rows: [plaintext position, ciphertext position, phase A, phase B, P, C].

    Positions and phases in returned rows are zero-based.
    """
    inverse = [0] * len(permutation)
    for j, i in enumerate(permutation):
        inverse[i] = j
    rows = []
    for i, plain in sorted(known.items()):
        j = inverse[i]
        pa = (j if order == "TSS" else i) % a
        pb = (i if order == "SST" else j) % b
        rows.append([i, j, pa, pb, plain, ciphertext[j]])
    return rows


def inspect_rows(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(row[2:4])].append(row)
    witnesses = []
    repeated_pairs = 0
    for phase in sorted(groups):
        for first, second in combinations(groups[phase], 2):
            repeated_pairs += 1
            if (first[4] == second[4]) != (first[5] == second[5]):
                witnesses.append({
                    "phase_pair_zero_based": list(phase),
                    "plaintext_positions_one_based": [first[0]+1, second[0]+1],
                    "ciphertext_positions_one_based": [first[1]+1, second[1]+1],
                    "plaintext_letters": first[4]+second[4],
                    "ciphertext_letters": first[5]+second[5],
                    "violation": ("equal_plaintext_distinct_ciphertext" if first[4] == second[4]
                                  else "distinct_plaintext_equal_ciphertext"),
                })
    return {"passes_necessary_condition": not witnesses,
            "phase_groups": len(groups),
            "repeated_phase_groups": sum(len(x) > 1 for x in groups.values()),
            "compared_pairs": repeated_pairs, "violating_pairs": len(witnesses),
            "witness": witnesses[0] if witnesses else None}


def independent_rows(ciphertext, known, permutation, order, a, b):
    """Track labeled positions through the literal stage order, independently."""
    tokens = [[i, None, None] for i in range(len(ciphertext))]
    layer = 0
    for operation in order:
        if operation == "T":
            tokens = [tokens[i] for i in permutation]
        else:
            period = (a, b)[layer]
            for position, token in enumerate(tokens):
                token[layer+1] = position % period
            layer += 1
    return sorted([i, j, pa, pb, known[i], ciphertext[j]]
                  for j, (i, pa, pb) in enumerate(tokens) if i in known)


def hand_checks():
    identity = list(range(4))
    assert inspect_rows(phase_rows("XYXY", dict(enumerate("ABAB")), identity,
                                   "SST", 1, 1))["passes_necessary_condition"]
    first = inspect_rows(phase_rows("XYZY", dict(enumerate("ABAB")), identity,
                                   "SST", 1, 1))
    assert first["witness"]["violation"] == "equal_plaintext_distinct_ciphertext"
    second = inspect_rows(phase_rows("XXXX", dict(enumerate("ABAB")), identity,
                                    "SST", 1, 1))
    assert second["witness"]["violation"] == "distinct_plaintext_equal_ciphertext"
    assert inspect_rows([])["passes_necessary_condition"]
    # Non-involutive route: inverse gather must put source 0 at destination 1.
    route = [2, 0, 3, 1]
    assert phase_rows("WXYZ", {0: "A"}, route, "STS", 2, 3) == [[0, 1, 0, 1, "A", "X"]]
    return 5


def main():
    started = datetime.now(timezone.utc).isoformat()
    clock = perf_counter()
    before = {name: digest(ROOT / name) for name in INPUTS}
    values = {}
    tree = ast.parse((ROOT / INPUTS[0]).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ("K4_CIPHERTEXT", "K4_CRIBS"):
                    values[target.id] = ast.literal_eval(node.value)
    ciphertext = values["K4_CIPHERTEXT"]
    known = {}
    for crib in values["K4_CRIBS"]:
        for offset, letter in enumerate(crib["text"]):
            i = crib["start"] - 1 + offset
            assert i not in known or known[i] == letter
            known[i] = letter
    assert len(ciphertext) == 97 and len(known) == 24
    stored = json.loads((ROOT / INPUTS[1]).read_text(encoding="utf-8"))
    assert stored["transposition_convention"] == "T(x)[j]=x[permutation[j]], zero-based"
    source_records = stored["records"]
    assert len(source_records) == 87
    routes, route_ids, seen = [], {}, set()
    records, summaries = [], defaultdict(Counter)
    manual = hand_checks()
    for source in source_records:
        permutation = tuple(x-1 for x in source["source_positions_one_based"])
        assert sorted(permutation) == list(range(97))
        if permutation not in route_ids:
            route_ids[permutation] = len(routes)
            routes.append({"route_id": len(routes), "aliases": source["aliases"],
                           "source_positions_one_based": list(source["source_positions_one_based"])})
        order = source["order"]
        assert order in ORDERS and (permutation, order) not in seen
        seen.add((permutation, order))
        for a, b in PERIODS:
            rows = phase_rows(ciphertext, known, permutation, order, a, b)
            independent = independent_rows(ciphertext, known, permutation, order, a, b)
            assert rows == independent
            result = inspect_rows(rows)
            # Independent ungrouped comparison audits counts and both implications.
            equal_phases = [(x, y) for x, y in combinations(independent, 2) if x[2:4] == y[2:4]]
            violations = [(x, y) for x, y in equal_phases if (x[4] == y[4]) != (x[5] == y[5])]
            assert result["compared_pairs"] == len(equal_phases)
            assert result["violating_pairs"] == len(violations)
            if result["witness"]:
                w = result["witness"]
                assert any([x[0]+1, y[0]+1] == w["plaintext_positions_one_based"] for x, y in violations)
            records.append({"route_id": route_ids[permutation], "order": order,
                            "period_a": a, "period_b": b, **result})
            key = (order, a, b)
            summaries[key]["models"] += 1
            summaries[key]["passed" if result["passes_necessary_condition"] else "rejected"] += 1
    assert len(routes) == 29 and len(records) == 348
    assert all((p, order) in seen for p in route_ids for order in ORDERS)
    after = {name: digest(ROOT / name) for name in INPUTS}
    assert before == after, "Inputs changed during the computation"
    rejected = sum(not r["passes_necessary_condition"] for r in records)
    summary = [{"order": order, "period_a": a, "period_b": b,
                "models": summaries[order, a, b]["models"],
                "passed": summaries[order, a, b]["passed"],
                "rejected": summaries[order, a, b]["rejected"]}
               for a, b in PERIODS for order in ORDERS]
    result = {"base_checkpoint": "K4-20261012-F", "model_count": len(records),
              "rejected": rejected, "passed_necessary_condition": len(records)-rejected,
              "condition": "Same phase pair implies plaintext equality iff ciphertext equality",
              "convention": "T(x)[j]=x[permutation[j]]; internal indices zero-based; witness positions one-based",
              "period_pairs": PERIODS, "inputs": [{"path": n, "sha256_before": before[n],
                                                       "sha256_after": after[n]} for n in INPUTS],
              "run": {"started_at": started, "runtime_seconds": perf_counter()-clock,
                      "python": platform.python_version(), "platform": platform.platform(),
                      "workers": 1, "randomness": False},
              "validation": {"hand_cases": manual, "independent_stage_tracking_models": 348,
                             "independent_pair_count_checks": 348, "inputs_unchanged": True},
              "groups": summary, "routes": routes, "records": records,
              "non_claim": "Passing this necessity does not construct or prove feasibility of any actual layered substitution system."}
    path = ROOT / OUT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, separators=(",", ":"))+"\n", encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["model_count"] == 348
    manifest = {
        "schema_version": 1, "claim_id": "K4-20261012-F-phase-pair-invariants",
        "repository": {"commit": "unavailable (no .git in workspace)", "dirty": True},
        "command": "python research/phase_pair_invariants.py",
        "environment": {"software": ["Python " + platform.python_version()], "hardware": platform.platform()},
        "mathematics": {"assertion_tested": result["condition"], "coefficient_domain": "Exact symbol equality and integer residues",
                        "conventions": result["convention"], "inputs": list(INPUTS),
                        "bounds": {"routes": 29, "orders": 3, "period_pairs": PERIODS, "models": 348, "workers": 1},
                        "non_claims": [result["non_claim"], "No new routes, alphabets, keys, or plaintexts enumerated"]},
        "randomness": {"used": False, "generator": "", "seed": None},
        "run": {"started_at": started, "runtime_seconds": perf_counter()-clock, "exit_status": 0},
        "input_artifacts": result["inputs"],
        "outputs": [{"path": OUT, "sha256": digest(path)}],
        "checks": ["5 hand cases passed", "348 models independently tracked through literal stage orders",
                   "348 ungrouped pair counts agree", "All before/after input hashes agree", "Output JSON read back"],
        "result": f"{rejected}/348 rejected; {348-rejected}/348 pass only the necessary condition",
        "residual_risks": ["No independent author review yet", "No proof of sufficiency for passing models",
                           "Version 1 manifest; before/after hashes additionally recorded in result JSON"]}
    path.with_name("manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"models": 348, "rejected": rejected, "passed_necessity": 348-rejected,
                      "groups": summary, "output": OUT}, indent=2))


if __name__ == "__main__":
    main()
