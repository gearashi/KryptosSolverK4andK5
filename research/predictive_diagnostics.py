"""Exact predictive coverage of already-recorded shared-alphabet crib fits.

Reads the 1,018 feasible checkpoint-D models; searches no new model or key.
Known phrases are also withheld retrospectively, after model selection using
all 24 letters. That exercise is not independent validation.

Run: python research/predictive_diagnostics.py --output PATH
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
HOLDS = {"EASTNORTHEAST": list(range(21, 34)), "BERLINCLOCK": list(range(63, 74))}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_literals(path):
    values = {}
    for statement in ast.parse(path.read_text(encoding="utf-8-sig")).body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in ("K4_CIPHERTEXT", "K4_CRIBS"):
                    values[target.id] = ast.literal_eval(statement.value)
    ciphertext, cribs = values["K4_CIPHERTEXT"], values["K4_CRIBS"]
    assert len(ciphertext) == 97
    known = {}
    for crib in cribs:
        for offset, symbol in enumerate(crib["text"]):
            i = crib["start"] - 1 + offset
            assert i not in known or known[i] == symbol
            known[i] = symbol
    assert len(known) == 24
    for phrase, positions in HOLDS.items():
        assert "".join(known[i] for i in positions) == phrase
    assert set(known) == set(HOLDS["EASTNORTHEAST"]) | set(HOLDS["BERLINCLOCK"])
    return ciphertext, cribs, known


def phases(i, j, order, a, b):
    if order == "SST":
        return i % a, i % b
    if order == "STS":
        return i % a, j % b
    if order == "TSS":
        return j % a, j % b
    raise ValueError("unknown layer order")


def graph_state(ciphertext, known, alphabet, inverse, order, a, b):
    """One weighted component reconstruction; unused key slots stay isolated."""
    index = {symbol: value for value, symbol in enumerate(alphabet)}
    adjacency = [[] for _ in range(a + b)]
    for i, plain in sorted(known.items()):
        j = inverse[i]
        u, v = phases(i, j, order, a, b)
        v += a
        residue = (index[ciphertext[j]] - index[plain]) % 26
        # h(A)-h(B)=residue, where h(A)=a_key and h(B)=-b_key.
        adjacency[u].append((v, -residue))
        adjacency[v].append((u, residue))
    components, potential = [-1] * (a + b), [None] * (a + b)
    count = 0
    for root in range(a + b):
        if potential[root] is not None:
            continue
        potential[root], components[root] = 0, count
        count += 1
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for neighbor, difference in adjacency[node]:
                value = (potential[node] + difference) % 26
                if potential[neighbor] is None:
                    potential[neighbor], components[neighbor] = value, components[root]
                    queue.append(neighbor)
                elif potential[neighbor] != value:
                    raise ValueError("stored feasible model contradicts its supplied training cribs")
    return components, potential, count


def prediction_mask(ciphertext, positions, alphabet, inverse, order, a, b, state):
    components, potential, _ = state
    index = {symbol: value for value, symbol in enumerate(alphabet)}
    symbols, forced_positions = [], []
    for i in positions:
        j = inverse[i]
        u, v = phases(i, j, order, a, b)
        v += a
        if components[u] == components[v]:
            symbols.append(alphabet[(index[ciphertext[j]] - potential[u] + potential[v]) % 26])
            forced_positions.append(i + 1)
        else:
            symbols.append("?")
    return "".join(symbols), forced_positions


def self_test():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext, inverse = "DKSHQQ", [0, 3, 1, 2, 5, 4]
    known = {0: "A", 1: "B", 3: "D"}
    state = graph_state(ciphertext, known, alphabet, inverse, "STS", 2, 3)
    mask, positions = prediction_mask(ciphertext, [2, 4, 5], alphabet, inverse, "STS", 2, 3, state)
    assert mask == "?E?" and positions == [5]
    full = graph_state(ciphertext, dict(enumerate("ABCDEF")), alphabet, inverse, "STS", 2, 3)
    assert prediction_mask(ciphertext, range(6), alphabet, inverse, "STS", 2, 3, full)[0] == "ABCDEF"
    # The unconnected B slot can shift freely, producing every possible letter.
    components, potential, _ = state
    i, j = 2, inverse[2]
    u, v = phases(i, j, "STS", 2, 3)
    v += 2
    assert components[u] != components[v]
    domain = {alphabet[(alphabet.index(ciphertext[j]) - potential[u] + potential[v] + shift) % 26]
              for shift in range(26)}
    assert domain == set(alphabet)
    # Empty training constraints leave all A/B vertices in different components.
    empty = graph_state(ciphertext, {}, alphabet, inverse, "STS", 2, 3)
    assert prediction_mask(ciphertext, range(6), alphabet, inverse, "STS", 2, 3, empty)[0] == "??????"
    return {"passed_cases": 4, "scope": "forced partial prediction, full prediction, exact 26-symbol marginal, empty training"}


def analyze():
    started = datetime.now(timezone.utc).isoformat()
    timer = time.perf_counter()
    names = ["kryptos/data.py", "research/predictive_diagnostics.py",
             "research/runs/layers-001/results.json", "research/runs/layers-001/manifest.json"]
    paths = {name: ROOT / name for name in names}
    before = {name: digest(path) for name, path in paths.items()}
    manifest = json.loads(paths[names[3]].read_text(encoding="utf-8"))
    recorded_hash = next(item["sha256"] for item in manifest["outputs"] if item["path"] == names[2])
    assert before[names[2]] == recorded_hash
    old_data_hash = next(item["sha256"] for item in manifest["input_artifacts"] if item["path"] == names[0])
    # A changed source file needs a separate provenance review before reuse.
    assert before[names[0]] == old_data_hash
    source = json.loads(paths[names[2]].read_text(encoding="utf-8"))
    assert source["checkpoint"] == "K4-20261012-D" and source["alphabet"] == ALPHABET
    assert source["crib_fit_count"] == 1018 and source["distinct_routes"] == 29
    ciphertext, cribs, known = read_literals(paths[names[0]])
    unknown = [i for i in range(97) if i not in known]
    assert len(unknown) == 73
    controls = self_test()
    records = []
    full_histogram = Counter()
    hold_histograms = {phrase: Counter() for phrase in HOLDS}
    position_coverage = Counter()
    forced_mismatches = 0
    route_orders = set()
    for route_record_index, row in enumerate(source["records"]):
        permutation = [position - 1 for position in row["source_positions_one_based"]]
        assert sorted(permutation) == list(range(97))
        route_order = (tuple(permutation), row["order"])
        assert route_order not in route_orders
        route_orders.add(route_order)
        inverse = [0] * 97
        for output, original in enumerate(permutation):
            inverse[original] = output
        for stored in row["models"]:
            if not stored["feasible"]:
                continue
            a, b, order = stored["period_a"], stored["period_b"], row["order"]
            full = graph_state(ciphertext, known, ALPHABET, inverse, order, a, b)
            assert full[2] == stored["free_components"]
            mask, forced_all = prediction_mask(ciphertext, range(97), ALPHABET, inverse, order, a, b, full)
            assert all(mask[i] == symbol for i, symbol in known.items())
            forced_unknown = [i + 1 for i in unknown if mask[i] != "?"]
            count = len(forced_unknown)
            assert len(forced_all) == count + 24
            full_histogram[count] += 1
            position_coverage.update(forced_unknown)
            holds = {}
            for phrase, positions in HOLDS.items():
                held = set(positions)
                training = {i: symbol for i, symbol in known.items() if i not in held}
                state = graph_state(ciphertext, training, ALPHABET, inverse, order, a, b)
                held_mask, held_forced = prediction_mask(ciphertext, positions, ALPHABET, inverse, order, a, b, state)
                mismatches = [i + 1 for i, symbol in zip(positions, held_mask) if symbol != "?" and symbol != known[i]]
                forced_mismatches += len(mismatches)
                holds[phrase] = {
                    "training_crib_letters": len(training), "component_count": state[2],
                    "forced_count": len(held_forced), "unforced_count": len(positions) - len(held_forced),
                    "held_prediction_mask": held_mask, "forced_positions_one_based": held_forced,
                    "forced_matches": len(held_forced) - len(mismatches), "forced_mismatches": mismatches,
                }
                hold_histograms[phrase][len(held_forced)] += 1
            records.append({
                "model_id": len(records), "source_route_record_index": route_record_index,
                "route_aliases": row["aliases"], "order": order, "period_a": a, "period_b": b,
                "full_cribs": {"component_count": full[2], "forced_unknown_count": count,
                               "unforced_unknown_count": 73 - count, "prediction_mask": mask,
                               "forced_unknown_positions_one_based": forced_unknown},
                "retrospective_holds": holds,
            })
    assert len(route_orders) == 87 and len(records) == 1018
    assert forced_mismatches == 0  # logically required after selection with every crib
    after = {name: digest(path) for name, path in paths.items()}
    assert before == after
    values = sorted(full_histogram)
    example_counts = sorted({values[0], values[len(values) // 2], values[-1]})
    examples = [next(row for row in records if row["full_cribs"]["forced_unknown_count"] == count)
                for count in example_counts]
    hold_summary = {}
    for phrase, positions in HOLDS.items():
        histogram = hold_histograms[phrase]
        hold_summary[phrase] = {
            "positions_one_based": [i + 1 for i in positions], "held_letters": len(positions),
            "forced_count_histogram": {str(k): v for k, v in sorted(histogram.items())},
            "models_predicting_at_least_one_held_letter": sum(v for k, v in histogram.items() if k > 0),
            "models_predicting_entire_held_phrase": histogram[len(positions)],
            "total_forced_predictions": sum(k * v for k, v in histogram.items()),
            "forced_mismatches": 0,
            "caution": "Retrospective coverage only: all models were selected using this phrase, so these matches are not independent validation.",
        }
    return {
        "source_checkpoint": "K4-20261012-D", "started_at": started,
        "runtime_seconds": time.perf_counter() - timer,
        "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
        "input_artifacts": [{"path": name, "sha256": before[name], "sha256_after": after[name]} for name in names],
        "checks": {"inputs_unchanged": True, "source_results_match_manifest": True,
                   "source_data_match_original_manifest": True, "component_counts_match_all_recorded_fits": True,
                   "all_known_symbols_forced_and_correct": True, "small_controls": controls},
        "scope": {"selected_models": 1018, "available_routes": 29, "layer_orders": ["SST", "STS", "TSS"],
                  "period_range": [1, 16], "alphabet": ALPHABET, "literal_letters": 97,
                  "known_letters": 24, "unknown_letters_per_model": 73, "new_models_searched": 0},
        "ciphertext": ciphertext, "cribs": cribs,
        "unknown_positions_one_based": [i + 1 for i in unknown],
        "full_crib_summary": {
            "forced_unknown_count_histogram": {str(k): v for k, v in sorted(full_histogram.items())},
            "models_forcing_all_73_unknown_letters": full_histogram[73],
            "models_forcing_no_unknown_letter": full_histogram[0],
            "total_forced_unknown_predictions": sum(k * v for k, v in full_histogram.items()),
            "total_unforced_unknown_positions": sum((73 - k) * v for k, v in full_histogram.items()),
            "per_position_forcing_model_counts": {str(i + 1): position_coverage[i + 1] for i in unknown},
        },
        "retrospective_hold_summary": hold_summary, "representative_coverage_examples": examples,
        "records": records,
        "non_claims": [
            "Forced values are conditional consequences of a particular fitted model, not authenticated plaintext.",
            "Unforced positions each have all26 symbols as their marginal domain; their values can be correlated across positions.",
            "The withholding exercise is retrospective because all models were selected using all24 crib letters.",
            "No language scoring, independent validation, solution confidence, or authenticity is inferred.",
            "No new cipher model, route, period, or key search and no full application tests were run.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze()
    output = args.output.resolve()
    if output in {(ROOT / entry["path"]).resolve() for entry in result["input_artifacts"]}:
        raise ValueError("output cannot overwrite an input")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"scope": result["scope"], "full_crib_summary": result["full_crib_summary"],
                      "retrospective_hold_summary": result["retrospective_hold_summary"],
                      "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
