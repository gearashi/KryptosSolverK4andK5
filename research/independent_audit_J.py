"""Reproduce the small read-only columnar and general/optimize CLI audits.

These are preserved versions of the two inline independent checks performed
during checkpoint J. No K4 model bank, PK3 enumeration, or full suite is run.
"""
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import itertools
import json
import math
from pathlib import Path
import platform
import random
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MODEL_PATH = "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
SOURCE_PATHS = (
    "research/independent_audit_J.py", "kryptos/__main__.py",
    "kryptos/advanced_cli.py", "kryptos/columnar.py", "kryptos/explanations.py",
    "kryptos/general_layers.py", "kryptos/factor_search.py", "kryptos/language.py",
    "kryptos/ciphers.py", "kryptos/data.py", "kryptos/layer_plan.py", "kryptos/grid.py",
    "kryptos/recovery.py", "kryptos/scoring.py", "kryptos/position_residues.py", MODEL_PATH,
)


def hashes():
    return {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def audit_columnar():
    from kryptos.columnar import recover_column_order
    started = perf_counter()
    rng = random.Random(13102026)
    checked = truncated = 0
    for case in range(24):
        labels = [-7, 2, 9, 20][:3 + case % 2]
        cells = [(r, c) for c in labels for r in range(1 + (abs(c) + case) % 3)]
        rng.shuffle(cells)
        n = len(cells)
        plain = "".join(rng.choice("ABCD") for _ in cells)
        for direction in ("top_to_bottom", "bottom_to_top"):
            cols = {c: sorted([i for i, cell in enumerate(cells) if cell[1] == c],
                              key=lambda i: cells[i][0], reverse=direction == "bottom_to_top") for c in labels}
            truth = list(labels)
            rng.shuffle(truth)
            gather = [i for c in truth for i in cols[c]]
            cipher = "".join(plain[i] for i in gather)
            known = {i: plain[i] for i in range(n) if rng.randrange(4) == 0}
            cribs = [{"start": i + 1, "text": c} for i, c in known.items()]
            rows = []
            # Independent exhaustive permutations; no matching/SCC/count helper
            # from the audited module is called to calculate expected results.
            for order in itertools.permutations(sorted(labels)):
                permutation = [i for c in order for i in cols[c]]
                candidate = [""] * n
                for j, i in enumerate(permutation):
                    candidate[i] = cipher[j]
                candidate = "".join(candidate)
                if all(candidate[i] == c for i, c in known.items()):
                    rows.append((order, candidate))
            result = recover_column_order(cipher, cribs, cells=cells, column_direction=direction,
                                          max_candidates=1000, max_states=200000, time_limit_seconds=3)
            assert result["complete"] and result["total_column_orders"] == len(rows)
            assert result["column_order_lower_bound"] == len(rows)
            assert result["total_distinct_plaintexts"] == len({r[1] for r in rows})
            if rows:
                assert result["column_domains"] == [sorted({order[i] for order, text in rows}) for i in range(len(labels))]
                domains = ["".join(sorted({text[i] for order, text in rows})) for i in range(n)]
                assert result["plaintext_domains"] == domains
                assert result["forced_plaintext_mask"] == "".join(x if len(x) == 1 else "?" for x in domains)
            assert {(tuple(r["column_order"]), r["plaintext"]) for r in result["candidates"]} == set(rows)
            checked += 1
            for budget in (1, 12, 75, 250):
                short = recover_column_order(cipher, cribs, cells=cells, column_direction=direction,
                                             max_candidates=2, max_states=budget, time_limit_seconds=3)
                assert short["column_order_lower_bound"] <= len(rows)
                if not short["complete"]:
                    assert all(short[field] is None for field in ("total_column_orders", "column_domains",
                               "plaintext_domains", "forced_plaintext_mask", "forced_columns"))
                    truncated += 1
                else:
                    assert short["total_column_orders"] == len(rows)
    assert checked == 48
    return {"status": "passed", "complete_cases_checked": checked,
            "budget_limited_checks": checked * 4, "truncated_cases_checked": truncated,
            "seconds": perf_counter() - started,
            "contract": {"random_seed": 13102026, "geometry_cases": 24, "columns": [3, 4],
                         "directions": ["top_to_bottom", "bottom_to_top"],
                         "plaintext_symbols": "ABCD", "source_order": "deterministically shuffled occupied cells",
                         "column_labels": [-7, 2, 9, 20], "state_budgets": [1, 12, 75, 250]},
            "verified": ["Exact column-order counts versus all column permutations",
                         "Exact distinct plaintext counts with all small orders retained",
                         "All supported output-slot column domains and plaintext character domains",
                         "Forced masks and complete saved candidate sets",
                         "Truncated order-count lower bounds and withholding of global exact domains"]}


def encrypt_direct(plaintext, keys, stages):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keys = iter(keys)
    for stage in stages:
        if stage["operation"] == "gather":
            plaintext = "".join(plaintext[i] for i in stage["permutation"])
        else:
            key = next(keys)
            output = []
            for i, symbol in enumerate(plaintext):
                p, k = alphabet.index(symbol), alphabet.index(key[i % len(key)])
                cipher = stage.get("cipher", "vigenere")
                output.append(alphabet[(p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k) % 26])
            plaintext = "".join(output)
    return plaintext


def audit_advanced():
    from kryptos.advanced_cli import run_advanced, json_safe_integers
    from kryptos.__main__ import _target
    from kryptos.language import CharacterNgramModel
    started = perf_counter()
    checks = 0
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    stages = [{"operation": "substitution", "period": 2},
              {"operation": "gather", "permutation": [0, 2, 1, 3, 4, 6, 5, 7]},
              {"operation": "substitution", "period": 2},
              {"operation": "gather", "permutation": [0, 4, 2, 6, 1, 5, 3, 7]},
              {"operation": "substitution", "period": 2}]
    plain = "ABCDEFGH"
    cipher = encrypt_direct(plain, ["BC", "DE", "FG"], stages)
    request = {"ciphertext": cipher, "alphabet": "standard", "stages": stages,
               "cribs": [{"start": i + 1, "text": plain[i]} for i in (0, 3, 5, 6)], "top": 2}
    result = run_advanced("general", request, _target)
    assert result["complete"] and result["distinct_plaintext_count"] == 2 and result["evaluated"] == 2
    assert not result["candidates_omitted"]
    assert {row["plaintext"] for row in result["candidates"]} == {"ABCDEFGH", "AOPDRFGU"}
    for row in result["candidates"]:
        assert encrypt_direct(row["plaintext"], row["keys"], stages) == cipher
        assert len(row["evidence"]["stage_outputs"]) == 5
    checks += 1
    result = run_advanced("general", {**request, "max_candidates": 1}, _target)
    assert result["feasible"] and not result["complete"] and result["evaluated"] == 0 and not result["candidates"]
    checks += 1
    result = run_advanced("general", {**request, "max_operations": 1}, _target)
    assert result["feasible"] is None and not result["complete"] and result["stop_reason"] == "algebra_budget"
    checks += 1
    result = run_advanced("general", {"ciphertext": "AC", "alphabet": "standard",
        "cribs": [{"start": 1, "text": "AA"}], "stages": [{"operation": "substitution", "period": 1}]}, _target)
    assert not result["feasible"] and result["complete"] and result["stop_reason"] == "exact_contradiction_in_declared_model"
    checks += 1
    stages16 = [{"operation": "gather", "permutation": [1, 2, 0]} for _ in range(15)] + [{"operation": "substitution", "period": 1}]
    result = run_advanced("general", {"ciphertext": "DEF", "alphabet": "standard",
        "cribs": [{"start": 1, "text": "ABC"}], "stages": stages16}, _target)
    assert len(result["candidates"][0]["evidence"]["stage_outputs"]) == 16
    assert result["candidates"][0]["plaintext"] == "ABC"
    checks += 1
    model_path = ROOT / MODEL_PATH
    model = CharacterNgramModel.from_json(model_path.read_text(encoding="utf-8"))
    stages = [{"operation": "substitution", "period": 2}]
    cipher = encrypt_direct("SECRET", ["BC"], stages)
    request = {"ciphertext": cipher, "alphabet": "standard", "stages": stages,
               "cribs": [{"start": 1, "text": "S"}], "model_path": str(model_path)}
    numerator, denominator = float(model.alpha).as_integer_ratio()
    scores = []
    for value in range(26):
        candidate = "".join(alphabet[(alphabet.index(x) - (1 if i % 2 == 0 else value)) % 26]
                            for i, x in enumerate(cipher))
        score = math.prod(model.counts.get(candidate[i:i + 3], 0) * denominator + numerator for i in (1, 2, 3))
        scores.append(score)
    for limit in (0, 1, 1000):
        result = run_advanced("optimize", {**request, "max_nodes": limit}, _target)
        search, candidate = result["optimization"]["search"], result["optimization"]["candidate"]
        assert search["lower_bound"] <= max(scores) <= search["upper_bound"]
        assert encrypt_direct(candidate["plaintext"], candidate["keys"], stages) == cipher
        assert candidate["plaintext"][0] == "S"
        assert result["optimization"]["scoring"]["window_positions"] == [[1, 2, 3], [2, 3, 4], [3, 4, 5]]
        if limit == 1000:
            assert search["score"] == max(scores) and search["complete"] and search["optimal"]
        assert result["model_file_sha256"] == sha256(model_path.read_bytes()).hexdigest()
        checks += 1
    result = run_advanced("optimize", {**request, "max_factor_entries": 1}, _target)
    assert result["feasible"] and not result["complete"] and result["stop_reason"] == "factor_table_budget"
    assert "optimization" not in result
    checks += 1
    large = 1 << 15000
    encoded = json_safe_integers({"score": large})
    assert int(encoded["score"]["value"], 16) == large
    json.dumps(encoded)
    checks += 1
    assert checks == 10
    return {"status": "passed", "cases_checked": checks, "seconds": perf_counter() - started,
            "verified": ["Two-plaintext unequal-prime-rank case with all five stages replayed",
                         "Candidate cap performs no arbitrary partial enumeration",
                         "Algebra budget failure has no infeasibility verdict",
                         "Exact contradictory model classification",
                         "Sixteen-stage replay support",
                         "Node budgets 0/1/1000 bound an independent 26-key exact-score brute force",
                         "Crib-touching windows are excluded without concatenating gaps",
                         "Model-file byte hash provenance",
                         "Factor-table budget has no optimum verdict",
                         "15001-bit integer hex serialization roundtrip"]}


def analyze():
    started, before = perf_counter(), hashes()
    result = {"schema": "kryptos.independent-audit.v1", "checkpoint": "K4-20261013-J",
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "python_version": platform.python_version(), "python_implementation": platform.python_implementation(),
              "command": "python -B research/independent_audit_J.py --output research/independent_audit_J.json",
              "columnar": audit_columnar(), "advanced_general_optimize": audit_advanced()}
    after = hashes()
    if before != after:
        raise RuntimeError("an audited source or model changed during the checks")
    result.update(status="passed_in_stated_finite_scope", inputs_unchanged=True,
                  inputs=[{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in SOURCE_PATHS],
                  runtime_seconds=perf_counter() - started,
                  limitations=[
                      "Independent means expected values use separate literal arithmetic/permutation enumeration, not a separate author or formal verification.",
                      "Columnar coverage is 48 small constructed occupied-cell cases, not every geometry or width; time-limit interruption is not independently forced here.",
                      "State-budget checks cover 192 bounded runs; this does not prove a hard runtime or memory bound.",
                      "The CLI audit covers ten fixed cases; it is not an exhaustive API, malformed-input, or security audit.",
                      "This script does not repeat K4/PK3 research scans or the full application/unit suite.",
                      "Exact objective agreement concerns one fixed corpus model and mask, not English authenticity, cross-language calibration, or a Kryptos solution.",
                  ])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = args.output.resolve()
    if not path.is_relative_to(ROOT / "research") or path.exists():
        parser.error("output must be a new path inside research")
    if not __debug__:
        parser.error("run without -O; assertion checks must remain enabled")
    result = analyze()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"saved": str(path), "status": result["status"],
                      "columnar_cases": result["columnar"]["complete_cases_checked"],
                      "columnar_budget_checks": result["columnar"]["budget_limited_checks"],
                      "advanced_cases": result["advanced_general_optimize"]["cases_checked"],
                      "seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
