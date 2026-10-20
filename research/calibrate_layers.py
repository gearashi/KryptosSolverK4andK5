"""Small whole-pipeline controls and a synthetic hidden-key recovery challenge.

Default: the two previously defined K3-inspired routes, all three orders,
periods1..16. Every input gets the same family, mask, budgets, and selection rule.
No selection of models using K4's crib values occurs before the controls run.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.layer_plan import compile_layer_plan
from kryptos.scoring import english_score
from kryptos.experiments import ExperimentJournal, fingerprint, control_summary
from research.check_layer_hypothesis import hypothesis_routes
from research.layer_constraints import apply_layers

ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def _validate_saved_job(job_id, job, routes, inputs, known, max_period, budget):
    if job_id not in {str(i) for i in range(len(routes))} or not isinstance(job, dict):
        raise ValueError("checkpoint contains an unplanned route job")
    route_id = int(job_id)
    route, aliases = routes[route_id]
    if (job.get("route") != aliases or job.get("model_count") != 2 * max_period ** 2 + max_period
            or not isinstance(job.get("inputs"), dict) or set(job["inputs"]) != set(inputs)):
        raise ValueError("checkpoint route configuration is invalid")
    for name, row in job["inputs"].items():
        fields = ("fits", "complete_models", "candidates_evaluated", "skipped_by_dimension")
        if not isinstance(row, dict) or any(type(row.get(k)) is not int or row[k] < 0 for k in fields):
            raise ValueError("checkpoint counts are invalid")
        hist = row.get("dimension_histogram")
        if (not isinstance(hist, dict) or any(not k.isdigit() or type(v) is not int or v < 0 for k, v in hist.items())
                or sum(hist.values()) != row["fits"] or hist.get("0", 0) != row["complete_models"]
                or row["fits"] > job["model_count"] or row["candidates_evaluated"] > budget
                or type(row.get("budget_exhausted")) is not bool or not isinstance(row.get("plaintexts"), dict)
                or len(row["plaintexts"]) > row["candidates_evaluated"]):
            raise ValueError("checkpoint coverage is inconsistent")
        for plain, candidate in row["plaintexts"].items():
            if not isinstance(candidate, dict) or len(plain) != 97 or any(ch not in ALPHABET for ch in plain):
                raise ValueError("invalid saved plaintext")
            score = candidate.get("score")
            if (type(score) not in (int, float) or not math.isfinite(score)
                    or score != english_score(plain, known) or candidate.get("route_id") != route_id
                    or candidate.get("permutation") != list(route)
                    or any(plain[i] != ch for i, ch in known.items())):
                raise ValueError("invalid saved candidate score, route, or cribs")
            keys, order = candidate.get("keys"), candidate.get("order")
            if (not isinstance(keys, (tuple, list)) or len(keys) != 2 or order not in ("SST", "STS", "TSS")
                    or not all(isinstance(key, str) and key and set(key) <= set(ALPHABET) for key in keys)
                    or candidate.get("periods") != [len(key) for key in keys]
                    or apply_layers(plain, *keys, ALPHABET, order, route) != inputs[name]):
                raise ValueError("saved candidate does not reproduce ciphertext")


def analyze(controls=4, max_period=16, max_dimension=0, candidate_budget=10000,
            seed=20261012, journal_path=None, max_route_jobs=None):
    if (any(type(value) is not int for value in (controls, max_period, max_dimension, candidate_budget, seed))
            or not 1 <= controls <= 64 or not 1 <= max_period <= 32 or not 0 <= max_dimension <= 2):
        raise ValueError("bounds: controls1..64, periods1..32, dimension0..2")
    if candidate_budget < 1 or (max_route_jobs is not None and (type(max_route_jobs) is not int or max_route_jobs < 1)):
        raise ValueError("budgets must be positive")
    started = time.perf_counter()
    known = {c["start"] - 1 + k: ch for c in K4_CRIBS for k, ch in enumerate(c["text"])}
    routes = [(tuple(route), aliases) for route, aliases in hypothesis_routes().items()
              if any(alias.startswith("K3-inspired") for alias in aliases)]
    assert len(routes) == 2
    # The fixture contains the same clues but new surrounding text; generation
    # knows the key. The recovery loop receives only its ciphertext and cribs.
    synthetic = list(("THECOURIERWILLARRIVEAFTERDARKPLEASEWAITUNTILTHESIGNALISGIVENANDTHENREADTHEHIDDENMESSAGE" * 2)[:97])
    for i, ch in known.items():
        synthetic[i] = ch
    synthetic = "".join(synthetic)
    inputs = {"K4": K4_CIPHERTEXT,
              "synthetic": apply_layers(synthetic, "BC", "DEF", ALPHABET, "STS", routes[0][0])}
    for kind in ("shuffle", "uniform"):
        for sample in range(controls):
            rng = random.Random(f"{seed}/{kind}/{sample}")
            chars = list(K4_CIPHERTEXT)
            if kind == "shuffle":
                rng.shuffle(chars)
            else:
                chars = [rng.choice(ALPHABET) for _ in chars]
            inputs[f"{kind}-{sample}"] = "".join(chars)
    config = {"controls_per_kind": controls, "periods": [1, max_period],
              "maximum_plaintext_dimension": max_dimension, "candidate_budget_per_input": candidate_budget,
              "seed": seed, "family": "two stored K3-inspired routes; allSST,STS,TSS; sharedKRYPTOS",
              "selection": "all crib-consistent complete plaintexts within dimension/budget; largest masked English score",
              "deduplication": "SST/TSS period exchange removed; identical complete strings counted once per input",
              "budget_unit": "raw model/plaintext completions, including repeats across models",
              "python_version": sys.version, "materialized_inputs": inputs,
              "known_plaintext": {str(i): ch for i, ch in sorted(known.items())},
              "routes": [{"permutation": list(route), "aliases": aliases} for route, aliases in routes]}
    names = ["research/calibrate_layers.py", "kryptos/layer_plan.py", "kryptos/experiments.py",
             "kryptos/scoring.py", "kryptos/data.py", "research/check_layer_hypothesis.py",
             "research/check_physical_routes.py", "research/k3_reference.py", "research/layer_constraints.py"]
    identity = fingerprint(config, [ROOT / name for name in names])
    journal = ExperimentJournal(journal_path, identity) if journal_path else None
    jobs = journal.records if journal else {}
    for job_id, job in jobs.items():
        _validate_saved_job(job_id, job, routes, inputs, known, max_period, candidate_budget)
    budgets = Counter()
    for old in jobs.values():
        budgets.update({name: row["candidates_evaluated"] for name, row in old["inputs"].items()})
    if any(value > candidate_budget for value in budgets.values()):
        raise ValueError("saved aggregate candidate budget exceeded")
    jobs_this_call = 0
    for route_id, (route, aliases) in enumerate(routes):
        job_id = str(route_id)
        if job_id in jobs:
            continue
        if max_route_jobs is not None and jobs_this_call >= max_route_jobs:
            break
        rows = {name: {"fits": 0, "complete_models": 0, "candidates_evaluated": 0,
                       "skipped_by_dimension": 0, "budget_exhausted": False, "plaintexts": {},
                       "dimension_histogram": {}} for name in inputs}
        model_count = 0
        for order in ("SST", "STS", "TSS"):
            for a in range(1, max_period + 1):
                for b in range(1, max_period + 1):
                    if order != "STS" and a > b:
                        continue  # adjacent additions commute, same alphabet
                    model_count += 1
                    plan = compile_layer_plan(97, known, order, route, a, b)
                    for name, ciphertext in inputs.items():
                        outcome = plan.solve(ciphertext, known, ALPHABET)
                        if not outcome["feasible"]:
                            continue
                        row, solution = rows[name], outcome["solution"]
                        row["fits"] += 1
                        dim = str(plan.plaintext_dimension)
                        row["dimension_histogram"][dim] = row["dimension_histogram"].get(dim, 0) + 1
                        row["complete_models"] += plan.plaintext_dimension == 0
                        if plan.plaintext_dimension > max_dimension:
                            row["skipped_by_dimension"] += 1
                            continue
                        needed = solution.distinct_plaintext_count
                        if budgets[name] + needed > candidate_budget:
                            row["budget_exhausted"] = True
                            continue
                        budgets[name] += needed
                        row["candidates_evaluated"] += needed
                        for values, plaintext in solution.enumerate_plaintexts(candidate_budget):
                            keys = solution.keys(values)
                            if apply_layers(plaintext, *keys, ALPHABET, order, route) != ciphertext:
                                raise AssertionError("candidate failed independent literal re-encryption")
                            if plaintext not in row["plaintexts"]:
                                score = english_score(plaintext, known)
                                row["plaintexts"][plaintext] = {"score": score, "order": order,
                                    "periods": [a, b], "freedom_values": values, "keys": keys,
                                    "route_id": route_id, "route_aliases": aliases, "permutation": list(route)}
        job = {"route": aliases, "model_count": model_count, "inputs": rows}
        if journal:
            journal.record(job_id, job)
        else:
            jobs[job_id] = job
        jobs_this_call += 1
    summaries = {}
    for name, ciphertext in inputs.items():
        counts, histogram, candidates = Counter(), Counter(), {}
        exhausted = False
        for job in jobs.values():
            row = job["inputs"][name]
            for key in ("fits", "complete_models", "candidates_evaluated", "skipped_by_dimension"):
                counts[key] += row[key]
            exhausted |= row["budget_exhausted"]
            histogram.update(row["dimension_histogram"])
            for text, candidate in row["plaintexts"].items():
                candidates.setdefault(text, candidate)
        ranked = sorted(candidates, key=lambda text: (-candidates[text]["score"], text))
        best = ranked[0] if ranked else None
        summaries[name] = {**dict(counts), "ciphertext": ciphertext,
            "dimension_histogram": dict(sorted(histogram.items())), "distinct_plaintexts": len(candidates),
            "budget_exhausted": exhausted, "best_score": candidates[best]["score"] if best else None,
            "best_plaintext": best, "best_model": candidates.get(best),
            "synthetic_plaintext_recovered": synthetic in candidates if name == "synthetic" else None,
            "synthetic_rank": ranked.index(synthetic) + 1 if name == "synthetic" and synthetic in candidates else None}
    assert identity == fingerprint(config, [ROOT / name for name in names])
    return {"base_checkpoint": "K4-20261012-H", "config": config, "identity": identity,
            "complete": set(jobs) == {str(i) for i in range(len(routes))}, "route_jobs_completed": len(jobs),
            "route_jobs_total": len(routes), "unique_parameter_models": sum(job["model_count"] for job in jobs.values()),
            "inputs_unchanged": True, "runtime_seconds": time.perf_counter() - started,
            "results": summaries,
            "literal_reencryptions_checked": sum(row["candidates_evaluated"] for row in summaries.values()),
            "comparisons": {kind: control_summary(summaries["K4"]["best_score"],
                              [summaries[f"{kind}-{k}"]["best_score"] for k in range(controls)])
                            for kind in ("shuffle", "uniform")},
            "non_claims": ["Exploratory small controls, not calibrated significance or independent confirmation.",
                           "Synthetic fixture tests recovery inside the specified family, not actualK4 method.",
                           "Complete means the stated route jobs finished, not every conceivable cipher searched.",
                           "Dimension/budget omissions are explicit; English score cannot reject other languages."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--controls", type=int, default=4)
    parser.add_argument("--max-period", type=int, default=16)
    parser.add_argument("--max-dimension", type=int, default=0)
    parser.add_argument("--candidate-budget", type=int, default=10000)
    parser.add_argument("--max-route-jobs", type=int)
    args = parser.parse_args()
    if args.journal and args.output.resolve() == args.journal.resolve():
        parser.error("output and journal must differ")
    result = analyze(args.controls, args.max_period, args.max_dimension, args.candidate_budget,
                     journal_path=args.journal, max_route_jobs=args.max_route_jobs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("complete", "unique_parameter_models", "runtime_seconds", "comparisons")}))
    print(json.dumps({name: {k: row[k] for k in ("fits", "distinct_plaintexts", "best_score", "synthetic_plaintext_recovered", "synthetic_rank")}
                      for name, row in result["results"].items()}, indent=2))


if __name__ == "__main__":
    main()
