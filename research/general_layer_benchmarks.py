"""Fixed checkpoint-J controls for generalized layers and exact factor search.

No network, method discovery, custom corpus, GPU work, or application test run.
The fixed eight-model K4 bank reports algebraic feasibility/counts only.
"""
from hashlib import sha256
from itertools import product
import argparse
import json
import math
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.general_layers import solve_layers
from kryptos.factor_search import IntegerFactor, ngram_problem, optimize_product
from kryptos.grid import coordinate_routes, k4_cells
from kryptos.language import CharacterNgramModel
from kryptos.layer_plan import compile_layer_plan
from research import pk_benchmarks

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MODEL_PATH = "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
SOURCE_PATHS = tuple(dict.fromkeys(("research/general_layer_benchmarks.py", "kryptos/general_layers.py",
    "kryptos/factor_search.py", "kryptos/grid.py", "kryptos/language.py", MODEL_PATH,
    *pk_benchmarks.SOURCE_PATHS)))
K4_PERIOD_TRIPLES = ((2, 3, 5), (3, 5, 7), (5, 7, 11), (7, 8, 9))
K4_ROUTE_PAIRS = (("geometry/rotate90/forward", "rows/major0/minor0/snake1/forward"),
                  ("rows/major0/minor0/snake1/forward", "geometry/rotate90/forward"))
TIME_CAP_SECONDS = 90


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return sha256(value.encode("utf-8")).hexdigest()


def hashes():
    return {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def substitution(period, cipher="vigenere"):
    return {"operation": "substitution", "period": period, "cipher": cipher}


def gather(permutation):
    return {"operation": "gather", "permutation": list(permutation)}


def encrypt_direct(text, keys, stages, alphabet=ALPHABET):
    """Evaluator-only literal arithmetic; never supplies keys to solve_layers."""
    keys = iter(keys)
    for stage in stages:
        if stage["operation"] == "gather":
            text = "".join(text[i] for i in stage["permutation"])
        else:
            key = next(keys)
            equation = stage.get("cipher", "vigenere")
            output = []
            for i, char in enumerate(text):
                p, k = alphabet.index(char), alphabet.index(key[i % len(key)])
                output.append(alphabet[(p + k if equation == "vigenere" else k - p if equation == "beaufort" else p - k) % 26])
            text = "".join(output)
    return text


def deadline(started):
    if perf_counter() - started > TIME_CAP_SECONDS:
        raise TimeoutError("fixed generalized benchmark exceeded its 90-second cooperative cap")


def torsion_control():
    plain = "ABCDEFGH"
    stages = [substitution(2), gather([0, 2, 1, 3, 4, 6, 5, 7]), substitution(2),
              gather([0, 4, 2, 6, 1, 5, 3, 7]), substitution(2)]
    cipher = encrypt_direct(plain, ("BC", "DE", "FG"), stages)
    known = {i: plain[i] for i in (0, 3, 5, 6)}
    solution = solve_layers(cipher, known, stages)
    assert (solution.field2.rank, solution.field13.rank) == (3, 4)
    assert (solution.dimensions_mod2, solution.dimensions_mod13) == (1, 0)
    candidates = [solution.candidate(a, b) for a, b, _ in solution.enumerate_plaintexts(2)]
    assert {c["plaintext"] for c in candidates} == {"ABCDEFGH", "AOPDRFGU"}
    return {"kind": "three substitutions, two gathers, unequal prime-field ranks",
            "ciphertext": cipher, "known_zero_based": [[i, p] for i, p in known.items()],
            "solution": solution.summary(), "candidates": candidates}


def conflict_control():
    solution = solve_layers("AC", {0: "A", 1: "A"}, [substitution(1)])
    summary = solution.summary()
    assert not solution.feasible and {c["modulus"] for c in summary["conflicts"]} == {13}
    for certificate in summary["conflicts"]:
        prime = certificate["modulus"]
        weights = {r["constraint_index"]: r["weight"] for r in certificate["constraint_weights"]}
        for col in range(solution.key_slots):
            assert sum(weights.get(i, 0) * row["key_coefficients_mod26"][col] for i, row in enumerate(summary["constraints"])) % prime == 0
        value = sum(weights.get(i, 0) * row["rhs_mod26"] for i, row in enumerate(summary["constraints"])) % prime
        assert value == certificate["resultant_residue"] != 0
    return summary


def compare_old_plans():
    records = []
    plain, perm = "SECRET", [2, 5, 0, 4, 1, 3]
    for alphabet in (ALPHABET, pk_benchmarks.ALPHABET):
        for order in ("SST", "STS", "TSS"):
            periods = iter((2, 3))
            stages = [gather(perm) if s == "T" else substitution(next(periods)) for s in order]
            cipher = encrypt_direct(plain, ("BJ", "FXQ"), stages, alphabet)
            known = {i: plain[i] for i in (0, 3, 5)}
            generalized = solve_layers(cipher, known, stages, alphabet)
            old = compile_layer_plan(len(cipher), known, order, perm, 2, 3).solve(cipher, known, alphabet)["solution"]
            prior = {text for _, text in old.enumerate_plaintexts(676)}
            current = set()
            for a, b, text in generalized.enumerate_plaintexts(676):
                candidate = generalized.candidate(a, b)
                assert encrypt_direct(text, candidate["keys"], stages, alphabet) == cipher
                current.add(text)
            assert prior == current and plain in current
            assert generalized.prediction_mask() == old.prediction_mask()
            records.append({"order": order, "alphabet": alphabet, "ciphertext": cipher,
                            "exact_family_size": len(current), "families_equal": True,
                            "family_sha256": digest(canonical(sorted(current))), "all_reencrypted": True})
    return records


def compare_pk3(started):
    fixtures, _ = pk_benchmarks.load_fixtures()
    fixture = next(f for f in fixtures if f["id"] == "pk3")
    cipher, plain = fixture["ciphertext"], fixture["plaintext"]
    known = {i: plain[i] for i in pk_benchmarks.crib_positions()}
    stages = [substitution(10), substitution(8)]
    generalized = solve_layers(cipher, known, stages, pk_benchmarks.ALPHABET)
    old = compile_layer_plan(len(cipher), known, "SST", range(len(cipher)), 10, 8).solve(cipher, known, pk_benchmarks.ALPHABET)["solution"]
    assert generalized.distinct_plaintext_count == old.distinct_plaintext_count == 17576
    assert generalized.prediction_mask() == old.prediction_mask()
    old_texts = {text for _, text in old.enumerate_plaintexts(17576)}
    new_texts = set()
    for number, (a, b, text) in enumerate(generalized.enumerate_plaintexts(17576)):
        if number % 256 == 0:
            deadline(started)
        keys = generalized.keys(a, b)
        assert encrypt_direct(text, keys, stages, pk_benchmarks.ALPHABET) == cipher
        assert all(text[i] == p for i, p in known.items())
        new_texts.add(text)
    assert old_texts == new_texts and plain in new_texts
    return {"published_fixture": "PK3", "method_known": True, "supplied_cribs_are_artificial": True,
            "length": len(cipher), "declared_periods": [10, 8], "supplied_crib_positions": sorted(known),
            "exact_family_size": len(new_texts), "families_equal": True, "all_reencrypted": True,
            "published_truth_present": True, "family_sha256": digest(canonical(sorted(new_texts))),
            "dimensions_mod2": generalized.dimensions_mod2, "dimensions_mod13": generalized.dimensions_mod13,
            "prediction_mask": generalized.prediction_mask()}


def optimization_control():
    domains = (2,) * 10
    factors = [IntegerFactor((i,), {(0,): 1, (1,): 3}) for i in range(10)]
    scored = [(math.prod(f.values[tuple(point[i] for i in f.scope)] for f in factors), point)
              for point in product(*(range(size) for size in domains))]
    optimum = max(score for score, _ in scored)
    point = min(p for score, p in scored if score == optimum)
    optimized = optimize_product(domains, factors, max_nodes=1000, time_limit_seconds=5)
    assert optimized["optimal"] and optimized["complete"]
    assert (optimized["score"], tuple(optimized["assignment"])) == (optimum, point)
    assert optimized["nodes"] < len(scored)
    interrupted = optimize_product(domains, factors, max_nodes=0, time_limit_seconds=5)
    assert interrupted["lower_bound"] <= optimum <= interrupted["upper_bound"]
    assert not interrupted["complete"]
    return {"synthetic_factor_control": True, "brute_force_assignments": len(scored),
            "brute_optimum": optimum, "optimized": optimized, "interrupted": interrupted}


def language_optimization(model):
    plain = "READTHENEXTCLUES"
    # Make the fixed message length 16; both affine permutations preserve parity
    # while changing positions, leaving two aggregate shift freedoms.
    assert len(plain) == 16
    stages = [substitution(2, "beaufort"), gather([(3 * i + 1) % 16 for i in range(16)]),
              substitution(2, "variant"), gather([(5 * i + 2) % 16 for i in range(16)]), substitution(2)]
    cipher = encrypt_direct(plain, ("GQ", "PT", "LX"), stages)
    solution = solve_layers(cipher, {}, stages)
    assert solution.distinct_plaintext_count == 676
    problem = ngram_problem(solution, model, (), max_factor_entries=200000)
    num, den = float(model.alpha).as_integer_ratio()
    brute = []
    truth_score = None
    for a, b, text in solution.enumerate_plaintexts(676):
        score = math.prod(model.counts.get(text[i:i + model.order], 0) * den + num
                          for i in range(len(text) - model.order + 1))
        brute.append((score, a + b))
        if text == plain:
            truth_score = score
    optimum = max(value for value, _ in brute)
    assignment = min(point for value, point in brute if value == optimum)
    result = optimize_product(problem.domains, problem.factors, max_nodes=10000, time_limit_seconds=10)
    assert result["complete"] and result["optimal"] and result["tie_break_proven"]
    assert (result["score"], tuple(result["assignment"])) == (optimum, assignment)
    candidate = solution.candidate(assignment[:solution.dimensions_mod2], assignment[solution.dimensions_mod2:])
    assert encrypt_direct(candidate["plaintext"], candidate["keys"], stages) == cipher
    return {"ciphertext": cipher, "stages": stages, "fixture_plaintext_sha256": digest(plain),
            "supplied_cribs": [], "model_id": model.model_id, "scoring": dict(problem.metadata),
            "brute_force_assignments": len(brute), "brute_best_score": optimum,
            "truth_competition_rank": 1 + sum(value > truth_score for value, _ in brute),
            "truth_ties": sum(value == truth_score for value, _ in brute),
            "optimized": result, "candidate": candidate,
            "interpretation": "One synthetic fixed-method comparison; not a blinded recovery rate or language calibration."}


def k4_bank(started):
    routes = {alias: row["permutation"] for row in coordinate_routes(k4_cells()) for alias in row["aliases"]}
    known = {crib["start"] - 1 + j: symbol for crib in K4_CRIBS for j, symbol in enumerate(crib["text"])}
    records = []
    for periods in K4_PERIOD_TRIPLES:
        for route_names in K4_ROUTE_PAIRS:
            deadline(started)
            stages = [substitution(periods[0]), gather(routes[route_names[0]]), substitution(periods[1]),
                      gather(routes[route_names[1]]), substitution(periods[2])]
            solved = solve_layers(K4_CIPHERTEXT, known, stages, "kryptos")
            records.append({"periods": list(periods), "route_aliases": list(route_names),
                            "result": solved.summary(), "candidate_enumeration": "none", "language_ranking": "none"})
    assert len(records) == 8
    return {"predeclared_period_triples": [list(row) for row in K4_PERIOD_TRIPLES],
            "predeclared_route_pairs": [list(row) for row in K4_ROUTE_PAIRS],
            "alphabet": "KRYPTOSABCDEFGHIJLMNQUVWXZ", "all_substitutions": "vigenere",
            "models": len(records), "fits": sum(row["result"]["feasible"] for row in records),
            "records": records, "interpretation": "Only these eight fixed models; no arbitrary-family witness is ranked."}


def self_test():
    torsion_control()
    conflict_control()
    optimization_control()
    return {"passed_controls": 3, "K4_models_run": 0, "PK3_enumeration": False}


def analyze():
    started, before = perf_counter(), hashes()
    if before["kryptos/data.py"] != "2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2":
        raise ValueError("canonical data changed from checkpoint-I input")
    model = CharacterNgramModel.from_json((ROOT / MODEL_PATH).read_text(encoding="utf-8"))
    result = {"checkpoint": "K4-20261013-J", "experiment": "generalized-linear-layers-and-exact-factor-search",
              "python": platform.python_version(), "time_cap_seconds": TIME_CAP_SECONDS,
              "torsion_control": torsion_control(), "conflict_control": conflict_control(),
              "old_two_layer_comparisons": compare_old_plans(), "factor_control": optimization_control(),
              "fixed_model_language_optimization": language_optimization(model),
              "PK3_comparison": compare_pk3(started), "K4_fixed_bank": k4_bank(started)}
    deadline(started)
    after = hashes()
    if before != after:
        raise RuntimeError("a declared input changed during the benchmark")
    result.update(inputs=[{"path": path, "sha256_before": before[path], "sha256_after": after[path]} for path in SOURCE_PATHS],
                  inputs_unchanged=True, runtime_seconds=perf_counter() - started,
                  non_claims=["No K4/K5 solution or method authentication.",
                              "Exact optimization is within one supplied finite model, not proof of meaningful English.",
                              "Synthetic controls and one published method-known fixture do not establish general recovery rates.",
                              "The K4 bank is limited to eight declared models; no broader exclusion or discovery claim."])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        if args.output:
            parser.error("self-test does not write the canonical experiment")
        print(json.dumps(self_test(), indent=2))
        return
    if args.output is None:
        parser.error("--output is required")
    path = args.output.resolve()
    if not path.is_relative_to(ROOT / "research") or path.exists():
        parser.error("output must be a new path inside research")
    result = analyze()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"saved": str(path), "PK3_family_size": result["PK3_comparison"]["exact_family_size"],
                      "K4_models": result["K4_fixed_bank"]["models"], "K4_fits": result["K4_fixed_bank"]["fits"],
                      "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
