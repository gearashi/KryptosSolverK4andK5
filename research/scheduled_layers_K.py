"""Checkpoint-K fixed shared/scheduled/mixed-stage controls and K4 banks.

No model selection from results, scoring, network use, or arbitrary unknown
alphabet. Root runs the declared bank once; --self-test runs tiny controls only.
"""
from hashlib import sha256
from itertools import product
import argparse
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.general_layers import solve_layers
from kryptos.grid import k4_cells, coordinate_routes
from kryptos.scheduled_layers import solve_scheduled, make_phase_map, stage_position_map
from kryptos.mixed_stages import solve_mixed_stages

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
K = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
SOURCE_PATHS = ("research/scheduled_layers_K.py", "kryptos/scheduled_layers.py", "kryptos/mixed_stages.py",
                "kryptos/general_layers.py", "kryptos/grid.py", "kryptos/data.py")
ROUTE_ALIASES = ("geometry/rotate90/forward", "rows/major0/minor0/snake1/forward")
PERIODS = (2, 3, 5)
SCHEDULE_KINDS = ("row_reset", "column", "serpentine")
RELATIVE_OFFSETS = (0, 1)
MIXED_PERIODS = (1, 2)
MIXED_ALPHABETS = ((A, K, A), (K, A, K))
MIXED_SHARE_OUTER = (True, False)
TIME_CAP_SECONDS = 90


def direct(text, keys, stages, *, decrypt=False, alphabet=A):
    for stage in (reversed(stages) if decrypt else stages):
        if stage["operation"] == "gather":
            perm = stage["permutation"]
            if decrypt:
                inv = [0] * len(text)
                for j, i in enumerate(perm):
                    inv[i] = j
                perm = inv
            text = "".join(text[i] for i in perm)
            continue
        alpha, key = stage.get("alphabet", alphabet), keys[stage["key_id"]]
        phase = stage.get("phase_map", [i % len(key) for i in range(len(text))])
        output = []
        for i, symbol in enumerate(text):
            x, k = alpha.index(symbol), alpha.index(key[(phase[i] + stage.get("offset", 0)) % len(key)])
            cipher = stage.get("cipher", "vigenere")
            if cipher == "beaufort":
                value = k - x
            elif cipher == "variant":
                value = x + k if decrypt else x - k
            else:
                value = x - k if decrypt else x + k
            output.append(alpha[value % 26])
        text = "".join(output)
    return text


def controls():
    records = []
    stages = [{"operation": "substitution", "key_id": "k", "key_length": 2},
              {"operation": "gather", "permutation": [2, 0, 4, 1, 3]},
              {"operation": "substitution", "key_id": "k", "key_length": 2, "cipher": "beaufort",
               "phase_map": [1, 0, 1, 1, 0], "offset": -1},
              {"operation": "substitution", "key_id": "k", "key_length": 2, "cipher": "variant"}]
    plain = "STONE"
    cipher = direct(plain, {"k": "FU"}, stages)
    expected, key_count = set(), 0
    for symbols in product(A, repeat=2):
        text = direct(cipher, {"k": "".join(symbols)}, stages, decrypt=True)
        if text[1] == "T":
            expected.add(text)
            key_count += 1
    solved = solve_scheduled(cipher, {1: "T"}, stages)
    found = set()
    for a, b, text in solved.enumerate_plaintexts(676):
        candidate = solved.candidate(a, b)
        assert direct(text, candidate["keys_by_id"], stages) == cipher
        found.add(text)
    assert found == expected and solved.key_assignment_count == key_count
    assert list(map(set, solved.plaintext_domains())) == [set(p[i] for p in expected) for i in range(5)]
    records.append({"control": "shared scheduled key versus all676 letter keys", "passed": True,
                    "key_assignments": key_count, "distinct_plaintexts": len(found)})

    independent = [{"operation": "substitution", "key_id": "a", "key_length": 2},
                   {"operation": "gather", "permutation": [2, 5, 0, 4, 1, 3]},
                   {"operation": "substitution", "key_id": "b", "key_length": 3}]
    cipher = direct("SECRET", {"a": "BF", "b": "CDE"}, independent)
    known = {0: "S", 3: "R", 5: "T"}
    solved = solve_scheduled(cipher, known, independent)
    old = solve_layers(cipher, known, [{"operation": "substitution", "period": 2}, independent[1],
                                      {"operation": "substitution", "period": 3}])
    assert {p for a, b, p in solved.enumerate_plaintexts(676)} == {p for a, b, p in old.enumerate_plaintexts(676)}
    records.append({"control": "distinct periodic keys specialize to pinned general solver", "passed": True,
                    "distinct_plaintexts": solved.distinct_plaintext_count})

    stage = {"operation": "substitution", "key_id": "same", "key_length": 1}
    marginal = []
    for repetitions, expected_count in ((1, 26), (2, 13), (13, 2)):
        solved = solve_scheduled("A", {}, [stage] * repetitions)
        assert solved.distinct_plaintext_count == expected_count == len(solved.plaintext_domains()[0])
        marginal.append({"repetitions": repetitions, "domain": solved.plaintext_domains()[0]})
    phases, perm = [0, 1, 0, 1, 0], [2, 0, 4, 1, 3]
    stages = [{"operation": "substitution", "key_id": "x", "key_length": 2, "phase_map": phases},
              {"operation": "gather", "permutation": perm},
              {"operation": "substitution", "key_id": "x", "key_length": 2, "cipher": "variant",
               "phase_map": [phases[i] for i in perm]}]
    solved = solve_scheduled("".join("ABCDE"[i] for i in perm), {}, stages)
    assert solved.plaintext() == "ABCDE" and solved.key_assignment_count == 676
    assert len(solved.dependency_report()["structurally_cancelled_key_slots"]) == 2
    records.append({"control": "exact2/13/26 marginal sizes and transported key cancellation", "passed": True,
                    "marginal_examples": marginal, "cancellation_report": solved.dependency_report()})

    mixed = [{"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": A},
             {"operation": "gather", "permutation": [2, 5, 0, 4, 1, 3]},
             {"operation": "substitution", "key_id": "b", "key_length": 1, "alphabet": B, "cipher": "beaufort"},
             {"operation": "gather", "permutation": [1, 4, 5, 0, 2, 3]},
             {"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": K, "cipher": "variant"}]
    cipher = direct("SECRET", {"a": "G", "b": "D"}, mixed)
    known = {0: "S", 4: "E"}
    expected, count = set(), 0
    for a, b in product(A, repeat=2):
        text = direct(cipher, {"a": a, "b": b}, mixed, decrypt=True)
        if all(text[i] == c for i, c in known.items()):
            expected.add(text)
            count += 1
    result = solve_mixed_stages(cipher, known, mixed, max_candidates=1000)
    assert result["complete"] and result["key_assignment_count"] == count
    assert {c["plaintext"] for c in result["candidates"]} == expected
    assert list(map(set, result["plaintext_domains"])) == [set(p[i] for p in expected) for i in range(6)]
    records.append({"control": "three known alphabets/two gathers/shared letter key versus676 key pairs", "passed": True,
                    "key_assignments": count, "distinct_plaintexts": len(expected), "work": result["work"]})
    return records


def hashes():
    return {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_PATHS}


def analyze():
    started, before = perf_counter(), hashes()
    if before["kryptos/data.py"] != "2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2":
        raise ValueError("canonical data changed")
    control_results = controls()
    cells = k4_cells()
    routes = {alias: row["permutation"] for row in coordinate_routes(cells) for alias in row["aliases"]}
    t1 = {"operation": "gather", "permutation": routes[ROUTE_ALIASES[0]]}
    t2 = {"operation": "gather", "permutation": routes[ROUTE_ALIASES[1]]}
    transported = stage_position_map(97, [t1, t2])
    known = {crib["start"] - 1 + i: c for crib in K4_CRIBS for i, c in enumerate(crib["text"])}
    scheduled, mixed = [], []
    for period, kind, offset in product(PERIODS, SCHEDULE_KINDS, RELATIVE_OFFSETS):
        if perf_counter() - started > TIME_CAP_SECONDS:
            raise TimeoutError("scheduled-layer benchmark time cap")
        stages = [{"operation": "substitution", "key_id": "outer", "key_length": period,
                   "phase_map": make_phase_map(cells, kind, period)}, t1,
                  {"operation": "substitution", "key_id": "middle", "key_length": period + 1,
                   "phase_map": make_phase_map(cells, "column", period + 1)}, t2,
                  {"operation": "substitution", "key_id": "outer", "key_length": period, "cipher": "variant",
                   "phase_map": make_phase_map(cells, kind, period, frame="source", stage_to_source=transported), "offset": offset}]
        solution = solve_scheduled(K4_CIPHERTEXT, known, stages, K)
        scheduled.append({"period": period, "schedule": kind, "relative_offset": offset,
                          "result": solution.summary(), "candidate_enumeration": "none", "language_ranking": "none"})
    for period, alphabets, shared in product(MIXED_PERIODS, MIXED_ALPHABETS, MIXED_SHARE_OUTER):
        if perf_counter() - started > TIME_CAP_SECONDS:
            raise TimeoutError("mixed-stage benchmark time cap")
        stages = [{"operation": "substitution", "key_id": "outer", "key_length": period, "alphabet": alphabets[0],
                   "phase_map": make_phase_map(cells, "row_reset", period)}, t1,
                  {"operation": "substitution", "key_id": "middle", "key_length": period, "alphabet": alphabets[1],
                   "phase_map": make_phase_map(cells, "column", period)}, t2,
                  {"operation": "substitution", "key_id": "outer" if shared else "last", "key_length": period,
                   "alphabet": alphabets[2], "cipher": "variant",
                   "phase_map": make_phase_map(cells, "row_reset", period, frame="source", stage_to_source=transported)}]
        result = solve_mixed_stages(K4_CIPHERTEXT, known, stages, max_nodes=2000, max_relation_checks=750000,
                                    max_candidates=0, max_distinct_plaintexts=1000, time_limit_seconds=3)
        mixed.append({"period": period, "alphabets": list(alphabets), "shared_outer_key": shared, "result": result})
    after = hashes()
    if before != after:
        raise RuntimeError("a pinned source changed during the run")
    assert len(scheduled) == 18 and len(mixed) == 8
    return {"checkpoint": "K4-20261013-K", "experiment": "shared-key-fixed-phase-known-mixed-alphabet-stages",
            "python": platform.python_version(), "controls": control_results,
            "contract": {"route_aliases": list(ROUTE_ALIASES), "scheduled_periods": list(PERIODS),
                         "schedule_kinds": list(SCHEDULE_KINDS), "relative_offsets": list(RELATIVE_OFFSETS),
                         "mixed_periods": list(MIXED_PERIODS), "mixed_alphabet_triples": [list(a) for a in MIXED_ALPHABETS],
                         "shared_outer_options": list(MIXED_SHARE_OUTER), "time_cap_seconds": TIME_CAP_SECONDS,
                         "geometry": "existing occupied K4 grid surrogate; missing cells consume no phase",
                         "candidate_ranking": "none"},
            "scheduled_models": scheduled, "mixed_models": mixed,
            "summary": {"scheduled_models": 18, "scheduled_fits": sum(row["result"]["feasible"] for row in scheduled),
                        "mixed_models": 8, "mixed_complete": sum(row["result"]["complete"] for row in mixed),
                        "mixed_complete_rejects": sum(row["result"]["complete"] and row["result"]["feasible"] is False for row in mixed),
                        "mixed_witnessed_fits": sum(row["result"]["feasible"] is True for row in mixed)},
            "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in SOURCE_PATHS],
            "inputs_unchanged": True, "runtime_seconds": perf_counter() - started,
            "non_claims": ["Only the declared periods, schedules, known alphabets, routes and key identities are tested.",
                           "Truncated mixed searches are not rejections; they provide witnessed lower bounds only.",
                           "No unknown alphabet, freely fitted grid, language ranking, authenticated K4 or K5 solution."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error("assertion checks must remain enabled; do not use-O")
    if args.self_test:
        if args.output:
            parser.error("self-test does not write the canonical bank")
        print(json.dumps({"controls": controls(), "K4_models_run": 0}, indent=2))
        return
    if args.output is None:
        parser.error("--output is required")
    path = args.output.resolve()
    if not path.is_relative_to(ROOT / "research") or path.exists():
        parser.error("use a new result path inside research")
    result = analyze()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({**result["summary"], "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
