"""Bounded, reproducible incumbent search inside an exact factor domain.

Coordinate ascent changes only domain coordinates; it cannot leave the affine
plaintext family represented by the caller. Scores and deltas are integers.
This is a heuristic for finding witnesses, never an optimality certificate.
"""
import math
import random
import time

from .search_runtime import _integer, _validate, evaluate_factor


GUIDED_FIELDS = {"seed", "restarts", "max_evaluations", "max_sweeps", "top",
                 "max_factor_evaluations"}


class _Stop(Exception):
    pass


def guided_seeds(problem, *, seed=0, restarts=8, max_evaluations=2048,
                 max_sweeps=8, top=4, max_factor_evaluations=200000,
                 time_limit_seconds=5, initial_assignments=()):
    """Return bounded feasible hints, with exact adjacent-factor delta scores.

    Initial scores and every trial coordinate count as objective evaluations.
    Every evaluated point is eligible for retention. The first restart starts
    at zero unless a supplied warm start is present; later starts use Random
    with the explicit integer seed. Fixed evaluation caps are reproducible;
    wall-time termination can vary with hardware.
    """
    domains, factors = _validate(problem)
    _integer(seed, "seed", 0, 2**64 - 1)
    _integer(restarts, "restarts", 1, 100)
    _integer(max_evaluations, "max_evaluations", 1, 100000)
    _integer(max_sweeps, "max_sweeps", 1, 1000)
    _integer(top, "top", 1, 100)
    _integer(max_factor_evaluations, "max_factor_evaluations", 1, 2000000)
    if type(time_limit_seconds) not in (int, float) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time_limit_seconds must be in (0,600]")
    if not isinstance(initial_assignments, (list, tuple)) or len(initial_assignments) > 100:
        raise ValueError("at most100 warm starts are allowed")
    warm = []
    for point in initial_assignments:
        if not isinstance(point, (list, tuple)) or len(point) != len(domains) or any(type(v) is not int or not 0 <= v < d for v, d in zip(point, domains)):
            raise ValueError("invalid warm-start coordinates")
        warm.append(tuple(point))
    started = time.monotonic()
    rng = random.Random(seed)
    adjacency = [[] for _ in domains]
    for number, f in enumerate(factors):
        for variable in f["scope"]:
            adjacency[variable].append(number)
    work = {"objective_evaluations": 0, "factor_evaluations": 0,
            "accepted_moves": 0, "restarts_started": 0, "sweeps_completed": 0,
            "full_factor_evaluations_avoided": 0}
    retained = {}

    def check(number):
        if time.monotonic() - started >= time_limit_seconds:
            raise _Stop("time_limit")
        if work["objective_evaluations"] >= max_evaluations:
            raise _Stop("evaluation_limit")
        if work["factor_evaluations"] + number > max_factor_evaluations:
            raise _Stop("factor_evaluation_limit")

    def values_at(point, numbers):
        values = []
        for number in numbers:
            if time.monotonic() - started >= time_limit_seconds:
                raise _Stop("time_limit")
            f = factors[number]
            value = evaluate_factor(f, tuple(point[i] for i in f["scope"]), domains, problem.get("model"))
            values.append(value ** f.get("power", 1))
            work["factor_evaluations"] += 1
        return values

    def retain(point, score):
        point = tuple(point)
        retained[point] = score
        if len(retained) > top:
            worst = max(retained, key=lambda p: (-retained[p], p))
            del retained[worst]

    stop = "restarts_complete"
    try:
        for restart in range(restarts):
            point = list(warm[restart] if restart < len(warm) else
                         tuple(0 for _ in domains) if restart == 0 else
                         tuple(rng.randrange(d) for d in domains))
            check(len(factors))
            current_values = values_at(point, range(len(factors)))
            positive_product = math.prod(v for v in current_values if v)
            zeros = current_values.count(0)
            current_score = 0 if zeros else positive_product
            work["objective_evaluations"] += 1
            work["restarts_started"] += 1
            retain(point, current_score)
            for _ in range(max_sweeps):
                changed = False
                order = [i for i, d in enumerate(domains) if d > 1 and adjacency[i]]
                rng.shuffle(order)
                for variable in order:
                    neighbors = adjacency[variable]
                    outside_product = positive_product
                    outside_zeros = zeros
                    for number in neighbors:
                        old = current_values[number]
                        if old:
                            outside_product //= old
                        else:
                            outside_zeros -= 1
                    original = point[variable]
                    best_value, best_score, best_local = original, current_score, None
                    for value in range(domains[variable]):
                        if value == original:
                            continue
                        check(len(neighbors))
                        trial = list(point)
                        trial[variable] = value
                        local = values_at(trial, neighbors)
                        trial_zeros = outside_zeros + local.count(0)
                        trial_product = outside_product * math.prod(v for v in local if v)
                        score = 0 if trial_zeros else trial_product
                        work["objective_evaluations"] += 1
                        work["full_factor_evaluations_avoided"] += len(factors) - len(neighbors)
                        retain(trial, score)
                        if score > best_score or (score == best_score and value < best_value):
                            best_value, best_score, best_local = value, score, (local, trial_product, trial_zeros)
                    if best_value != original:
                        point[variable] = best_value
                        local, positive_product, zeros = best_local
                        for number, value in zip(neighbors, local):
                            current_values[number] = value
                        current_score = best_score
                        work["accepted_moves"] += 1
                        changed = True
                work["sweeps_completed"] += 1
                if not changed:
                    break
    except _Stop as exc:
        stop = str(exc)
    candidates = [{"assignment": list(point), "score_hex": hex(score)}
                  for point, score in sorted(retained.items(), key=lambda row: (-row[1], row[0]))]
    return {"method": "seeded_affine_coordinate_ascent_exact_factor_deltas", "seed": seed,
            "candidates": candidates, "work": work, "stop_reason": stop,
            "runtime_seconds": time.monotonic() - started,
            "bounds": {"restarts": restarts, "max_evaluations": max_evaluations,
                       "max_sweeps": max_sweeps, "top": top,
                       "max_factor_evaluations": max_factor_evaluations,
                       "time_limit_seconds": time_limit_seconds},
            "optimality_claimed": False,
            "interpretation": "Feasible coordinates and exact scores only. Local optima and unvisited regions remain possible; no authentication."}
