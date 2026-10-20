"""Bounded exact ranking of explicit column-order/repeating-key completions.

This is a separate enumerator: the counting-only joint solver is unchanged.
Only exhaustion certifies top-k over the declared family. Language scores
never reject a constraint-compatible route or key. Crib positions are masked.
"""
from collections import Counter, defaultdict
import hashlib
from itertools import product
import json
import math
from pathlib import Path
import string
import time

from . import columnar
from .explanations import replay_recipe
from .language import CharacterNgramModel

ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}


class _Limit(Exception):
    pass


class _Budget:
    def __init__(self, states, seconds):
        self.limit = states
        self.deadline = time.monotonic() + seconds
        self.work = defaultdict(int)

    def tick(self, name):
        if time.monotonic() >= self.deadline:
            raise _Limit("time_limit_seconds")
        if self.work["states"] >= self.limit:
            raise _Limit("max_states")
        self.work["states"] += 1
        self.work[name] += 1


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def rank_joint_columnar(ciphertext, cribs, *, model, period, order="ST", cipher="vigenere",
                        alphabet="kryptos", width=None, cells=None,
                        column_direction="top_to_bottom", top=20,
                        max_segmentations=2048, max_states=200000,
                        max_orders=5000, max_evaluations=100000,
                        time_limit_seconds=5, score_mask=None):
    """Return distinct-plaintext top-k and conservative coverage metadata.

    Counted keys include only phases used by this finite message. Unvisited
    declared key slots receive the alphabet's zero symbol in each representative
    recipe and are identified separately, not counted as recovered values.
    """
    started = time.monotonic()
    ciphertext, known, occupied, labels, columns = columnar._inputs(
        ciphertext, cribs, width, cells, column_direction)
    if len(ciphertext) > 512:
        raise ValueError("ranked joint messages are limited to512 letters")
    for value, name, low, high in ((period, "period", 1, 256), (top, "top", 1, 100),
        (max_segmentations, "max_segmentations", 1, 100000),
        (max_states, "max_states", 1, 5000000), (max_orders, "max_orders", 1, 100000),
        (max_evaluations, "max_evaluations", 1, 1000000)):
        columnar._integer(value, name, low, high)
    if order not in ("ST", "TS") or cipher not in ("vigenere", "beaufort", "variant"):
        raise ValueError("unsupported layer order or cipher equation")
    if not isinstance(alphabet, str):
        raise ValueError("alphabet must be a known uppercase permutation")
    alphabet = ALPHABETS.get(alphabet, alphabet)
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be a permutation of uppercase A-Z")
    if not isinstance(model, CharacterNgramModel) or set(model.alphabet) != set(string.ascii_uppercase) or len(model.alphabet) != 26 or model.order > 6:
        raise ValueError("supply a validated A-Z character model of order1..6")
    if type(time_limit_seconds) not in (int, float) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time limit must be finite and in(0,600]")
    n, w, used = len(ciphertext), len(columns), min(period, len(ciphertext))
    if score_mask is None:
        score_mask = sorted(known)
    if not isinstance(score_mask, (list, tuple)) or any(type(i) is not int or not 0 <= i < n for i in score_mask) or len(set(score_mask)) != len(score_mask) or not set(known) <= set(score_mask):
        raise ValueError("score_mask must be distinct original positions including every crib")
    score_mask = sorted(score_mask)
    masked = set(score_mask)
    starts = [i for i in range(n - model.order + 1) if not any(j in masked for j in range(i, i + model.order))]
    p, q = model.alpha.as_integer_ratio()
    index = {c: i for i, c in enumerate(alphabet)}
    cvalues = [index[c] for c in ciphertext]
    lengths = [len(c) for c in columns]
    multiplicities = Counter(lengths)
    budget = _Budget(max_states, time_limit_seconds)
    bounds = dict(top=top, max_segmentations=max_segmentations, max_states=max_states,
                  max_orders=max_orders, max_evaluations=max_evaluations, time_limit_seconds=time_limit_seconds)
    assumptions = dict(period=period, order=order, cipher=cipher, alphabet=alphabet,
                       cells=[list(c) for c in occupied], column_direction=column_direction)
    retained, evaluated, orders, segmentations = {}, 0, 0, 0
    visited_order_assignments = 0
    complete, reason = True, "exhausted_declared_family"

    def visit(column_ids, key_values):
        nonlocal evaluated, orders, visited_order_assignments
        if orders >= max_orders:
            raise _Limit("max_orders")
        orders += 1
        route = [i for col in column_ids for i in columns[col]]
        free = [i for i, value in enumerate(key_values) if value is None]
        visited_order_assignments += 26 ** len(free)
        labelled = tuple(labels[c] for c in column_ids)
        for assignment in product(range(26), repeat=len(free)):
            if evaluated >= max_evaluations:
                raise _Limit("max_evaluations")
            budget.tick("key_completions")
            key = list(key_values)
            for phase, value in zip(free, assignment):
                key[phase] = value
            plaintext = [""] * n
            for j, i in enumerate(route):
                k, c = key[(i if order == "ST" else j) % period], cvalues[j]
                plaintext[i] = alphabet[(k - c if cipher == "beaufort" else c + k if cipher == "variant" else c - k) % 26]
            plaintext = "".join(plaintext)
            if any(plaintext[i] != c for i, c in known.items()):
                raise AssertionError("key-constraint enumeration produced a crib mismatch")
            exact = 1
            for start in starts:
                budget.tick("scored_windows")
                exact *= model.counts.get(plaintext[start:start + model.order], 0) * q + p
            evaluated += 1
            key_text = "".join(alphabet[v] for v in key)
            representation = (labelled, key_text)
            old = retained.get(plaintext)
            if old is not None and representation >= old["representation"]:
                continue
            if old is None and len(retained) >= top:
                worst = max(retained, key=lambda text: (-retained[text]["exact"], text))
                if (-exact, plaintext) >= (-retained[worst]["exact"], worst):
                    continue
                del retained[worst]
            retained[plaintext] = dict(exact=exact, representation=representation, route=route,
                                        key=key_text + alphabet[0] * (period - used))

    def search(domains, requirements, chosen, keys):
        budget.tick("route_nodes")
        if len(chosen) == w:
            visit(chosen, keys)
            return
        taken = set(chosen)
        # A perfect matching is a necessary condition only. Full route branches
        # still enforce all shared-key equations; matching is not a relaxation
        # that can create accepted candidates.
        current = []
        for slot, domain in enumerate(domains):
            current.append((chosen[slot],) if slot < len(chosen) else tuple(
                col for col in domain if col not in taken and all(
                    keys[phase] is None or keys[phase] == value
                    for phase, value in requirements[slot, col])))
        if columnar._matching(current, budget) is None:
            budget.work["matching_rejections"] += 1
            return
        slot = len(chosen)
        for col in current[slot]:
            child = list(keys)
            for phase, value in requirements[slot, col]:
                child[phase] = value
            search(current, requirements, chosen + [col], child)

    def evaluate(pattern):
        nonlocal segmentations
        if segmentations >= max_segmentations:
            raise _Limit("max_segmentations")
        segmentations += 1
        offset, domains, requirements = 0, [], {}
        for slot, length in enumerate(pattern):
            domain = []
            for col, positions in enumerate(columns):
                budget.tick("compatibility_pairs")
                if len(positions) != length:
                    continue
                requirements_here, valid = {}, True
                for vertical, i in enumerate(positions):
                    if i not in known:
                        continue
                    j = offset + vertical
                    c, plain = cvalues[j], index[known[i]]
                    value = (c + plain if cipher == "beaufort" else plain - c if cipher == "variant" else c - plain) % 26
                    phase = (i if order == "ST" else j) % period
                    if phase in requirements_here and requirements_here[phase] != value:
                        valid = False
                        break
                    requirements_here[phase] = value
                if valid:
                    domain.append(col)
                    requirements[slot, col] = tuple(requirements_here.items())
            domains.append(tuple(domain))
            offset += length
        search(domains, requirements, [], [None] * used)

    def segment(pattern):
        budget.tick("segmentation_nodes")
        if len(pattern) == w:
            evaluate(pattern)
            return
        for length in sorted(multiplicities):
            if multiplicities[length]:
                multiplicities[length] -= 1
                segment(pattern + [length])
                multiplicities[length] += 1

    try:
        segment([])
    except _Limit as error:
        complete, reason = False, str(error)
    candidates = []
    for plaintext, row in sorted(retained.items(), key=lambda pair: (-pair[1]["exact"], pair[0])):
        substitution = dict(operation="repeat_substitution", cipher=cipher, key_pattern=row["key"])
        gather = dict(operation="gather", permutation=row["route"])
        recipe = dict(schema="kryptos.encryption-recipe.v1", alphabet=alphabet, index_origin=0,
                      stages=[substitution, gather] if order == "ST" else [gather, substitution])
        replay = replay_recipe(plaintext, recipe)
        if replay["ciphertext"] != ciphertext:
            raise AssertionError("independent literal reencryption failed")
        display = model.score(plaintext, score_mask)
        candidates.append(dict(plaintext=plaintext, column_order=list(row["representation"][0]),
            key_pattern=row["key"], permutation=row["route"], encryption_recipe=recipe,
            score_exact=hex(row["exact"]), score=display.mean_log_probability,
            score_available=display.available, classification="ranked_model_consistency_witness",
            evidence=dict(literal_reencryption_matches=True, crib_matches=len(known),
                          stage_outputs=replay["stages"], authenticated_solution=False)))
    return dict(schema="kryptos.joint-ranked.v1", complete=complete, truncated=not complete,
        stop_reason=reason, feasible=True if evaluated else False if complete else None,
        top_k_exact=complete, ranking_exact_over_evaluated=True,
        total_column_orders=orders if complete else None,
        total_order_key_assignments=evaluated if complete else None,
        column_orders_visited=orders, compatible_assignment_lower_bound=visited_order_assignments,
        evaluated=evaluated, candidates=candidates, segmentations_tested=segmentations,
        bounds=bounds, work=dict(budget.work), assumptions=assumptions,
        unused_key_slots=list(range(used, period)),
        scoring=dict(model_id=model.model_id, score_mask=score_mask, windows=len(starts),
                     score_available=bool(starts), alpha_numerator=str(p), alpha_denominator=str(q),
                     comparison="Exact product(count*q+p), then plaintext lexical order; duplicate plaintexts merged. Representative ties use labelled column order, then used-key lexical order."),
        provenance=dict(normalized_input_sha256=_digest(dict(ciphertext=ciphertext, cribs=known,
                        assumptions=assumptions, bounds=bounds, score_mask=score_mask, model_id=model.model_id))),
        elapsed_seconds=time.monotonic() - started, authenticated_solution=False,
        interpretation="Only an exhausted declared family certifies its distinct-plaintext top-k. Truncated results rank evaluated completions only; no global score bound or solution authentication is inferred.")


def run_joint_ranked(request, target_fn):
    """Strict CLI adapter; the app separately allowlists model paths."""
    options = {"period", "order", "cipher", "alphabet", "width", "cells", "column_direction", "top",
               "max_segmentations", "max_states", "max_orders", "max_evaluations", "time_limit_seconds", "score_mask"}
    if not isinstance(request, dict) or set(request) - options - {"target", "ciphertext", "cribs", "model_path"}:
        raise ValueError("unknown ranked-joint request field")
    if "period" not in request or not isinstance(request.get("model_path"), str):
        raise ValueError("ranked joint requires period and model_path")
    target, ciphertext, cribs, _ = target_fn(request)
    path = Path(request["model_path"])
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("model exceeds64MiB")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    model = CharacterNgramModel.from_json(raw.decode("utf-8"))
    result = rank_joint_columnar(ciphertext, cribs, model=model,
                                 **{key: request[key] for key in options if key in request})
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError("scoring model changed during ranked search")
    result.update(target=target, model_file_sha256=digest, model_id=model.model_id)
    return result
