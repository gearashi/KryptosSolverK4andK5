"""Bounded exact inference of a whole-column order and a repeating key.

Cribs constrain the original plaintext, and gather means output[j]=input[pi[j]].
One supplied period and one known shared alphabet define each finite model.
Unknown key values remain unknown; no language score eliminates assignments.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import string
import time

from . import columnar

ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
FULL = (1 << 26) - 1


class _Stop(Exception):
    pass


class _Budget:
    def __init__(self, limit, seconds):
        self.limit, self.deadline = limit, time.monotonic() + seconds
        names = ("states", "segmentation_nodes", "segmentations_tested", "compatibility_pairs",
                 "matching_edge_visits", "support_edge_visits", "supported_edges_removed",
                 "count_states", "memo_hits", "factorial_components", "enumeration_nodes",
                 "search_nodes", "phase_edge_checks", "phase_support_checks", "propagation_rounds",
                 "internal_edge_conflicts", "key_incompatible_edges_removed", "key_values_removed",
                 "matching_rejections", "phase_support_rejections", "branches", "factorized_blocks")
        self.work = dict.fromkeys(names, 0)

    def tick(self, name):
        if time.monotonic() >= self.deadline:
            raise _Stop("time_limit_seconds")
        if self.work["states"] >= self.limit:
            raise _Stop("max_states")
        self.work["states"] += 1
        self.work[name] += 1


def _values(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask -= bit


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _primitive(key):
    if "?" in key:
        return None
    return next(key[:size] for size in range(1, len(key) + 1)
                if len(key) % size == 0 and key == key[:size] * (len(key) // size))


def _key_value(c, p, cipher):
    return (c + p if cipher == "beaufort" else p - c if cipher == "variant" else c - p) % 26


def _plain_value(c, k, cipher):
    return (k - c if cipher == "beaufort" else c + k if cipher == "variant" else c - k) % 26


def _propagate(domains, key_domains, requirements, budget):
    """Sound joint propagation; a perfect matching alone is not a joint fit."""
    domains, key_domains = list(domains), list(key_domains)
    while True:
        budget.tick("propagation_rounds")
        old = (tuple(domains), tuple(key_domains))
        filtered = []
        for slot, domain in enumerate(domains):
            kept = []
            for col in domain:
                compatible = True
                for phase, value in requirements[slot, col]:
                    budget.tick("phase_edge_checks")
                    if not key_domains[phase] & (1 << value):
                        compatible = False
                        break
                if compatible:
                    kept.append(col)
                else:
                    budget.work["key_incompatible_edges_removed"] += 1
            filtered.append(tuple(kept))
        matching = columnar._matching(filtered, budget)
        if matching is None:
            budget.work["matching_rejections"] += 1
            return None
        domains = columnar._supported(filtered, matching, budget)
        # Every output slot and every source column must select an incident
        # edge. Union of edge supports, intersected over these groups, is safe.
        groups = [[(slot, col) for col in domain] for slot, domain in enumerate(domains)]
        groups += [[(slot, col) for slot, domain in enumerate(domains) if col in domain]
                   for col in range(len(domains))]
        active_phases = sorted({phase for group in groups[:len(domains)]
                                for edge in group for phase, _ in requirements[edge]})
        for phase in active_phases:
            allowed = key_domains[phase]
            for group in groups:
                union = 0
                for edge in group:
                    budget.tick("phase_support_checks")
                    req = dict(requirements[edge])
                    union |= (1 << req[phase]) if phase in req else FULL
                    if union == FULL:
                        break
                allowed &= union
                if not allowed:
                    budget.work["phase_support_rejections"] += 1
                    return None
            budget.work["key_values_removed"] += key_domains[phase].bit_count() - allowed.bit_count()
            key_domains[phase] = allowed
        if old == (tuple(domains), tuple(key_domains)):
            return domains, key_domains, matching


def recover_joint_columnar(ciphertext, cribs, *, period, order="ST", cipher="vigenere",
                            alphabet="kryptos", width=None, cells=None,
                            column_direction="top_to_bottom", max_segmentations=2048,
                            max_states=200000, max_candidates=20, time_limit_seconds=5):
    """Recover exact bounded order/key families for one declared period.

    ST substitutes before gathering; TS substitutes after gathering. Counted
    key phases are only those visited by the finite message. The storage cap
    limits saved order families, not counting. Complete inferred periodic keys
    get shortest-period metadata; raw counts are never silently quotiented.
    """
    ciphertext, known, occupied, labels, columns = columnar._inputs(ciphertext, cribs, width, cells, column_direction)
    columnar._integer(period, "period", 1, 256)
    for value, name, low, high in ((max_segmentations, "max_segmentations", 1, 1_000_000),
                                  (max_states, "max_states", 1, 5_000_000),
                                  (max_candidates, "max_candidates", 0, 1000)):
        columnar._integer(value, name, low, high)
    if order not in ("ST", "TS") or cipher not in ("vigenere", "beaufort", "variant"):
        raise ValueError("order must be ST/TS and cipher must be vigenere/beaufort/variant")
    if not isinstance(alphabet, str):
        raise ValueError("alphabet must name a known uppercase A-Z permutation")
    alphabet = ALPHABETS.get(alphabet, alphabet)
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be an uppercase A-Z permutation")
    if isinstance(time_limit_seconds, bool) or not isinstance(time_limit_seconds, (int, float)) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time_limit_seconds must be finite, positive and at most600")
    n, w, used = len(ciphertext), len(columns), min(period, len(ciphertext))
    index = {c: i for i, c in enumerate(alphabet)}
    cvalues = [index[c] for c in ciphertext]
    known_values = {i: index[c] for i, c in known.items()}
    lengths = [len(col) for col in columns]
    multiplicities = Counter(lengths)
    pattern_count = math.factorial(w) // math.prod(math.factorial(v) for v in multiplicities.values())
    bounds = {"max_segmentations": max_segmentations, "max_states": max_states,
              "max_candidates": max_candidates, "time_limit_seconds": time_limit_seconds}
    assumptions = {"order": order, "cipher": cipher, "alphabet": alphabet, "declared_period": period,
                   "cells_in_plaintext_order": [list(c) for c in occupied], "column_direction": column_direction,
                   "known_plaintext": [{"position": i + 1, "letter": c} for i, c in known.items()]}
    source_hashes = {Path(p).name: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                     for p in (__file__, columnar.__file__)}
    provenance = {"normalized_request_sha256": _digest({"ciphertext": ciphertext, "assumptions": assumptions, "bounds": bounds}),
                  "source_sha256": source_hashes}
    budget = _Budget(max_states, time_limit_seconds)
    order_count = assignment_count = order_lower = assignment_lower = 0
    max_one_order_plaintexts = 0
    candidates, saved_orders = [], set()
    plain_domains = [set() for _ in range(n)]
    key_marginals = [0] * used
    column_domains = [set() for _ in range(w)]
    complete, reason = True, None

    def save(column_ids, key_domains):
        if len(candidates) >= max_candidates or tuple(column_ids) in saved_orders:
            return
        permutation = [i for col in column_ids for i in columns[col]]
        key_pattern = "".join(alphabet[next(_values(mask))] if mask.bit_count() == 1 else "?"
                              for mask in key_domains) + "?" * (period - used)
        plain_mask = ["?"] * n
        for j, i in enumerate(permutation):
            phase = (i if order == "ST" else j) % period
            if key_domains[phase].bit_count() == 1:
                plain_mask[i] = alphabet[_plain_value(cvalues[j], next(_values(key_domains[phase])), cipher)]
        plain_mask = "".join(plain_mask)
        message_complete = "?" not in plain_mask
        substitution = {"operation": "repeat_substitution", "cipher": cipher, "key_pattern": key_pattern}
        gather = {"operation": "gather", "permutation": permutation}
        recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": alphabet,
                  "index_origin": 0, "stages": [substitution, gather] if order == "ST" else [gather, substitution]}
        trace, encrypted, signature = [], None, None
        if message_complete:
            text = plain_mask
            for number, stage in enumerate(recipe["stages"], 1):
                if stage["operation"] == "gather":
                    text = "".join(text[i] for i in permutation)
                else:
                    out = []
                    for i, c in enumerate(text):
                        p, k = index[c], index[key_pattern[i % period]]
                        value = k - p if cipher == "beaufort" else p - k if cipher == "variant" else p + k
                        out.append(alphabet[value % 26])
                    text = "".join(out)
                trace.append({"stage": number, "operation": stage["operation"], "output": text,
                              "sha256": hashlib.sha256(text.encode()).hexdigest()})
            encrypted = text
            assert encrypted == ciphertext and all(plain_mask[i] == c for i, c in known.items())
            shift = [next(_values(key_domains[(i if order == "ST" else j) % period]))
                     for j, i in enumerate(permutation)]
            if cipher == "variant":
                shift = [-value % 26 for value in shift]
            signature = _digest({"alphabet": alphabet, "permutation": permutation,
                                 "plaintext_sign": -1 if cipher == "beaufort" else 1,
                                 "shifts_at_output": shift})
        canonical = _primitive(key_pattern)
        candidates.append({"classification": "consistent_complete_candidate" if message_complete else "partial_key_family",
                           "plaintext": plain_mask if message_complete else None, "plaintext_mask": plain_mask,
                           "column_order": [labels[col] for col in column_ids], "permutation": permutation,
                           "key_pattern": key_pattern, "key_domains": [list(_values(mask)) for mask in key_domains],
                           "used_key_assignment_count": math.prod(mask.bit_count() for mask in key_domains),
                           "unused_key_slots": list(range(used, period)), "declared_period": period,
                           "canonical_key": canonical, "canonical_period": len(canonical) if canonical else None,
                           "finite_encryption_signature": signature,
                           "encryption_recipe": recipe, "recipe_complete_for_message": message_complete,
                           "reencrypted_ciphertext": encrypted,
                           "evidence": {"literal_reencryption_matches": True if message_complete else None,
                                        "stage_outputs": trace, "crib_matches": len(known),
                                        "external_verification_performed": False},
                           "technique_summary": "Joint crib-derived key constraints and all-different column matching; exact supported-edge propagation and bounded branching.",
                           "supplied_assumptions": assumptions, "provenance": provenance,
                           "authenticated_solution": False})
        saved_orders.add(tuple(column_ids))

    def factor_block(domains, key_domains, matching, offsets):
        nonlocal order_count, assignment_count, order_lower, assignment_lower, max_one_order_plaintexts
        # All remaining edge equations are implied by singleton key domains.
        # Therefore perfect matchings and the remaining key choices factor.
        weight = math.prod(mask.bit_count() for mask in key_domains)
        order_lower += 1
        assignment_lower += weight
        max_one_order_plaintexts = max(max_one_order_plaintexts, weight)
        save(matching, key_domains)
        parts = [columnar._component_counter(slots, cols, domains, budget)
                 for slots, cols in columnar._components(domains)]
        count = math.prod(part["total"] for part in parts)
        assert count > 0
        order_count += count
        assignment_count += count * weight
        order_lower += count - 1
        assignment_lower += (count - 1) * weight
        budget.work["factorized_blocks"] += 1
        for phase, mask in enumerate(key_domains):
            key_marginals[phase] |= mask
        for slot, domain in enumerate(domains):
            column_domains[slot].update(labels[col] for col in domain)
            for col in domain:
                for vertical, i in enumerate(columns[col]):
                    j = offsets[slot] + vertical
                    phase = (i if order == "ST" else j) % period
                    plain_domains[i].update(alphabet[_plain_value(cvalues[j], k, cipher)]
                                            for k in _values(key_domains[phase]))
        if len(candidates) < max_candidates:
            for column_ids in columnar._orders(parts, w, budget):
                save(column_ids, key_domains)
                if len(candidates) >= max_candidates:
                    break

    def search(domains, key_domains, requirements, offsets):
        budget.tick("search_nodes")
        propagated = _propagate(domains, key_domains, requirements, budget)
        if propagated is None:
            return
        domains, key_domains, matching = propagated
        coupled = [(slot, col) for slot, domain in enumerate(domains) for col in domain
                   if any(key_domains[phase].bit_count() != 1 for phase, _ in requirements[slot, col])]
        if not coupled:
            factor_block(domains, key_domains, matching, offsets)
            return
        choices = sorted({slot for slot, _ in coupled if len(domains[slot]) > 1})
        assert choices
        slot = min(choices, key=lambda s: (len(domains[s]),
                   -sum(len(requirements[s, col]) for col in domains[s]), s))
        for col in domains[slot]:
            budget.work["branches"] += 1
            child = list(domains)
            child[slot] = (col,)
            search(child, key_domains, requirements, offsets)

    def evaluate(pattern):
        if budget.work["segmentations_tested"] >= max_segmentations:
            raise _Stop("max_segmentations")
        budget.work["segmentations_tested"] += 1
        offsets, domains, requirements = [], [], {}
        start = 0
        for slot, length in enumerate(pattern):
            offsets.append(start)
            domain = []
            for col in range(w):
                budget.tick("compatibility_pairs")
                if lengths[col] != length:
                    continue
                req, consistent = {}, True
                for vertical, i in enumerate(columns[col]):
                    if i not in known_values:
                        continue
                    j = start + vertical
                    phase = (i if order == "ST" else j) % period
                    k = _key_value(cvalues[j], known_values[i], cipher)
                    if phase in req and req[phase] != k:
                        consistent = False
                        budget.work["internal_edge_conflicts"] += 1
                        break
                    req[phase] = k
                if consistent:
                    domain.append(col)
                    requirements[slot, col] = tuple(sorted(req.items()))
            domains.append(tuple(domain))
            start += length
        search(domains, [FULL] * used, requirements, offsets)

    def segment(pattern):
        budget.tick("segmentation_nodes")
        if len(pattern) == w:
            evaluate(pattern)
            return
        for length in sorted(multiplicities):
            if multiplicities[length]:
                multiplicities[length] -= 1
                pattern.append(length)
                segment(pattern)
                pattern.pop()
                multiplicities[length] += 1

    try:
        segment([])
    except _Stop as exc:
        complete, reason = False, str(exc)
    feasible = bool(order_lower) if complete or order_lower else None
    mask = "".join(next(iter(d)) if len(d) == 1 else "?" for d in plain_domains) if complete and feasible else None
    unique_plaintext = ("?" not in mask) if mask is not None else (False if complete else None)
    all_orders_stored = complete and order_count == len(candidates)
    all_keys_resolved = all(row["recipe_complete_for_message"] for row in candidates)
    distinct_plaintexts = (0 if complete and not feasible else 1 if unique_plaintext else
                           assignment_count if complete and order_count == 1 else
                           len({row["plaintext"] for row in candidates}) if all_orders_stored and all_keys_resolved else None)
    return {"schema": "kryptos.joint-columnar.v1", "complete": complete, "truncated": not complete,
            "stop_reason": reason, "feasible": feasible,
            "total_column_orders": order_count if complete else None,
            "total_order_key_assignments": assignment_count if complete else None,
            "column_order_lower_bound": order_lower, "order_key_assignment_lower_bound": assignment_lower,
            "distinct_plaintext_count": distinct_plaintexts,
            "distinct_plaintext_lower_bound": max_one_order_plaintexts,
            "unique_plaintext_within_family": unique_plaintext,
            "column_domains": [sorted(d) for d in column_domains] if complete and feasible else None,
            "forced_columns": [{"output_slot": i, "column": next(iter(d))} for i, d in enumerate(column_domains) if len(d) == 1]
                              if complete and feasible else None,
            "plaintext_domains": ["".join(sorted(d)) for d in plain_domains] if complete and feasible else None,
            "forced_plaintext_mask": mask,
            "key_domains": [list(_values(d)) for d in key_marginals] if complete and feasible else None,
            "unused_key_slots": list(range(used, period)), "declared_period": period,
            "column_labels": labels, "column_lengths": lengths, "distinct_length_segmentations": pattern_count,
            "candidates": candidates, "all_column_orders_stored": all_orders_stored,
            "count_convention": "Labelled column orders and assignments to key phases used by this finite message, within one declared period. No quotient by repeated keys or equal plaintexts.",
            "cross_period_convention": "Do not sum model counts across periods. Complete inferred keys expose shortest-period metadata and a finite encryption signature for duplicate detection; partial keys are not canonicalized.",
            "bounds": bounds, "work": budget.work, "assumptions": assumptions, "provenance": provenance,
            "authenticated_solution": False,
            "limits": ["One supplied geometry, column direction, alphabet, cipher rule, layer order and period are assumed.",
                       "Only crib-consistent order/key families are tested; language scores do not prune.",
                       "Unknown key phases and plaintext positions remain unresolved, even in saved candidate families.",
                       "Global marginals and exact counts are withheld on truncation.",
                       "Literal reencryption establishes model consistency, not authenticity."]}
