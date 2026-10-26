"""Exact, bounded crib-guided recovery of an unknown whole-column order.

The supplied cells, in original plaintext stream order, are filled without
padding. Encryption reads each occupied column in a supplied vertical direction,
then concatenates columns in an unknown order. No substitution is inferred.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import string
import time


def _integer(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _letters(value, label):
    if not isinstance(value, str) or any(c not in string.ascii_letters and not c.isspace() for c in value):
        raise ValueError(f"{label} must contain ASCII letters and optional whitespace only")
    value = "".join(value.split()).upper()
    if not 1 <= len(value) <= 4096:
        raise ValueError(f"{label} must contain between 1 and 4096 letters")
    return value


def _inputs(ciphertext, cribs, width, cells, direction):
    ciphertext = _letters(ciphertext, "ciphertext")
    n = len(ciphertext)
    if not isinstance(cribs, (list, tuple)):
        raise ValueError("cribs must be a list of {start: one-based position, text: letters}")
    known = {}
    for crib in cribs:
        if not isinstance(crib, dict):
            raise ValueError("each crib must be an object")
        start = _integer(crib.get("start"), "crib start", 1, n) - 1
        text = _letters(crib.get("text"), "crib text")
        if start + len(text) > n:
            raise ValueError("crib extends beyond the ciphertext")
        for i, c in enumerate(text, start):
            if i in known and known[i] != c:
                raise ValueError(f"contradictory cribs at position {i + 1}")
            known[i] = c
    if (width is None) == (cells is None):
        raise ValueError("supply exactly one of width or cells")
    if width is not None:
        _integer(width, "width", 1, min(n, 64))
        cells = [(i // width, i % width) for i in range(n)]
    elif not isinstance(cells, (list, tuple)) or len(cells) != n:
        raise ValueError("cells must contain one (row, column) pair per plaintext position")
    occupied = []
    for cell in cells:
        if not isinstance(cell, (list, tuple)) or len(cell) != 2:
            raise ValueError("each cell must be a (row, column) pair")
        occupied.append(tuple(_integer(x, "cell coordinate", -1_000_000, 1_000_000) for x in cell))
    if len(set(occupied)) != n:
        raise ValueError("occupied cells must be distinct")
    labels = sorted({c for _, c in occupied})
    if len(labels) > 64:
        raise ValueError("at most 64 occupied columns are supported")
    if direction not in ("top_to_bottom", "bottom_to_top"):
        raise ValueError("column_direction must be top_to_bottom or bottom_to_top")
    columns = [sorted((i for i, (_, c) in enumerate(occupied) if c == label),
                      key=lambda i: occupied[i][0], reverse=direction == "bottom_to_top")
               for label in labels]
    return ciphertext, dict(sorted(known.items())), occupied, labels, columns


class _Stop(Exception):
    pass


class _Budget:
    def __init__(self, limit, seconds):
        self.limit = limit
        self.deadline = time.monotonic() + seconds
        self.work = {name: 0 for name in (
            "states", "segmentation_nodes", "compatibility_pairs", "matching_edge_visits",
            "support_edge_visits", "count_states", "enumeration_nodes", "segmentations_tested",
            "feasible_segmentations", "rejected_segmentations", "supported_edges_removed",
            "memo_hits", "factorial_components")}

    def tick(self, name):
        if time.monotonic() >= self.deadline:
            raise _Stop("time_limit_seconds")
        if self.work["states"] >= self.limit:
            raise _Stop("max_states")
        self.work["states"] += 1
        self.work[name] += 1


def _matching(domains, budget):
    """One perfect matching, or None. Slots and column IDs are zero-based."""
    w = len(domains)
    owner = [-1] * w

    def augment(slot, seen):
        for col in domains[slot]:
            budget.tick("matching_edge_visits")
            if col in seen:
                continue
            seen.add(col)
            if owner[col] < 0 or augment(owner[col], seen):
                owner[col] = slot
                return True
        return False

    for slot in sorted(range(w), key=lambda s: (len(domains[s]), s)):
        if not augment(slot, set()):
            return None
    answer = [-1] * w
    for col, slot in enumerate(owner):
        answer[slot] = col
    return answer


def _supported(domains, matching, budget):
    """Keep precisely edges belonging to at least one perfect matching.

    Relative to a perfect matching, any additional usable edge lies on an
    alternating cycle. Directed strongly connected components find all of them.
    """
    w = len(domains)
    graph = [[] for _ in range(2 * w)]
    reverse = [[] for _ in graph]
    for slot, domain in enumerate(domains):
        for col in domain:
            budget.tick("support_edge_visits")
            a, b = (w + col, slot) if matching[slot] == col else (slot, w + col)
            graph[a].append(b)
            reverse[b].append(a)
    visited, order = set(), []

    def visit(v):
        if v in visited:
            return
        visited.add(v)
        for nxt in graph[v]:
            visit(nxt)
        order.append(v)

    for v in range(2 * w):
        visit(v)
    component = [-1] * (2 * w)

    def assign(v, label):
        if component[v] >= 0:
            return
        component[v] = label
        for nxt in reverse[v]:
            assign(nxt, label)

    for v in reversed(order):
        if component[v] < 0:
            assign(v, v)
    supported = [tuple(col for col in domain
                       if matching[slot] == col or component[slot] == component[w + col])
                 for slot, domain in enumerate(domains)]
    budget.work["supported_edges_removed"] += sum(map(len, domains)) - sum(map(len, supported))
    return supported


def _components(domains):
    by_col = [[] for _ in domains]
    for slot, domain in enumerate(domains):
        for col in domain:
            by_col[col].append(slot)
    seen = set()
    result = []
    for first in range(len(domains)):
        if first in seen:
            continue
        pending, slots, cols = [first], set(), set()
        while pending:
            slot = pending.pop()
            if slot in slots:
                continue
            slots.add(slot)
            for col in domains[slot]:
                cols.add(col)
                pending.extend(other for other in by_col[col] if other not in slots)
        seen.update(slots)
        assert len(slots) == len(cols)
        result.append((sorted(slots, key=lambda s: (len(domains[s]), s)), sorted(cols)))
    return result


def _component_counter(slots, cols, domains, budget):
    local = {col: i for i, col in enumerate(cols)}
    masks = [sum(1 << local[c] for c in domains[slot]) for slot in slots]
    size = len(slots)
    complete = all(mask == (1 << size) - 1 for mask in masks)
    if complete:
        budget.work["factorial_components"] += 1

    @lru_cache(maxsize=None)
    def count(used):
        budget.tick("count_states")
        row = used.bit_count()
        if complete:
            return math.factorial(size - row)
        if row == size:
            return 1
        available = masks[row] & ~used
        total = 0
        while available:
            bit = available & -available
            available -= bit
            total += count(used | bit)
        return total

    total = count(0)
    budget.work["memo_hits"] += count.cache_info().hits
    return {"slots": slots, "cols": cols, "masks": masks, "count": count, "total": total}


def _orders(parts, width, budget):
    """Enumerate representatives only through prefixes with a positive count."""
    assignment = [-1] * width

    def fill(part_index, row=0, used=0):
        budget.tick("enumeration_nodes")
        if part_index == len(parts):
            yield list(assignment)
            return
        part = parts[part_index]
        if row == len(part["slots"]):
            yield from fill(part_index + 1)
            return
        available = part["masks"][row] & ~used
        while available:
            bit = available & -available
            available -= bit
            if part["count"](used | bit):
                assignment[part["slots"][row]] = part["cols"][bit.bit_length() - 1]
                yield from fill(part_index, row + 1, used | bit)

    yield from fill(0)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def recover_column_order(ciphertext, cribs, *, width=None, cells=None,
                         column_direction="top_to_bottom", max_segmentations=2048,
                         max_states=200000, max_candidates=20, time_limit_seconds=5):
    """Recover possible whole-column reading orders, with rigorous finite bounds.

    Cribs refer to one-based original plaintext positions. ``width`` supplies a
    row-filled rectangle with a possibly short last row; alternatively ``cells``
    explicitly identifies every occupied source cell. No cells are invented.
    ``max_candidates`` limits saved witnesses only, not exact solution counting.
    On truncation all global forced assignments/domains are withheld.
    """
    ciphertext, known, cells, labels, columns = _inputs(ciphertext, cribs, width, cells, column_direction)
    _integer(max_segmentations, "max_segmentations", 1, 1_000_000)
    _integer(max_states, "max_states", 1, 5_000_000)
    _integer(max_candidates, "max_candidates", 0, 1000)
    if isinstance(time_limit_seconds, bool) or not isinstance(time_limit_seconds, (int, float)) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time_limit_seconds must be finite, positive, and at most 600")
    budget = _Budget(max_states, time_limit_seconds)
    bounds = {"max_segmentations": max_segmentations, "max_states": max_states,
              "max_candidates": max_candidates, "time_limit_seconds": time_limit_seconds}
    assumptions = {"model": "pure whole-column transposition of supplied occupied cells",
                   "cells_in_plaintext_order": [list(c) for c in cells],
                   "column_direction": column_direction,
                   "known_plaintext": [{"position": i + 1, "letter": c} for i, c in known.items()]}
    request_hash = _digest({"ciphertext": ciphertext, "assumptions": assumptions, "bounds": bounds})
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    lengths = [len(c) for c in columns]
    multiplicities = Counter(lengths)
    pattern_count = math.factorial(len(columns))
    for count in multiplicities.values():
        pattern_count //= math.factorial(count)
    constraints = [[(offset, known[i]) for offset, i in enumerate(col) if i in known] for col in columns]
    candidates, saved_orders = [], set()
    column_domains = [set() for _ in columns]
    plaintext_domains = [set() for _ in ciphertext]
    exact_count, lower_bound = 0, 0
    reason = None
    complete = True
    inventory = Counter(ciphertext)
    shortage = [{"letter": c, "required_by_cribs": count, "available_in_ciphertext": inventory[c]}
                for c, count in sorted(Counter(known.values()).items()) if count > inventory[c]]

    def save(order):
        if len(candidates) >= max_candidates or tuple(order) in saved_orders:
            return
        permutation = [i for col in order for i in columns[col]]
        plaintext = [""] * len(ciphertext)
        for output, original in enumerate(permutation):
            plaintext[original] = ciphertext[output]
        plaintext = "".join(plaintext)
        encrypted = "".join(plaintext[i] for i in permutation)
        assert encrypted == ciphertext and all(plaintext[i] == c for i, c in known.items())
        labelled_order = [labels[col] for col in order]
        recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": string.ascii_uppercase,
                  "index_origin": 0, "arithmetic": "none (pure transposition)",
                  "stages": [{"operation": "gather", "permutation": permutation,
                              "formula": "output[j] = input[permutation[j]]"}]}
        candidates.append({"classification": "consistent_complete_candidate", "plaintext": plaintext,
                           "column_order": labelled_order, "permutation": permutation,
                           "recipe": recipe, "reencrypted_ciphertext": encrypted, "reencryption_matches": True,
                           "authenticated": False,
                           "technique_summary": "Split ciphertext at possible column lengths; solve the crib-compatible all-different column assignment exactly.",
                           "supplied_assumptions": assumptions,
                           "recovered_values": {"possible_column_order": labelled_order},
                           "provenance": {"normalized_request_sha256": request_hash,
                                          "source_sha256": source_hash},
                           "interpretation": "A full consistency witness. Other column orders or plaintexts may also fit; consult the exhaustive result and domains."})
        saved_orders.add(tuple(order))

    def evaluate(pattern):
        nonlocal exact_count, lower_bound
        if budget.work["segmentations_tested"] >= max_segmentations:
            raise _Stop("max_segmentations")
        budget.work["segmentations_tested"] += 1
        offset, chunks, domains = 0, [], []
        for length in pattern:
            chunk = ciphertext[offset:offset + length]
            chunks.append(chunk)
            offset += length
            domain = []
            for col in range(len(columns)):
                budget.tick("compatibility_pairs")
                if lengths[col] == length and all(chunk[k] == c for k, c in constraints[col]):
                    domain.append(col)
            domains.append(tuple(domain))
        matching = _matching(domains, budget)
        if matching is None:
            budget.work["rejected_segmentations"] += 1
            return
        budget.work["feasible_segmentations"] += 1
        lower_bound += 1
        save(matching)
        supported = _supported(domains, matching, budget)
        parts = [_component_counter(slots, cols, supported, budget) for slots, cols in _components(supported)]
        count = math.prod(part["total"] for part in parts)
        assert count > 0
        exact_count += count
        lower_bound += count - 1
        for slot, domain in enumerate(supported):
            column_domains[slot].update(labels[col] for col in domain)
            for col in domain:
                for k, original in enumerate(columns[col]):
                    plaintext_domains[original].add(chunks[slot][k])
        if len(candidates) < max_candidates:
            for order in _orders(parts, len(columns), budget):
                save(order)
                if len(candidates) >= max_candidates:
                    break

    def segment(pattern):
        budget.tick("segmentation_nodes")
        if len(pattern) == len(columns):
            evaluate(pattern)
            return
        for length in sorted(multiplicities):
            if multiplicities[length]:
                multiplicities[length] -= 1
                pattern.append(length)
                segment(pattern)
                pattern.pop()
                multiplicities[length] += 1

    if not shortage:
        try:
            segment([])
        except _Stop as exc:
            complete, reason = False, str(exc)
    feasible = bool(lower_bound) if complete or lower_bound else None
    forced_mask = "".join(next(iter(d)) if len(d) == 1 else "?" for d in plaintext_domains) if complete and feasible else None
    forced_columns = ([{"output_slot": slot, "column": next(iter(domain))}
                       for slot, domain in enumerate(column_domains) if len(domain) == 1]
                      if complete and feasible else None)
    stored_plaintexts = len({c["plaintext"] for c in candidates})
    candidates_complete = complete and exact_count == len(candidates)
    unique_plaintext = ("?" not in forced_mask) if forced_mask is not None else (False if complete else None)
    plaintext_count = (0 if complete and not feasible else
                       1 if unique_plaintext else stored_plaintexts if candidates_complete else None)
    return {"schema": "kryptos.column-order-recovery.v1", "complete": complete,
            "truncated": not complete, "stop_reason": reason, "feasible": feasible,
            "total_column_orders": exact_count if complete else None,
            "column_order_lower_bound": lower_bound, "total_distinct_plaintexts": plaintext_count,
            "unique_plaintext_within_family": unique_plaintext,
            "column_labels": labels, "column_lengths": lengths,
            "distinct_length_segmentations": pattern_count,
            "inventory_rejection": shortage or None,
            "column_domains": [sorted(d) for d in column_domains] if complete and feasible else None,
            "forced_columns": forced_columns,
            "plaintext_domains": ["".join(sorted(d)) for d in plaintext_domains] if complete and feasible else None,
            "forced_plaintext_mask": forced_mask,
            "supplied_crib_mask": "".join(known.get(i, "?") for i in range(len(ciphertext))),
            "candidates": candidates, "candidates_complete": candidates_complete,
            "stored_distinct_plaintexts": stored_plaintexts,
            "bounds": bounds, "work": budget.work,
            "provenance": {"normalized_request_sha256": request_hash, "source_sha256": source_hash},
            "assumptions": assumptions, "authenticated": False,
            "search_algorithm": "Distinct column-length segmentations; perfect matching; alternating-cycle supported-edge propagation; component-wise memoized exact counts with complete-component factorial shortcut.",
            "limits": ["Only the supplied occupied-cell geometry and vertical direction are tested.",
                       "No unknown substitution, column reversal, row order, or padding is inferred.",
                       "Counts distinguish column orders, not necessarily plaintexts. Stored candidates can be a subset.",
                       "Truncated searches do not expose global forced assignments or exact counts.",
                       "Reencryption establishes consistency with this model, not authenticity."]}
