"""Bounded exact cyclic constraints for supplied stage-specific alphabets.

Keys shared across stages are LETTER strings, not numeric alphabet indices.
Each intermediate symbol has an A-Z domain; propagation enforces the actual
Vigenere/Beaufort/variant equation in that stage's known alphabet. There is no
relaxation to an arbitrary substitution table and no unknown alphabet fitting.
"""
from collections import deque
import math
import string
from time import monotonic

from .general_layers import LayerBudgetExceeded
from .scheduled_layers import (normalize_stages, solve_scheduled, expanded_recipe,
                               replay_expanded)

LETTERS = string.ascii_uppercase
ALL = (1 << 26) - 1


class _Stop(Exception):
    pass


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _symbols(mask):
    while mask:
        bit = mask & -mask
        mask -= bit
        yield bit.bit_length() - 1


def _domain(mask):
    return "".join(LETTERS[i] for i in _symbols(mask))


def _equal_alphabet(ciphertext, known, normalized, alphabet, max_candidates, max_key_slots):
    solved = solve_scheduled(ciphertext, known, [s.to_dict() for s in normalized], alphabet,
                             max_key_slots=max_key_slots)
    summary = solved.summary()
    candidates = []
    if solved.feasible and max_candidates:
        if solved.distinct_plaintext_count <= max_candidates:
            candidates = [solved.candidate(a, b) for a, b, text in solved.enumerate_plaintexts(max_candidates)]
        else:
            candidates = [solved.candidate()]
    return {"method": "exact_equal_alphabet_linear_dispatch", "complete": True,
            "feasible": solved.feasible, "stop_reason": "exact_linear_family",
            "key_assignment_count": solved.key_assignment_count,
            "key_assignment_lower_bound": solved.key_assignment_count,
            "distinct_plaintext_count": solved.distinct_plaintext_count,
            "distinct_plaintext_lower_bound": solved.distinct_plaintext_count,
            "plaintext_domains": solved.plaintext_domains() if solved.feasible else None,
            "prediction_mask": solved.prediction_mask() if solved.feasible else None,
            "key_letter_domains": None, "key_domain_note": "Not calculated by linear dispatch; no key marginals are claimed.",
            "candidates": candidates, "candidates_complete": len(candidates) == solved.distinct_plaintext_count,
            "linear_summary": summary, "authenticated_solution": False,
            "interpretation": "The entire equal-alphabet family is characterized exactly; saved candidates may be a bounded set of consistency witnesses."}


def solve_mixed_stages(ciphertext, known, stages, *, max_key_slots=256, max_constraints=4096,
                       max_nodes=10000, max_relation_checks=2_000_000, max_candidates=20,
                       max_distinct_plaintexts=10000, time_limit_seconds=5.0,
                       dispatch_equal_alphabets=True):
    """Return exact counts/marginals on completion, otherwise valid lower bounds.

    Search branches only on used shared letter-key slots. Unused slots contribute
    a known factor26 each. Candidate saving never limits counting. A separate
    distinct-plaintext budget bounds the set needed for exact deduplication.
    Limits are cooperative and checked during propagation and branching.
    """
    started = monotonic()
    if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 4096 or any(c not in LETTERS for c in ciphertext):
        raise ValueError("ciphertext must contain1..4096 uppercase letters")
    n = len(ciphertext)
    if not isinstance(known, dict) or any(type(i) is not int or not 0 <= i < n
            or not isinstance(c, str) or len(c) != 1 or c not in LETTERS for i, c in known.items()):
        raise ValueError("known must map original zero-based positions to single letters")
    _integer(max_constraints, "max_constraints", 1, 65536)
    _integer(max_nodes, "max_nodes", 0, 1_000_000)
    _integer(max_relation_checks, "max_relation_checks", 1, 100_000_000)
    _integer(max_candidates, "max_candidates", 0, 1000)
    _integer(max_distinct_plaintexts, "max_distinct_plaintexts", 1, 100000)
    if type(dispatch_equal_alphabets) is not bool:
        raise ValueError("dispatch_equal_alphabets must be boolean")
    if (isinstance(time_limit_seconds, bool) or not isinstance(time_limit_seconds, (int, float))
            or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600):
        raise ValueError("time_limit_seconds must be finite and in(0,600]")
    normalized, layout = normalize_stages(n, stages, max_key_slots=max_key_slots)
    alphabets = {s.alphabet for s in normalized if s.operation == "substitution"}
    if dispatch_equal_alphabets and len(alphabets) <= 1:
        result = _equal_alphabet(ciphertext, known, normalized, next(iter(alphabets), LETTERS), max_candidates, max_key_slots)
        result["runtime_seconds"] = monotonic() - started
        result["dispatch_note"] = "Finite-domain search limits do not apply; pinned linear solver's explicit matrix/work bounds do."
        return result
    constraint_count = n * sum(s.operation == "substitution" for s in normalized)
    if constraint_count > max_constraints:
        raise LayerBudgetExceeded("mixed-stage constraint budget exceeded before search")
    width = sum(size for _, _, size in layout)
    starts = {key: start for key, start, size in layout}
    # Variable indices0..width-1 are shared LETTER-key slots; later indices are
    # the initial and intermediate letter variables. Gathers only reorder IDs.
    domains = [ALL] * (width + n)
    current = list(range(width, width + n))
    for i, c in known.items():
        domains[width + i] = 1 << LETTERS.index(c)
    constraints, tables, table_ids = [], [], {}
    used_keys = set()
    for stage_number, stage in enumerate(normalized):
        if stage.operation == "gather":
            current = [current[i] for i in stage.permutation]
            continue
        signature = (stage.alphabet, stage.cipher)
        if signature not in table_ids:
            alphabet = stage.alphabet
            index = {c: i for i, c in enumerate(alphabet)}
            table = []
            for x in LETTERS:
                row = []
                for k in LETTERS:
                    a, b = index[x], index[k]
                    value = a + b if stage.cipher == "vigenere" else b - a if stage.cipher == "beaufort" else a - b
                    row.append(LETTERS.index(alphabet[value % 26]))
                table.append(tuple(row))
            table_ids[signature] = len(tables)
            tables.append(tuple(table))
        output = []
        for position, x in enumerate(current):
            key = starts[stage.key_id] + stage.phases[position]
            y = len(domains)
            domains.append(ALL)
            output.append(y)
            used_keys.add(key)
            constraints.append((x, key, y, table_ids[signature], stage_number, position))
        current = output
    for j, var in enumerate(current):
        domains[var] &= 1 << LETTERS.index(ciphertext[j])
    adjacency = [[] for _ in domains]
    for number, constraint in enumerate(constraints):
        for var in constraint[:3]:
            adjacency[var].append(number)
    checks = nodes = propagations = 0
    key_count = 0
    texts, candidates = set(), []
    plaintext_union, key_union = [0] * n, [0] * width
    unused = sorted(set(range(width)) - used_keys)
    unused_multiplier = 26 ** len(unused)
    stop_reason, complete = "exhausted_exact_letter_key_space", True
    initial_conflict = None

    def checkpoint():
        if monotonic() - started >= time_limit_seconds:
            raise _Stop("time_limit_seconds")

    def propagate(state, initial):
        nonlocal checks, propagations
        if any(mask == 0 for mask in state):
            return False
        queue = deque(initial)
        queued = set(initial)
        while queue:
            checkpoint()
            number = queue.popleft()
            queued.discard(number)
            x, k, y, table_id, stage_number, position = constraints[number]
            supports_x = supports_k = supports_y = 0
            table = tables[table_id]
            propagations += 1
            for xv in _symbols(state[x]):
                for kv in _symbols(state[k]):
                    if checks >= max_relation_checks:
                        raise _Stop("max_relation_checks")
                    checks += 1
                    yv = table[xv][kv]
                    if state[y] & (1 << yv):
                        supports_x |= 1 << xv
                        supports_k |= 1 << kv
                        supports_y |= 1 << yv
            for var, support in ((x, supports_x), (k, supports_k), (y, supports_y)):
                if not support:
                    return False
                if support != state[var]:
                    state[var] = support
                    for neighbor in adjacency[var]:
                        if neighbor not in queued:
                            queue.append(neighbor)
                            queued.add(neighbor)
        return True

    def visit(state, queue):
        nonlocal nodes, key_count
        checkpoint()
        if nodes >= max_nodes:
            raise _Stop("max_nodes")
        nodes += 1
        if not propagate(state, queue):
            return
        unresolved = [var for var in used_keys if state[var].bit_count() > 1]
        if unresolved:
            var = min(unresolved, key=lambda i: (state[i].bit_count(), i))
            for value in _symbols(state[var]):
                child = list(state)
                child[var] = 1 << value
                visit(child, adjacency[var])
            return
        if any(state[width + i].bit_count() != 1 for i in range(n)):
            raise AssertionError("fixed keys and ciphertext did not determine a unique plaintext")
        text = "".join(_domain(state[width + i]) for i in range(n))
        novel = text not in texts
        if novel and len(texts) >= max_distinct_plaintexts:
            raise _Stop("max_distinct_plaintexts")
        keys = {key: "".join(_domain(state[i])[0] for i in range(start, start + size)) for key, start, size in layout}
        recipe = expanded_recipe(normalized, keys, n)
        replay = replay_expanded(text, recipe)
        if replay["ciphertext"] != ciphertext or any(text[i] != c for i, c in known.items()):
            raise AssertionError("mixed-stage solution failed exact literal equations")
        key_count += unused_multiplier
        for i in range(n):
            plaintext_union[i] |= state[width + i]
        for i in range(width):
            key_union[i] |= state[i]
        texts.add(text)
        if novel and len(candidates) < max_candidates:
            candidates.append({"plaintext": text, "keys_by_id": keys, "encryption_recipe": recipe,
                               "reencrypted_ciphertext": replay["ciphertext"], "stage_outputs": replay["stage_outputs"],
                               "reencryption_matches": True, "authenticated_solution": False})

    try:
        visit(domains, range(len(constraints)))
    except _Stop as error:
        complete, stop_reason = False, str(error)
    feasible = bool(key_count) if complete or key_count else None
    public_domains = [_domain(mask) for mask in plaintext_union] if complete and key_count else None
    return {"method": "exact_cyclic_relation_domains", "complete": complete, "feasible": feasible,
            "stop_reason": stop_reason, "normalized_stages": [s.to_dict() for s in normalized],
            "key_sharing_convention": "identical letter symbols; every stage uses its own known alphabet indices",
            "key_layout": [{"key_id": key, "slot_start": start, "key_length": size} for key, start, size in layout],
            "constraints": constraint_count, "symbol_variables": len(domains),
            "key_assignment_count": key_count if complete else None, "key_assignment_lower_bound": key_count,
            "distinct_plaintext_count": len(texts) if complete else None, "distinct_plaintext_lower_bound": len(texts),
            "plaintext_domains": public_domains,
            "prediction_mask": "".join(d if len(d) == 1 else "?" for d in public_domains) if public_domains is not None else None,
            "key_letter_domains": {key: [_domain(key_union[i]) for i in range(start, start + size)] for key, start, size in layout} if complete and key_count else None,
            "unreferenced_key_slots": unused, "unused_key_multiplier": unused_multiplier,
            "candidates": candidates, "candidates_complete": complete and len(candidates) == len(texts),
            "work": {"nodes": nodes, "relation_pairs_checked": checks, "constraints_propagated": propagations},
            "bounds": {"max_nodes": max_nodes, "max_relation_checks": max_relation_checks,
                       "max_candidates": max_candidates, "max_distinct_plaintexts": max_distinct_plaintexts,
                       "max_constraints": max_constraints, "max_key_slots": max_key_slots,
                       "time_limit_seconds": time_limit_seconds},
            "runtime_seconds": monotonic() - started, "authenticated_solution": False,
            "interpretation": "Exact counts and marginal domains require completed search. A truncated search supplies only witnessed lower bounds; saved candidates are consistency witnesses."}
