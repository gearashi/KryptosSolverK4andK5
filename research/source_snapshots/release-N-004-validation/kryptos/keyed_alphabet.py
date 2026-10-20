"""Bounded unknown cyclic-alphabet search, with genuine modular cipher rules.

Every letter has a distinct index in Z/26. Free numeric key phases are shared
across all occurrences. A fit is a model witness, never an authenticated text.
"""
from collections import Counter
from functools import lru_cache
import math
import string
import time

LETTERS = string.ascii_uppercase
FULL = (1 << 26) - 1


def _values(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


@lru_cache(maxsize=16384)
def _image(mask, coefficient):
    result = 0
    for value in _values(mask):
        result |= 1 << (coefficient * value % 26)
    return result


@lru_cache(maxsize=16384)
def _sumsets(left, right):
    result = 0
    for value in _values(left):
        result |= ((right << value) | (right >> (26 - value))) & FULL
    return result


def _matching(domains):
    """All alphabet variables must have a perfect matching to indices."""
    owner = [-1] * 26
    def augment(variable, seen):
        for value in _values(domains[variable]):
            if value in seen:
                continue
            seen.add(value)
            if owner[value] < 0 or augment(owner[value], seen):
                owner[value] = variable
                return True
        return False
    return all(augment(v, set()) for v in sorted(range(26), key=lambda i: domains[i].bit_count()))


def recover_cyclic_alphabet(ciphertext, cribs, *, period, cipher="vigenere",
                            fixed_indices=None, max_states=20000,
                            max_candidates=10, time_limit_seconds=5):
    """Search alphabet indices and repeating numeric keys by exact constraints.

    Cribs use one-based starts. fixed_indices are supplied absolute indices,
    not recovered values. Without any fixed indices A=0 removes only rotational
    gauge; unit multipliers and other equivalent alphabets are retained. The
    candidate storage cap does not terminate counting. A truncated no-witness
    run is inconclusive, not an exclusion. Counts refer to gauge-fixed complete
    alphabet/used-key-phase assignments, not distinct plaintexts.
    """
    if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 4096 or any(c not in LETTERS for c in ciphertext):
        raise ValueError("ciphertext must contain 1..4096 uppercase ASCII letters")
    if type(period) is not int or not 1 <= period <= 256:
        raise ValueError("period must be an integer in 1..256")
    if cipher not in ("vigenere", "beaufort", "variant"):
        raise ValueError("unsupported cyclic cipher")
    for value, name, high in ((max_states, "max_states", 1000000), (max_candidates, "max_candidates", 1000)):
        if type(value) is not int or not 1 <= value <= high:
            raise ValueError(f"{name} must be an integer in 1..{high}")
    if isinstance(time_limit_seconds, bool) or not isinstance(time_limit_seconds, (int, float)) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time limit must be finite and in (0,600]")
    if not isinstance(cribs, list):
        raise ValueError("cribs must be a list")
    known = {}
    for crib in cribs:
        if not isinstance(crib, dict) or set(crib) != {"start", "text"}:
            raise ValueError("crib must contain start and text")
        start, word = crib["start"], crib["text"]
        if type(start) is not int or not isinstance(word, str) or not word or any(c not in LETTERS for c in word) or start < 1 or start + len(word) - 1 > len(ciphertext):
            raise ValueError("invalid one-based crib")
        for i, c in enumerate(word, start - 1):
            if i in known and known[i] != c:
                raise ValueError("conflicting overlapping cribs")
            known[i] = c
    if fixed_indices is None:
        fixed_indices = {}
    if not isinstance(fixed_indices, dict) or any(not isinstance(k, str) or len(k) != 1 or k not in LETTERS or type(v) is not int or not 0 <= v < 26 for k, v in fixed_indices.items()):
        raise ValueError("fixed indices must map single uppercase letters to indices 0..25")
    if len(set(fixed_indices.values())) != len(fixed_indices):
        raise ValueError("fixed alphabet indices must be distinct")
    gauge = not fixed_indices
    fixed = {"A": 0} if gauge else dict(fixed_indices)
    used_phases = min(period, len(ciphertext))
    domains = [FULL] * (26 + used_phases)
    for letter, index in fixed.items():
        domains[LETTERS.index(letter)] = 1 << index
    constraints = []
    degrees = Counter()
    for i, plaintext in sorted(known.items()):
        coefficients = Counter()
        coefficients[LETTERS.index(ciphertext[i])] += 1
        coefficients[LETTERS.index(plaintext)] += 1 if cipher == "beaufort" else -1
        coefficients[26 + i % period] += 1 if cipher == "variant" else -1
        terms = tuple((v, c % 26) for v, c in sorted(coefficients.items()) if c % 26)
        constraints.append((i, terms))
        degrees.update(v for v, _ in terms)
    stats = {"states": 0, "constraint_revisions": 0, "matching_checks": 0,
             "dead_cache_hits": 0, "solutions": 0}
    start_time = time.monotonic()
    stopped = None
    candidates = []
    dead = set()
    last_conflict = None

    def propagate(ds):
        nonlocal last_conflict, stopped
        changed = True
        while changed:
            changed = False
            singletons = [d for d in ds[:26] if d.bit_count() == 1]
            if len(singletons) != len(set(singletons)):
                last_conflict = {"kind": "duplicate_alphabet_index"}
                return False
            used = 0
            for d in singletons:
                used |= d
            for v in range(26):
                if ds[v].bit_count() > 1:
                    updated = ds[v] & ~used
                    if not updated:
                        last_conflict = {"kind": "empty_alphabet_domain", "letter": LETTERS[v]}
                        return False
                    if updated != ds[v]:
                        ds[v] = updated
                        changed = True
            for position, terms in constraints:
                if time.monotonic() - start_time >= time_limit_seconds:
                    stopped = "time_limit"
                    return False
                for variable, coefficient in terms:
                    remaining = 1  # sum of no terms is zero
                    for other, factor in terms:
                        if other != variable:
                            remaining = _sumsets(remaining, _image(ds[other], factor))
                    allowed = 0
                    for value in _values(ds[variable]):
                        if remaining & (1 << (-coefficient * value % 26)):
                            allowed |= 1 << value
                    stats["constraint_revisions"] += 1
                    if not allowed:
                        last_conflict = {"kind": "modular_constraint_empty_domain", "crib_position": position + 1,
                                         "variable": LETTERS[variable] if variable < 26 else f"key_phase_{variable - 26}"}
                        return False
                    if allowed != ds[variable]:
                        ds[variable] = allowed
                        changed = True
            stats["matching_checks"] += 1
            if not _matching(ds[:26]):
                last_conflict = {"kind": "alphabet_has_no_perfect_matching"}
                return False
        return True

    def emit(ds):
        indices = [d.bit_length() - 1 for d in ds]
        alphabet = "".join(LETTERS[v] for v in sorted(range(26), key=lambda v: indices[v]))
        key = "".join(alphabet[indices[26 + j]] for j in range(used_phases)) + "?" * (period - used_phases)
        result = []
        for i, c in enumerate(ciphertext):
            cv, kv = indices[LETTERS.index(c)], indices[26 + i % period]
            pv = cv - kv if cipher == "vigenere" else kv - cv if cipher == "beaufort" else cv + kv
            result.append(alphabet[pv % 26])
        plaintext = "".join(result)
        if any(plaintext[i] != c for i, c in known.items()):
            raise AssertionError("CSP witness violates a crib")
        recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": alphabet,
                  "stages": [{"operation": "repeat_substitution", "cipher": cipher, "key_pattern": key}]}
        from .explanations import replay_recipe
        replay = replay_recipe(plaintext, recipe)
        if replay["ciphertext"] != ciphertext:
            raise AssertionError("CSP witness fails independent encryption")
        return {"plaintext": plaintext, "alphabet": alphabet, "key_pattern": key,
                "classification": "model_consistency_witness", "authenticated_solution": False,
                "encryption_recipe": recipe, "evidence": {"literal_reencryption_matches": True,
                "crib_matches": len(known), "stage_outputs": replay["stages"]}}

    def visit(ds):
        nonlocal stopped
        if stopped:
            return False
        if stats["states"] >= max_states:
            stopped = "state_limit"
            return False
        if time.monotonic() - start_time >= time_limit_seconds:
            stopped = "time_limit"
            return False
        stats["states"] += 1
        before = tuple(ds)
        if before in dead:
            stats["dead_cache_hits"] += 1
            return False
        if not propagate(ds):
            if not stopped:
                dead.add(before)
            return False
        unresolved = [i for i, domain in enumerate(ds) if domain.bit_count() > 1]
        if not unresolved:
            stats["solutions"] += 1
            if len(candidates) < max_candidates:
                candidates.append(emit(ds))
            return True
        variable = min(unresolved, key=lambda v: (ds[v].bit_count(), -degrees[v], v))
        any_solution = False
        for value in _values(ds[variable]):
            child = ds.copy()
            child[variable] = 1 << value
            any_solution |= visit(child)
            if stopped:
                break
        if not any_solution and not stopped:
            dead.add(before)
        return any_solution

    visit(domains.copy())
    complete = stopped is None
    return {"technique": "cyclic alphabet constraint propagation, all-different matching, MRV search and dead-state cache",
            "cipher": cipher, "period": period, "fixed_indices": fixed_indices,
            "gauge": "A=0 removes rotation only" if gauge else "absolute supplied indices; no gauge removed",
            "key_phases_not_used_by_message": period - used_phases,
            "complete": complete, "truncated": not complete,
            "feasible": bool(stats["solutions"]) if complete or stats["solutions"] else None,
            "total_alphabet_key_assignments": stats["solutions"] if complete else None,
            "count_convention": "Complete alphabet and message-used numeric key phases after the stated gauge; unused key phases are excluded.",
            "assignment_count_lower_bound": stats["solutions"], "candidates": candidates,
            "candidates_omitted": stats["solutions"] > len(candidates), "stats": stats,
            "stop_reason": stopped or "exhausted_declared_family",
            "last_branch_conflict": last_conflict,
            "limits": {"max_states": max_states, "max_candidates_stored": max_candidates, "time_limit_seconds": time_limit_seconds},
            "runtime_seconds": time.monotonic() - start_time,
            "interpretation": "Counts are gauge-fixed alphabet/key assignments, not distinct plaintexts. Branch conflicts describe a rejected branch, not the whole family. No language ranking or authentication is claimed."}
