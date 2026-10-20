"""Bounded, deterministic crib-guided recovery without supplied answer keys.

Crib starts are one-based original-plaintext positions. A route is an encryption
gather map T(text)[j] = text[permutation[j]]. Orders ST/TS place one repeating
substitution before/after that route. Unknown key symbols remain unknown.
"""

from __future__ import annotations

import string

ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
CIPHERS = ("vigenere", "beaufort", "variant")


def _letters(value, label):
    if not isinstance(value, str) or any(not (c in string.ascii_letters or c.isspace()) for c in value):
        raise ValueError(f"{label} must contain ASCII letters and optional whitespace only")
    text = "".join(value.split()).upper()
    if not text or len(text) > 4096:
        raise ValueError(f"{label} must contain between 1 and 4096 letters")
    return text


def _integer(value, label, minimum=0, maximum=1_000_000):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _inputs(ciphertext, cribs):
    ciphertext = _letters(ciphertext, "ciphertext")
    if not isinstance(cribs, (list, tuple)):
        raise ValueError("cribs must be a list of {start: one-based position, text: letters}")
    known = {}
    for crib in cribs:
        if not isinstance(crib, dict):
            raise ValueError("each crib must be an object")
        text = _letters(crib.get("text"), "crib text")
        start = _integer(crib.get("start"), "crib start", 1, len(ciphertext)) - 1
        if start + len(text) > len(ciphertext):
            raise ValueError("crib extends beyond the ciphertext")
        for i, symbol in enumerate(text, start):
            if i in known and known[i] != symbol:
                raise ValueError(f"contradictory cribs at position {i + 1}")
            known[i] = symbol
    return ciphertext, dict(sorted(known.items()))


def _routes(routes, length, substitution):
    if routes is None:
        routes = [{"name": "identity", "permutation": list(range(length))}]
    if not isinstance(routes, (list, tuple)) or len(routes) > 4096:
        raise ValueError("routes must be a finite list of at most 4096 candidates")
    distinct = {}
    for number, row in enumerate(routes):
        if not isinstance(row, dict):
            raise ValueError("each route must be an object")
        permutation = row.get("permutation")
        if not isinstance(permutation, (list, tuple)) or len(permutation) != length:
            raise ValueError("every route needs one source index per ciphertext position")
        if any(isinstance(i, bool) or not isinstance(i, int) for i in permutation) or set(permutation) != set(range(length)):
            raise ValueError("route permutation must be a zero-based bijection")
        order = row.get("order", "ST" if substitution else "T")
        if order not in (("ST", "TS") if substitution else ("T",)):
            raise ValueError("route order must be ST/TS for key recovery, or T for pure transposition")
        name = row.get("name", f"route-{number}")
        if not isinstance(name, str) or not name:
            raise ValueError("route name must be a nonempty string")
        signature = (tuple(permutation), order)
        if signature in distinct:
            if name not in distinct[signature]["aliases"]:
                distinct[signature]["aliases"].append(name)
            continue
        inverse = [0] * length
        for output, original in enumerate(permutation):
            inverse[original] = output
        distinct[signature] = {"aliases": [name], "permutation": tuple(permutation),
                               "inverse": inverse, "order": order}
    return list(distinct.values()), len(routes)


def _key_value(c, p, cipher):
    if cipher == "beaufort":
        return (c + p) % 26
    return ((p - c) if cipher == "variant" else (c - p)) % 26


def _plain_value(c, k, cipher):
    if cipher == "beaufort":
        return (k - c) % 26
    return ((c + k) if cipher == "variant" else (c - k)) % 26


def _cipher_value(p, k, cipher):
    if cipher == "beaufort":
        return (k - p) % 26
    return ((p - k) if cipher == "variant" else (p + k)) % 26


def canonical_key(key):
    """Shortest repeating word for a COMPLETE key; '?' is deliberately rejected."""
    key = _letters(key, "complete key")
    for period in range(1, len(key) + 1):
        if len(key) % period == 0 and key == key[:period] * (len(key) // period):
            return key[:period]
    raise AssertionError("a key is always periodic at its own length")


def _base_result(total, routes_supplied, routes_distinct, max_models, max_crib_checks):
    _integer(max_models, "max_models")
    _integer(max_crib_checks, "max_crib_checks")
    return {
        "status": "complete", "complete": True, "stop_reason": None,
        "limits": {"max_models": max_models, "max_crib_checks": max_crib_checks},
        "work": {"models_requested": total, "models_tested": 0, "crib_checks": 0,
                 "routes_supplied": routes_supplied, "distinct_routes": routes_distinct,
                 "plaintext_symbols_decoded": 0, "equivalent_complete_key_models_merged": 0},
        "candidates": [], "rejections": [],
        "warning": "Crib consistency is conditional on the supplied model family, not a solution or confidence score.",
    }


def _can_start(result, known_count):
    work, limits = result["work"], result["limits"]
    if work["models_tested"] >= limits["max_models"]:
        reason = "max_models"
    elif work["crib_checks"] + known_count > limits["max_crib_checks"]:
        reason = "insufficient_crib_budget_for_complete_model"
    else:
        return True
    result.update(status="truncated", complete=False, stop_reason=reason)
    return False


def recover_periodic_keys(ciphertext, cribs, *, periods=range(1, 33), alphabet="kryptos",
                          cipher="vigenere", routes=None, max_models=2048, max_crib_checks=100000):
    """Recover constrained repeating keys, optionally before/after a fixed route.

    No answer-key parameter exists. For each tested route/period, reject exact
    contradictory crib requirements or return all forced key residues. Missing
    positions remain '?' and have 26 possible values each. Complete keys are
    reduced to their shortest repeating word and identical repeated-period
    models on the same route are merged. Incomplete patterns are never reduced
    to a guessed shorter key. No key completion, language ranking, or workers.
    """
    ciphertext, known = _inputs(ciphertext, cribs)
    if not isinstance(alphabet, str):
        raise ValueError("alphabet must be a known name or a 26-letter permutation")
    alphabet = ALPHABETS.get(alphabet, alphabet)
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be standard, kryptos, or an uppercase A-Z permutation")
    if cipher not in CIPHERS:
        raise ValueError("cipher must be vigenere, beaufort, or variant")
    if not isinstance(periods, (list, tuple, range)) or len(periods) > 4096:
        raise ValueError("periods must be a finite list, tuple, or range of at most 4096 entries")
    periods = sorted(set(_integer(period, "period", 1, 4096) for period in periods))
    route_rows, supplied = _routes(routes, len(ciphertext), True)
    result = _base_result(len(route_rows) * len(periods), supplied, len(route_rows), max_models, max_crib_checks)
    result.update(alphabet=alphabet, cipher=cipher, periods=periods, unique_crib_positions=len(known))
    index = {symbol: value for value, symbol in enumerate(alphabet)}
    canonical_candidates = {}
    for route_index, route in enumerate(route_rows):
        for period in periods:
            if not _can_start(result, len(known)):
                return result
            result["work"]["models_tested"] += 1
            key_values, sources = [None] * period, {}
            conflict = None
            for i, plain in known.items():
                j = route["inverse"][i]
                phase = (i if route["order"] == "ST" else j) % period
                value = _key_value(index[ciphertext[j]], index[plain], cipher)
                result["work"]["crib_checks"] += 1
                if key_values[phase] is not None and key_values[phase] != value:
                    conflict = {"key_position": phase + 1,
                                "plaintext_positions": [sources[phase], i + 1],
                                "required_key_symbols": [alphabet[key_values[phase]], alphabet[value]]}
                    break
                key_values[phase], sources[phase] = value, i + 1
            metadata = {"route_index": route_index, "route_aliases": list(route["aliases"]),
                        "order": route["order"], "declared_period": period}
            if conflict:
                result["rejections"].append({**metadata, "witness": conflict})
                continue
            pattern = "".join("?" if value is None else alphabet[value] for value in key_values)
            complete_key = "?" not in pattern
            reduced = canonical_key(pattern) if complete_key else None
            signature = (route_index, reduced) if complete_key else None
            if signature is not None and signature in canonical_candidates:
                canonical_candidates[signature]["declared_periods"].append(period)
                result["work"]["equivalent_complete_key_models_merged"] += 1
                continue
            mask = []
            for i, j in enumerate(route["inverse"]):
                phase = (i if route["order"] == "ST" else j) % period
                value = key_values[phase]
                mask.append("?" if value is None else alphabet[_plain_value(index[ciphertext[j]], value, cipher)])
                result["work"]["plaintext_symbols_decoded"] += value is not None
            mask = "".join(mask)
            if any(mask[i] != symbol for i, symbol in known.items()):
                raise AssertionError("recovered pattern violates a supplied crib")
            plaintext_complete = "?" not in mask
            reencrypted = None
            if plaintext_complete:
                output = [""] * len(ciphertext)
                for i, j in enumerate(route["inverse"]):
                    phase = (i if route["order"] == "ST" else j) % period
                    output[j] = alphabet[_cipher_value(index[mask[i]], key_values[phase], cipher)]
                reencrypted = "".join(output) == ciphertext
                if not reencrypted:
                    raise AssertionError("recovered plaintext does not re-encrypt")
            candidate = {
                "route_index": route_index, "route_aliases": list(route["aliases"]), "order": route["order"],
                "declared_periods": [period], "key_complete": complete_key,
                "key_pattern": reduced if complete_key else pattern,
                "canonical_key": reduced, "canonical_period": len(reduced) if reduced else None,
                "free_key_positions": sum(value is None for value in key_values),
                "plaintext_mask": mask, "plaintext_complete": plaintext_complete,
                "plaintext": mask if plaintext_complete else None, "reencryption_matches": reencrypted,
            }
            result["candidates"].append(candidate)
            if signature is not None:
                canonical_candidates[signature] = candidate
    return result


def recover_transposition_routes(ciphertext, cribs, routes, *, max_models=2048, max_crib_checks=100000):
    """Recover a pure transposition from a declared finite encryption-gather family."""
    ciphertext, known = _inputs(ciphertext, cribs)
    route_rows, supplied = _routes(routes, len(ciphertext), False)
    result = _base_result(len(route_rows), supplied, len(route_rows), max_models, max_crib_checks)
    result["unique_crib_positions"] = len(known)
    for route_index, route in enumerate(route_rows):
        if not _can_start(result, len(known)):
            return result
        result["work"]["models_tested"] += 1
        mismatch = None
        for i, plain in known.items():
            actual = ciphertext[route["inverse"][i]]
            result["work"]["crib_checks"] += 1
            if actual != plain:
                mismatch = {"plaintext_position": i + 1, "expected": plain, "actual": actual}
                break
        if mismatch:
            result["rejections"].append({"route_index": route_index, "route_aliases": route["aliases"], "witness": mismatch})
            continue
        plaintext = "".join(ciphertext[j] for j in route["inverse"])
        result["work"]["plaintext_symbols_decoded"] += len(plaintext)
        reencryption = "".join(plaintext[i] for i in route["permutation"]) == ciphertext
        if not reencryption:
            raise AssertionError("recovered route failed exact re-encryption")
        result["candidates"].append({"route_index": route_index, "route_aliases": list(route["aliases"]),
                                     "plaintext": plaintext, "reencryption_matches": True})
    return result
