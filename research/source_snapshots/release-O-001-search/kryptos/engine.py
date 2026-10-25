"""Finite deterministic batches of classical-cipher hypotheses.

run_batch is a top-level pickleable function suitable for ProcessPoolExecutor.
The caller owns process limits, checkpointing, and cancellation between batches.
K5 has no assumed ciphertext: callers must supply a clearly labelled hypothesis.
"""

from __future__ import annotations

import math
import random
from collections import Counter

from .ciphers import (
    CIPHERS, crib_match_count, decrypt, derive_crib_constraints,
    get_alphabet, normalize_letters,
)
from .scoring import english_score

K4_CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
DEFAULT_K4_CRIBS = [
    {"start": 22, "text": "EAST"},
    {"start": 26, "text": "NORTHEAST"},
    {"start": 64, "text": "BERLIN"},
    {"start": 70, "text": "CLOCK"},
]


def _integer(config: dict, field: str, default: int, low: int, high: int) -> int:
    value = config.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{field} must be an integer from {low} through {high}")
    return value


def validate_config(config: dict) -> dict:
    """Normalize input without silently interpreting arbitrary K5 material as known."""
    if not isinstance(config, dict):
        raise ValueError("configuration must be an object")
    result = dict(config)
    target = result.get("target", "k4")
    if target not in ("k4", "k5", "custom"):
        raise ValueError("target must be k4, k5, or custom")
    result["target"] = target
    ciphertext = result.get("ciphertext", K4_CIPHERTEXT if target == "k4" else "")
    ciphertext = normalize_letters(ciphertext, "ciphertext")
    if len(ciphertext) > 4096:
        raise ValueError("ciphertext is limited to 4096 letters per local search")
    result["ciphertext"] = ciphertext
    result["method"] = result.get("method", "dictionary")
    if result["method"] not in ("dictionary", "anneal", "routes"):
        raise ValueError("method must be dictionary, anneal, or routes")
    result["alphabet"] = result.get("alphabet", "standard")
    get_alphabet(result["alphabet"])
    result["cipher"] = result.get("cipher", "vigenere")
    if result["cipher"] not in CIPHERS:
        raise ValueError("cipher must be vigenere, beaufort, or variant")
    raw_cribs = result.get("cribs", DEFAULT_K4_CRIBS if target == "k4" and ciphertext == K4_CIPHERTEXT else [])
    if not isinstance(raw_cribs, list):
        raise ValueError("cribs must be a list")
    cribs, positions = [], {}
    for crib in raw_cribs:
        if not isinstance(crib, dict):
            raise ValueError("every crib must be an object with start and text")
        start = crib.get("start")
        text = normalize_letters(crib.get("text"), "crib text")
        if isinstance(start, bool) or not isinstance(start, int) or not 1 <= start <= len(ciphertext):
            raise ValueError("crib start must be a one-based position in the ciphertext")
        if start + len(text) - 1 > len(ciphertext):
            raise ValueError("crib extends beyond ciphertext")
        for offset, letter in enumerate(text):
            position = start - 1 + offset
            if position in positions and positions[position] != letter:
                raise ValueError(f"contradictory cribs at one-based position {position + 1}")
            positions[position] = letter
        cribs.append({"start": start, "text": text})
    result["cribs"] = cribs
    result["require_cribs"] = result.get("require_cribs", True)
    if not isinstance(result["require_cribs"], bool):
        raise ValueError("require_cribs must be a boolean")
    raw_keys = result.get("keys", ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK"])
    if not isinstance(raw_keys, list) or len(raw_keys) > 1_000_000:
        raise ValueError("keys must be a list of at most 1000000 strings")
    keys = list(dict.fromkeys(normalize_letters(key, "key") for key in raw_keys))
    if any(len(key) > 4096 for key in keys):
        raise ValueError("keys are limited to 4096 letters")
    result["keys"] = keys
    result["min_period"] = _integer(result, "min_period", 1, 1, 256)
    result["max_period"] = _integer(result, "max_period", 24, result["min_period"], 256)
    result["iterations"] = _integer(result, "iterations", 400, 0, 100_000)
    result["batch_size"] = _integer(result, "batch_size", 2, 1, 4096)
    result["restarts"] = _integer(result, "restarts", 24, 1, 1_000_000)
    result["seed"] = _integer(result, "seed", 2026, 0, 2**63 - 1)
    result["top_candidates"] = _integer(result, "top_candidates", 10, 1, 100)
    return result


def _crib_positions(config: dict) -> frozenset[int]:
    return frozenset(crib["start"] - 1 + offset
                     for crib in config["cribs"] for offset in range(len(crib["text"])))


def _candidate(plaintext: str, key: str, config: dict, details: dict, score: float | None = None) -> dict:
    matches, total = crib_match_count(plaintext, config["cribs"])
    excluded = _crib_positions(config)
    scored_characters = len(plaintext) - len(excluded)
    return {
        "plaintext": plaintext, "key": key, "method": config["method"],
        "alphabet": config["alphabet"], "cipher": config["cipher"],
        "score": english_score(plaintext, excluded_positions=excluded) if score is None else score,
        "language_scored_characters": scored_characters,
        "language_score_available": scored_characters > 0,
        "crib_matches": matches, "crib_total": total, "details": details,
    }


def _retain(candidates: list[dict], candidate: dict, config: dict) -> None:
    if config["require_cribs"] and candidate["crib_matches"] != candidate["crib_total"]:
        return
    if any(item["plaintext"] == candidate["plaintext"] and item["key"] == candidate["key"] for item in candidates):
        return
    candidates.append(candidate)
    candidates.sort(key=lambda item: (-item["score"], item["plaintext"], item["key"]))
    del candidates[config["top_candidates"]:]


def _route_specs(length: int) -> list[tuple[str, int, bool]]:
    specs = [("identity", 1, False), ("reverse", 1, False)]
    # A ragged final row is handled without adding/removing/padding letters.
    for width in range(2, min(length, 64) + 1):
        for operation in ("columns", "inverse_columns", "snake_rows", "snake_columns", "inverse_snake_columns"):
            specs.extend([(operation, width, False), (operation, width, True)])
    return specs


def work_units(config: dict) -> int:
    """Return the finite number of keys/routes/restarts before scheduling."""
    config = validate_config(config)
    if config["method"] == "dictionary":
        return len(config["keys"])
    if config["method"] == "routes":
        return len(_route_specs(len(config["ciphertext"])))
    return config["restarts"]


def total_batches(config: dict) -> int:
    config = validate_config(config)
    return (work_units(config) + config["batch_size"] - 1) // config["batch_size"]


def inspect_periods(config: dict) -> list[dict]:
    """Inspect exact crib consistency, without executing any search restarts."""
    config = validate_config(config)
    letters = get_alphabet(config["alphabet"])
    rows = []
    for period in range(config["min_period"], config["max_period"] + 1):
        fixed, conflict = derive_crib_constraints(
            config["ciphertext"], period, config["cribs"], config["cipher"], config["alphabet"],
        )
        rows.append({
            "period": period, "feasible": conflict is None,
            "fixed_key_positions": len(fixed),
            "key_pattern": "".join(letters[fixed[position]] if position in fixed else "?" for position in range(period)),
            "reason": conflict,
        })
    return rows


def _route(text: str, operation: str, width: int, reverse: bool = False) -> str:
    if operation == "identity":
        result = text
    elif operation == "reverse":
        result = text[::-1]
    else:
        rows = [list(range(start, min(start + width, len(text)))) for start in range(0, len(text), width)]
        if operation == "snake_rows":
            positions = [position for row_index, row in enumerate(rows) for position in (row if row_index % 2 == 0 else row[::-1])]
        else:
            positions = []
            for column in range(width):
                column_positions = [row[column] for row in rows if column < len(row)]
                if "snake" in operation and column % 2:
                    column_positions.reverse()
                positions.extend(column_positions)
        if operation.startswith("inverse_"):
            result_letters = [""] * len(text)
            for source, destination in enumerate(positions):
                result_letters[destination] = text[source]
            result = "".join(result_letters)
        else:
            result = "".join(text[position] for position in positions)
    return result[::-1] if reverse else result


def _decode_values(encrypted: list[int], key: list[int], cipher: str, letters: str) -> str:
    period = len(key)
    if cipher == "beaufort":
        return "".join(letters[(key[position % period] - value) % 26] for position, value in enumerate(encrypted))
    if cipher == "variant":
        return "".join(letters[(value + key[position % period]) % 26] for position, value in enumerate(encrypted))
    return "".join(letters[(value - key[position % period]) % 26] for position, value in enumerate(encrypted))


def run_batch(config: dict, batch_index: int) -> dict:
    """Execute one deterministic finite batch; no shared mutable state or I/O.

    ``evaluated`` counts plaintext scores, ``skipped`` counts incompatible
    annealing restarts, and ``completed_units`` counts keys/routes/restarts.
    Cribs are hard constraints during annealing even if require_cribs is false;
    remove cribs to investigate an unconstrained hypothesis.
    """
    config = validate_config(config)
    if isinstance(batch_index, bool) or not isinstance(batch_index, int) or batch_index < 0:
        raise ValueError("batch_index must be a nonnegative integer")
    method = config["method"]
    excluded = _crib_positions(config)
    specs = _route_specs(len(config["ciphertext"])) if method == "routes" else None
    total = len(config["keys"]) if method == "dictionary" else len(specs) if specs is not None else config["restarts"]
    start = min(batch_index * config["batch_size"], total)
    stop = min(start + config["batch_size"], total)
    result = {
        "candidates": [], "evaluated": 0, "skipped": 0,
        "completed_units": stop - start, "total_units": total,
        "done": stop >= total, "batch_index": batch_index, "skip_reasons": {},
    }
    if method == "dictionary":
        for unit in range(start, stop):
            key = config["keys"][unit]
            plain = decrypt(config["ciphertext"], key, config["cipher"], config["alphabet"])
            _retain(result["candidates"], _candidate(plain, key, config, {"key_index": unit}), config)
            result["evaluated"] += 1
    elif method == "routes":
        for unit in range(start, stop):
            operation, width, reverse = specs[unit]
            plain = _route(config["ciphertext"], operation, width, reverse)
            details = {"operation": operation, "width": width, "reverse_output": reverse,
                       "note": "Pure permutation hypothesis; cipher/alphabet settings do not affect routes."}
            key = f"{operation}:width={width}:reverse={str(reverse).lower()}"
            _retain(result["candidates"], _candidate(plain, key, config, details), config)
            result["evaluated"] += 1
    else:
        letters = get_alphabet(config["alphabet"])
        index = {character: position for position, character in enumerate(letters)}
        encrypted = [index[character] for character in config["ciphertext"]]
        skip_reasons = Counter()
        for unit in range(start, stop):
            period = config["min_period"] + unit % (config["max_period"] - config["min_period"] + 1)
            fixed, conflict = derive_crib_constraints(config["ciphertext"], period, config["cribs"], config["cipher"], config["alphabet"])
            if conflict:
                result["skipped"] += 1
                skip_reasons[conflict] += 1
                continue
            # Per-restart seed makes execution order and worker count irrelevant.
            rng = random.Random(config["seed"] + unit * 1_000_003)
            key = [fixed[position] if position in fixed else rng.randrange(26) for position in range(period)]
            mutable = [position for position in range(period) if position not in fixed]
            plain = _decode_values(encrypted, key, config["cipher"], letters)
            score = english_score(plain, excluded_positions=excluded)
            best_plain, best_key, best_score = plain, list(key), score
            result["evaluated"] += 1
            for step in range(config["iterations"] if mutable else 0):
                position = rng.choice(mutable)
                old_value = key[position]
                key[position] = (old_value + rng.randrange(1, 26)) % 26
                trial_plain = _decode_values(encrypted, key, config["cipher"], letters)
                trial_score = english_score(trial_plain, excluded_positions=excluded)
                result["evaluated"] += 1
                temperature = 0.22 * (0.015 / 0.22) ** (step / max(1, config["iterations"] - 1))
                delta = trial_score - score
                if delta >= 0 or rng.random() < math.exp(max(-700.0, delta / temperature)):
                    plain, score = trial_plain, trial_score
                    if score > best_score:
                        best_plain, best_key, best_score = plain, list(key), score
                else:
                    key[position] = old_value
            candidate = _candidate(best_plain, "".join(letters[value] for value in best_key), config,
                                   {"period": period, "restart": unit, "fixed_key_positions": len(fixed),
                                    "iterations": config["iterations"] if mutable else 0,
                                    "cribs_used_as_hard_constraints": True}, best_score)
            _retain(result["candidates"], candidate, config)
        result["skip_reasons"] = dict(skip_reasons)
    return result


search_batch = run_batch
