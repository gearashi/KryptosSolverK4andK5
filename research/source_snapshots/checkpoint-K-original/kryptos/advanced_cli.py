"""Checkpoint-J interfaces: exact bounded searches and replayable evidence."""
import hashlib
import json
from pathlib import Path
import time

from .explanations import replay_recipe

ROOT = Path(__file__).resolve().parents[1]
BASE_FIELDS = {"target", "ciphertext", "cribs"}


def _integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in {low}..{high}")
    return value


def _check(request, allowed):
    if not isinstance(request, dict) or set(request) - allowed:
        raise ValueError("unknown advanced request field")


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _explain(command, request, result, text=None, cribs=None):
    names = ["__main__.py", "advanced_cli.py", "explanations.py", "ciphers.py", "data.py"]
    names += {"columns": ["columnar.py", "sculpture.py"], "general": ["general_layers.py"],
              "alphabet": ["keyed_alphabet.py"], "layout": ["sculpture.py"],
              "optimize": ["general_layers.py", "factor_search.py", "language.py"]}[command]
    result.update(authenticated_solution=False)
    result["explanation"] = {
        "schema": "kryptos.result-explanation.v1", "command": command,
        "supplied_request": request,
        "request_sha256": _hash(json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()),
        "source_sha256": {"kryptos/" + name: _hash((ROOT / "kryptos" / name).read_bytes()) for name in names},
        "interpretation": "A model fit, re-encryption, or maximum language score is not authentication. Supplied geometry, periods, stage order and any fixed alphabet indices remain assumptions.",
        "external_verification_performed": False,
    }
    if text is not None:
        result["explanation"]["input"] = {"ciphertext": text, "sha256": _hash(text.encode("ascii")),
            "cribs": cribs, "crib_position_convention": "one-based original plaintext positions"}
    return result


def _candidate(candidate, stages, alphabet, ciphertext, known):
    candidate = dict(candidate)
    keys = iter(candidate["keys"])
    recipe_stages = []
    for stage in stages:
        if stage["operation"] == "gather":
            recipe_stages.append({"operation": "gather", "permutation": stage["permutation"]})
        else:
            recipe_stages.append({"operation": "repeat_substitution", "cipher": stage.get("cipher", "vigenere"),
                                  "key_pattern": next(keys)})
    recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": alphabet, "stages": recipe_stages}
    replay = replay_recipe(candidate["plaintext"], recipe)
    if replay["ciphertext"] != ciphertext or any(candidate["plaintext"][i] != c for i, c in known.items()):
        raise AssertionError("advanced candidate failed independent recipe or crib checks")
    candidate.update(classification="model_consistency_witness", encryption_recipe=recipe,
                     evidence={"literal_reencryption_matches": True, "crib_matches": len(known),
                               "stage_outputs": replay["stages"], "external_verification_performed": False})
    return candidate


def run_advanced(command, request, parse_target):
    if command == "layout":
        from .sculpture import load_layout, section_cells, section_text, fixed_routes, fixed_overlay
        _check(request, {"section", "transform"})
        section = request.get("section", "K4")
        layout = load_layout()
        result = {"technique": "Source-verified ordinal text geometry and explicitly fixed coordinate transforms",
                  "section": section, "text": section_text(section),
                  "cells": [c.to_dict() for c in section_cells(section)],
                  "routes": fixed_routes(section), "overlay": fixed_overlay(section, request.get("transform", "identity")),
                  "dataset_sha256": _hash((ROOT / "research/sculpture_layout.json").read_bytes()),
                  "sources": layout["sources"],
                  "interpretation": "Columns are transcription ordinals, not measured physical coordinates. Overlay alignment is a supplied hypothesis."}
        return _explain(command, request, result)
    if command == "columns":
        from .columnar import recover_column_order
        fields = {"width", "cells", "column_direction", "max_segmentations", "max_states", "max_candidates", "time_limit_seconds"}
        _check(request, BASE_FIELDS | fields)
        target, text, cribs, known = parse_target(request)
        options = {key: request[key] for key in fields if key in request}
        if "width" not in options and "cells" not in options:
            from .data import K4_CIPHERTEXT
            if target != "k4" or text != K4_CIPHERTEXT:
                raise ValueError("custom/K5 column recovery requires an explicit width or occupied cells")
            from .sculpture import section_cells
            options["cells"] = [(c.row, c.column) for c in section_cells("K4")]
        result = recover_column_order(text, cribs, **options)
        if "width" not in request and "cells" not in request:
            result["default_geometry"] = {"source":"research/sculpture_layout.json",
                "sha256":_hash((ROOT / "research/sculpture_layout.json").read_bytes()),
                "convention":"Verified K4 ordinal occupied cells; no padding"}
        for candidate in result["candidates"]:
            replay = replay_recipe(candidate["plaintext"], candidate["recipe"])
            if replay["ciphertext"] != text:
                raise AssertionError("column candidate failed independent recipe replay")
            candidate["encryption_recipe"] = candidate["recipe"]
            candidate["evidence"] = {"literal_reencryption_matches": True, "stage_outputs": replay["stages"],
                                     "crib_matches": len(known)}
        return _explain(command, request, {"target": target, **result}, text, cribs)
    if command == "alphabet":
        from .keyed_alphabet import recover_cyclic_alphabet
        fields = {"period", "cipher", "fixed_indices", "max_states", "max_candidates", "time_limit_seconds"}
        _check(request, BASE_FIELDS | fields)
        target, text, cribs, known = parse_target(request)
        options = {key: request[key] for key in fields if key in request}
        options.setdefault("period", 8)
        result = recover_cyclic_alphabet(text, cribs, **options)
        return _explain(command, request, {"target": target, **result}, text, cribs)
    if command not in ("general", "optimize"):
        raise ValueError("unknown advanced command")
    from .general_layers import solve_layers, LayerBudgetExceeded
    fields = {"stages", "alphabet", "max_key_slots", "max_matrix_cells", "max_operations", "time_limit_seconds"}
    fields |= ({"max_candidates", "top"} if command == "general" else
               {"model_path", "max_nodes", "max_factor_entries", "max_cache_entries"})
    _check(request, BASE_FIELDS | fields)
    target, text, cribs, known = parse_target(request)
    if "stages" not in request:
        raise ValueError("an explicit list of encryption stages is required")
    seconds = _integer(request.get("time_limit_seconds", 10), "time_limit_seconds", 1, 600)
    if command == "general":
        limit = _integer(request.get("max_candidates", 676), "max_candidates", 1, 100000)
        keep = _integer(request.get("top", 10), "top", 1, 1000)
    else:
        node_limit = _integer(request.get("max_nodes", 100000), "max_nodes", 0, 1000000)
        entry_limit = _integer(request.get("max_factor_entries", 200000), "max_factor_entries", 1, 2000000)
        cache_limit = _integer(request.get("max_cache_entries", 200000), "max_cache_entries", 0, 2000000)
        if not isinstance(request.get("model_path"), str):
            raise ValueError("optimize requires an explicit model_path")
    try:
        solution = solve_layers(text, known, request["stages"], request.get("alphabet", "kryptos"),
            **{key: request[key] for key in ("max_key_slots", "max_matrix_cells", "max_operations") if key in request})
    except LayerBudgetExceeded as exc:
        return _explain(command, request, {"target": target, "feasible": None, "complete": False,
            "stop_reason": "algebra_budget", "detail": str(exc)}, text, cribs)
    result = {"target": target, **solution.summary(),
              "technique": "Exact linear systems separately modulo2 and modulo13; projection to distinct plaintexts; CRT key lifts",
              "candidates": []}
    if not solution.feasible:
        result.update(complete=True, stop_reason="exact_contradiction_in_declared_model")
        return _explain(command, request, result, text, cribs)
    if command == "general":
        result["enumeration_bounds"] = {"max_candidates": limit, "top_stored": keep, "time_limit_seconds": seconds}
        result["evaluated"] = 0
        result["ranking"] = "No language ranking; deterministic algebraic coordinate order. Stored witnesses may be a subset."
        if solution.distinct_plaintext_count > limit:
            result.update(complete=False, stop_reason="candidate_limit; no arbitrary partial family enumerated")
        else:
            started = time.monotonic()
            result.update(complete=True, stop_reason="exhausted_declared_plaintext_family")
            for a, b, plaintext in solution.enumerate_plaintexts(limit):
                if time.monotonic() - started >= seconds:
                    result.update(complete=False, stop_reason="time_limit")
                    break
                candidate = solution.candidate(a, b)
                result["evaluated"] += 1
                if len(result["candidates"]) < keep:
                    result["candidates"].append(_candidate(candidate, request["stages"], solution.alphabet, text, known))
            result["enumeration_runtime_seconds"] = time.monotonic() - started
        result["candidates_omitted"] = len(result["candidates"]) < solution.distinct_plaintext_count
    else:
        from .factor_search import optimize_ngrams, FactorBudgetExceeded
        from .language import CharacterNgramModel
        model_path = Path(request["model_path"])
        if model_path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("model exceeds32MiB")
        model_bytes = model_path.read_bytes()
        model = CharacterNgramModel.from_json(model_bytes.decode("utf-8-sig"))
        result["model_file_sha256"] = _hash(model_bytes)
        try:
            optimized = optimize_ngrams(solution, model, known, max_factor_entries=entry_limit,
                max_nodes=node_limit, time_limit_seconds=seconds, max_cache_entries=cache_limit)
        except FactorBudgetExceeded as exc:
            result.update(complete=False, stop_reason="factor_table_budget", detail=str(exc))
        else:
            optimized["candidate"] = _candidate(optimized["candidate"], request["stages"], solution.alphabet, text, known)
            result["optimization"] = optimized
            result["complete"] = optimized["search"]["complete"]
            result["stop_reason"] = optimized["search"]["stop_reason"]
            result["technique"] += "; exact integer-product n-gram branch-and-bound with cached admissible local bounds"
    return _explain(command, request, result, text, cribs)


def json_safe_integers(value):
    """Preserve huge exact scores without overriding Python's decimal limit."""
    if type(value) is int and value.bit_length() > 12000:
        return {"encoding": "exact_integer_hex", "value": hex(value)}
    if isinstance(value, dict):
        return {key: json_safe_integers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe_integers(item) for item in value]
    return value
