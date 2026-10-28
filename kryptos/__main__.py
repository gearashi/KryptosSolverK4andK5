"""Bounded command-line tools for recovery and reproducible cipher hypotheses."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

from .ciphers import get_alphabet, normalize_letters, encrypt
from .data import K4_CIPHERTEXT, K4_CRIBS
from .layer_plan import compile_layer_plan
from .grid import k4_cells, check_grid_model
from .recovery import recover_periodic_keys
from .scoring import english_score
from .position_residues import check_position_residues
from .explanations import explain_recovery, explain_layers, explain_grid, explain_residues


def _strict_json(path):
    path = Path(path)
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("request exceeds4MiB")
    def reject(value):
        raise ValueError(f"non-finite JSON value: {value}")
    def finite(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            reject(value)
        return parsed
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = item
        return result
    value = json.loads(path.read_text(encoding="utf-8-sig"), parse_constant=reject,
                       parse_float=finite, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("request must be a JSON object")
    return value


def _ascii_letters(value, label):
    if not isinstance(value, str) or any(not (c.isascii() and c.isalpha()) and not c.isspace() for c in value):
        raise ValueError(f"{label} must contain ASCII letters and optional whitespace only")
    return normalize_letters(value, label)


def _target(request):
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    target = request.get("target", "custom" if "ciphertext" in request else "k4")
    if target not in ("k4", "k5", "custom"):
        raise ValueError("target must be k4, k5, or custom")
    if target != "k4" and "ciphertext" not in request:
        raise ValueError("custom/K5 input requires explicit ciphertext; no K5 ciphertext is assumed")
    text = _ascii_letters(request.get("ciphertext", K4_CIPHERTEXT), "ciphertext")
    if len(text) > 4096:
        raise ValueError("ciphertext exceeds4096letters")
    cribs = request.get("cribs", K4_CRIBS if target == "k4" and text == K4_CIPHERTEXT else [])
    if not isinstance(cribs, list):
        raise ValueError("cribs must be a list")
    known, normalized = {}, []
    for crib in cribs:
        if not isinstance(crib, dict):
            raise ValueError("each crib must be an object")
        if set(crib) - {"start", "text"}:
            raise ValueError("unknown crib field")
        start, word = crib.get("start"), _ascii_letters(crib.get("text"), "crib text")
        if type(start) is not int or not 1 <= start <= len(text) or start + len(word) - 1 > len(text):
            raise ValueError("crib starts are one-based and must fit the text")
        for i, char in enumerate(word, start - 1):
            if i in known and known[i] != char:
                raise ValueError("conflicting overlapping cribs")
            known[i] = char
        normalized.append({"start": start, "text": word})
    return target, text, normalized, known


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in{low}..{high}")
    return value


def run_recovery(request):
    allowed = {"target", "ciphertext", "cribs", "alphabet", "cipher", "min_period", "max_period", "routes", "max_models", "max_crib_checks"}
    if not isinstance(request, dict) or set(request) - allowed:
        raise ValueError("unknown recovery request field")
    target, text, cribs, known = _target(request)
    first = _integer(request.get("min_period", 1), "min_period", 1, 256)
    last = _integer(request.get("max_period", 32), "max_period", first, 256)
    result = recover_periodic_keys(text, cribs, periods=range(first, last + 1),
        alphabet=request.get("alphabet", "kryptos"), cipher=request.get("cipher", "vigenere"),
        routes=request.get("routes"),
        max_models=_integer(request.get("max_models", 2048), "max_models", 1, 100000),
        max_crib_checks=_integer(request.get("max_crib_checks", 100000), "max_crib_checks", 1, 1000000))
    return explain_recovery({"target": target, "authenticated_solution": False, **result},
                            request, text, cribs, known)


def run_layers(request):
    allowed = {"target", "ciphertext", "cribs", "alphabet", "cipher", "order", "permutation", "period_a", "period_b", "max_candidates", "top", "time_limit_seconds"}
    if not isinstance(request, dict) or set(request) - allowed:
        raise ValueError("unknown layered request field")
    if request.get("cipher", "vigenere") != "vigenere":
        raise ValueError("layered model currently supports additive vigenere only")
    target, text, cribs, known = _target(request)
    alphabet = get_alphabet(request.get("alphabet", "kryptos"))
    limit = _integer(request.get("max_candidates", 676), "max_candidates", 1, 100000)
    keep = _integer(request.get("top", 10), "top", 1, 100)
    seconds = _integer(request.get("time_limit_seconds", 10), "time_limit_seconds", 1, 600)
    bounds = {"max_candidates": limit, "top": keep, "time_limit_seconds": seconds}
    plan = compile_layer_plan(len(text), known, request.get("order", "STS"),
        request.get("permutation", list(range(len(text)))),
        _integer(request.get("period_a", 8), "period_a", 1, 256),
        _integer(request.get("period_b", 10), "period_b", 1, 256))
    outcome = plan.solve(text, known, alphabet)
    result = {"target": target, "authenticated_solution": False,
              "feasible": outcome["feasible"], "conflict_edge": outcome["conflict_edge"],
              "residual_mod_26": outcome["residual_mod_26"],
              "model": {"cipher": "vigenere", "order": plan.order, "periods": [plan.period_a, plan.period_b],
                        "alphabet": alphabet, "permutation": list(plan.permutation),
                        "convention": "T(x)[j]=x[permutation[j]], zero-based"}}
    if not outcome["feasible"]:
        return explain_layers(result, request, text, cribs, known, bounds)
    solution = outcome["solution"]
    result.update({"prediction_mask": solution.prediction_mask(),
        "plaintext_dimension": plan.plaintext_dimension,
        "distinct_plaintext_count": solution.distinct_plaintext_count,
        "scored_characters": len(text) - len(known), "candidates": [],
        "evaluated": 0, "enumeration_complete": False, "stop_reason": None})
    if solution.distinct_plaintext_count > limit:
        result["stop_reason"] = "candidate_limit; no arbitrary subset or representative ranked"
        return explain_layers(result, request, text, cribs, known, bounds)
    start = time.monotonic()
    for values, plaintext in solution.enumerate_plaintexts(limit):
        if time.monotonic() - start >= seconds:
            result["stop_reason"] = "time_limit"
            break
        keys = solution.keys(values)
        reencrypted = plaintext
        key_iterator = iter(keys)
        for stage in plan.order:
            if stage == "T":
                reencrypted = "".join(reencrypted[i] for i in plan.permutation)
            else:
                reencrypted = encrypt(reencrypted, next(key_iterator), alphabet=request.get("alphabet", "kryptos"))
        if reencrypted != text:
            raise AssertionError("candidate failed literal-stage re-encryption")
        candidate = {"plaintext": plaintext, "keys": keys, "freedom_values": values,
                     "score": english_score(plaintext, known),
                     "language_score_available": len(text) > len(known)}
        result["evaluated"] += 1
        result["candidates"].append(candidate)
        result["candidates"].sort(key=lambda item: (-item["score"], item["plaintext"]))
        del result["candidates"][keep:]
    else:
        result["enumeration_complete"] = True
        result["stop_reason"] = "exhausted_declared_plaintext_family"
    result["runtime_seconds"] = time.monotonic() - start
    result["interpretation"] = "Exact crib fits under a hypothetical model; English rank is not authentication."
    return explain_layers(result, request, text, cribs, known, bounds)


def doctor():
    executable = shutil.which("nvidia-smi")
    if executable is None and os.name == "nt":
        fallback = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/nvidia-smi.exe"
        executable = str(fallback) if fallback.is_file() else None
    gpu = {"status": "query_tool_unavailable"}
    if executable:
        try:
            query = subprocess.run([executable, "--query-gpu=name,memory.total,utilization.gpu", "--format=csv,noheader"],
                                   capture_output=True, text=True, timeout=5, check=False)
            gpu = {"status": "ok" if query.returncode == 0 else "query_failed",
                   "devices": query.stdout.strip().splitlines() if query.returncode == 0 else [],
                   "returncode": query.returncode}
        except (OSError, subprocess.TimeoutExpired) as exc:
            gpu = {"status": type(exc).__name__}
    gpu["interpretation"] = "nvidia-smi reports device visibility, not compiled CUDA readiness; the local app performs the actual backend probe."
    return {"python": sys.version, "platform": platform.platform(), "logical_cpus": os.cpu_count(),
            "gpu": gpu, "execution": "Exact constraints run on CPU; family scans support 1..4 CPU workers or an optional compiled CUDA backend. GPU readiness is checked separately by the local app."}


def run_grid(request):
    allowed = {"target", "ciphertext", "cribs", "alphabet", "permutation", "cells",
               "row_frame", "column_frame", "row_shift", "column_shift"}
    if not isinstance(request, dict) or set(request) - allowed:
        raise ValueError("unknown grid request field")
    target, text, cribs, known = _target(request)
    if "cells" not in request and (target != "k4" or text != K4_CIPHERTEXT):
        raise ValueError("a custom grid requires explicit occupied cells")
    cells = request.get("cells", k4_cells())
    route = request.get("permutation", list(range(len(text))))
    model = {"cells": cells, "permutation": route, "alphabet": request.get("alphabet", "kryptos"),
             "row_frame": request.get("row_frame", "source"), "column_frame": request.get("column_frame", "source"),
             "row_shift": request.get("row_shift", 0), "column_shift": request.get("column_shift", 0)}
    result = check_grid_model(text, known, **model)
    return explain_grid({"target": target, "authenticated_solution": False, "model": model, **result},
                        request, text, cribs, known)


def run_residues(request):
    allowed = {"target", "ciphertext", "cribs", "alphabet", "modulus", "step"}
    if not isinstance(request, dict) or set(request) - allowed:
        raise ValueError("unknown residue request field")
    target, text, cribs, known = _target(request)
    result = check_position_residues(text, known, modulus=request.get("modulus", 2),
        step=request.get("step", 1), alphabet=request.get("alphabet", "standard"))
    return explain_residues({"target": target, "authenticated_solution": False, **result}, request, text, cribs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("recover", "layers", "grid", "residues", "columns", "general", "optimize", "alphabet", "layout", "joint", "joint-ranked", "scheduled", "mixed", "alphabet-plus", "optimize-plus", "batch", "validate-holdout", "validate-controls", "validate-ablations", "constraint-lab", "factor-lab", "model-lab", "grammar-lab", "doctor"))
    parser.add_argument("--request", type=Path, help="JSON request; omitted uses canonical K4 defaults")
    parser.add_argument("--output", type=Path, help="new JSON output file; otherwise standard output")
    args = parser.parse_args()
    try:
        if args.output and args.output.exists():
            raise ValueError("output exists; use a new path to preserve previous evidence")
        request = _strict_json(args.request) if args.request else {}
        from .advanced_cli import run_advanced, json_safe_integers
        from .next_cli import run_next
        from .joint_ranked import run_joint_ranked
        from .validation_protocols import run_validation
        from .research_methods import COMMANDS, execute as run_research_method
        original = {"recover": run_recovery, "layers": run_layers, "grid": run_grid, "residues": run_residues}
        result = (run_research_method(args.command,request) if args.command in COMMANDS else doctor() if args.command == "doctor" else run_joint_ranked(request,_target) if args.command=='joint-ranked'
                  else run_validation(args.command,request) if args.command=='validate-ablations' else original[args.command](request)
                  if args.command in original else run_next(args.command, request, _target)
                  if args.command in ("joint", "scheduled", "mixed", "alphabet-plus", "optimize-plus", "batch", "validate-holdout", "validate-controls")
                  else run_advanced(args.command, request, _target))
        encoded = json.dumps(json_safe_integers(result), indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
            print(f"Saved {args.output}")
        else:
            print(encoded, end="")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
