"""Deterministic, replayable explanations for exact CLI results.

Search methods and supplied assumptions are distinct from an encryption recipe.
No package claims authentication, and no external verifier is contacted.
"""

import hashlib
import json
from pathlib import Path
import string

from .ciphers import ALPHABETS


def _digest(value):
    encoded = value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _alphabet(value):
    if not isinstance(value, str):
        raise ValueError("recipe alphabet must be an uppercase A-Z permutation")
    letters = ALPHABETS.get(value, value)
    if not isinstance(letters, str) or len(letters) != 26 or set(letters) != set(string.ascii_uppercase):
        raise ValueError("recipe alphabet must be an uppercase A-Z permutation")
    return letters


def replay_recipe(plaintext, recipe):
    """Literally replay a generated recipe, returning every intermediate output.

    '?' key slots are accepted only if this finite message never encounters
    them. A partial plaintext cannot be replayed as a completed candidate.
    """
    if not isinstance(recipe, dict) or recipe.get("schema") != "kryptos.encryption-recipe.v1":
        raise ValueError("unsupported encryption recipe")
    alphabet = _alphabet(recipe.get("alphabet"))
    if not isinstance(plaintext, str) or not 1 <= len(plaintext) <= 4096 or any(c not in alphabet for c in plaintext):
        raise ValueError("recipe replay needs a complete plaintext in its alphabet")
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    stages = recipe.get("stages")
    if not isinstance(stages, list) or not stages or len(stages) > 16:
        raise ValueError("recipe must have one through sixteen explicit stages")
    text, trace = plaintext, []
    for number, stage in enumerate(stages, 1):
        if not isinstance(stage, dict):
            raise ValueError("recipe stages must be objects")
        operation = stage.get("operation")
        if operation == "repeat_substitution":
            key = stage.get("key_pattern")
            cipher = stage.get("cipher")
            if (not isinstance(key, str) or not key or any(c not in alphabet + "?" for c in key)
                    or cipher not in ("vigenere", "beaufort", "variant")):
                raise ValueError("invalid repeating-substitution stage")
            result = []
            for position, symbol in enumerate(text):
                key_symbol = key[position % len(key)]
                if key_symbol == "?":
                    raise ValueError("recipe encounters an unresolved key position")
                p, k = index[symbol], index[key_symbol]
                value = p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k
                result.append(alphabet[value % 26])
            text = "".join(result)
        elif operation == "gather":
            permutation = stage.get("permutation")
            if (not isinstance(permutation, list) or len(permutation) != len(text)
                    or any(type(i) is not int for i in permutation)
                    or sorted(permutation) != list(range(len(text)))):
                raise ValueError("recipe gather must be a zero-based bijection")
            text = "".join(text[i] for i in permutation)
        elif operation == "coordinate_shift":
            cells, axis, offset = recipe.get("cells"), stage.get("axis"), stage.get("lookup_offset")
            if (not isinstance(cells, list) or len(cells) != len(text) or axis not in ("row", "column")
                    or type(offset) is not int or any(not isinstance(cell, list) or len(cell) != 2
                    or any(type(value) is not int for value in cell) for cell in cells)):
                raise ValueError("invalid coordinate-shift geometry")
            keys = stage.get("keys")
            if (not isinstance(keys, list) or any(not isinstance(row, dict) or set(row) != {"coordinate", "shift"}
                    or type(row["coordinate"]) is not int or type(row["shift"]) is not int
                    or not 0 <= row["shift"] < 26 for row in keys)):
                raise ValueError("invalid coordinate key assignments")
            mapping = {row["coordinate"]: row["shift"] for row in keys}
            axis_index = 0 if axis == "row" else 1
            if len(mapping) != len(keys) or set(mapping) != {cell[axis_index] for cell in cells}:
                raise ValueError("coordinate keys must cover occupied labels exactly")
            text = "".join(alphabet[(index[symbol] + mapping[cells[(i + offset) % len(text)][axis_index]]) % 26]
                           for i, symbol in enumerate(text))
        else:
            raise ValueError("unknown recipe operation")
        trace.append({"stage": number, "operation": operation, "output": text, "sha256": _digest(text)})
    return {"ciphertext": text, "stages": trace}


def _recipe(alphabet, stages, cells=None):
    value = {"schema": "kryptos.encryption-recipe.v1", "alphabet": _alphabet(alphabet),
             "index_origin": 0, "arithmetic": "modulo 26", "stages": stages}
    if cells is not None:
        value["cells"] = [list(cell) for cell in cells]
    return value


def _substitution(key, cipher="vigenere"):
    return {"operation": "repeat_substitution", "cipher": cipher, "key_pattern": key,
            "key_origin": 0, "formula": {"vigenere": "C=P+K", "beaufort": "C=K-P", "variant": "C=P-K"}[cipher] + " mod 26"}


def _gather(permutation):
    return {"operation": "gather", "permutation": list(permutation), "formula": "output[j]=input[permutation[j]]"}


def _evidence(plaintext, mask, recipe, ciphertext, known):
    matches = sum(mask[i] == symbol for i, symbol in known.items())
    if matches != len(known):
        raise AssertionError("explanation encountered a candidate that violates supplied cribs")
    result = {"crib_positions_checked": len(known), "crib_matches": matches,
              "expected_ciphertext": ciphertext, "expected_ciphertext_sha256": _digest(ciphertext),
              "external_verification_performed": False, "authentication": "not established"}
    if plaintext is None:
        result.update(status="not_replayed_incomplete_plaintext", literal_reencryption_matches=None,
                      reencrypted_ciphertext=None, stage_outputs=[])
    else:
        replay = replay_recipe(plaintext, recipe)
        if replay["ciphertext"] != ciphertext:
            raise AssertionError("explanation's independent literal recipe does not reproduce ciphertext")
        result.update(status="literal_reencryption_verified", literal_reencryption_matches=True,
                      reencrypted_ciphertext=replay["ciphertext"], stage_outputs=replay["stages"],
                      plaintext_sha256=_digest(plaintext))
    return result


def _run(command, request, ciphertext, cribs, assumptions, search, summary):
    modules = {"recover": ("recovery.py",), "layers": ("layer_plan.py", "scoring.py"),
               "grid": ("grid.py",), "residues": ("position_residues.py",)}[command]
    root = Path(__file__).resolve().parent
    files = sorted(set(("__main__.py", "explanations.py", "ciphers.py", "data.py") + modules))
    return {
        "schema": "kryptos.result-explanation.v1", "summary": summary,
        "authenticated_solution": False,
        "input": {"ciphertext": ciphertext, "ciphertext_sha256": _digest(ciphertext), "cribs": cribs,
                  "crib_position_convention": "one-based original plaintext positions"},
        "supplied_assumptions": assumptions,
        "request_fields_supplied": sorted(request), "request_sha256": _digest(request),
        "search": search,
        "provenance": {"command": "python -m kryptos " + command,
                       "source_files": [{"path": "kryptos/" + name,
                                         "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()} for name in files]},
        "limits_of_evidence": "Crib agreement and re-encryption show consistency under the stated assumptions; they do not authenticate the cipher or plaintext.",
    }


def explain_recovery(result, request, ciphertext, cribs, known):
    routes = request.get("routes")
    if routes is None:
        routes = [{"permutation": list(range(len(ciphertext))), "order": "ST"}]
    distinct = {}
    for route in routes:
        key = (tuple(route["permutation"]), route.get("order", "ST"))
        distinct.setdefault(key, {"permutation": list(key[0]), "order": key[1]})
    route_rows = list(distinct.values())
    assumptions = {"cipher": result["cipher"], "alphabet": result["alphabet"],
                   "declared_periods": result["periods"], "declared_routes": route_rows,
                   "key_origin": "index zero at the substitution stage; arbitrary key rotations are already included"}
    search = {"algorithm": "Derive repeating-key residues exactly from cribs for each declared route/period; reject contradictions; canonicalize complete keys.",
              "bounds": result["limits"], "work": result["work"], "complete": result["complete"],
              "stop_reason": result["stop_reason"], "language_scoring": "none"}
    family_count = len(result["candidates"])
    family_word = "family" if family_count == 1 else "families"
    result["explanation"] = _run("recover", request, ciphertext, cribs, assumptions, search,
                                 f"Crib-guided {result['cipher']} recovery returned {family_count} candidate {family_word} within the supplied routes and periods.")
    for candidate in result["candidates"]:
        route = route_rows[candidate["route_index"]]
        s = _substitution(candidate["key_pattern"], result["cipher"])
        t = _gather(route["permutation"])
        recipe = _recipe(result["alphabet"], [s, t] if route["order"] == "ST" else [t, s])
        complete = candidate["plaintext_complete"]
        classification = "complete_candidate" if complete and candidate["key_complete"] else "complete_plaintext_with_partial_key" if complete else "partial_candidate"
        candidate["explanation"] = {
            "classification": classification,
            "summary": f"Used exact crib-derived {result['cipher']} key residues with stage order {route['order']}. "
                       + ("The full plaintext re-encrypts exactly." if complete else "Unresolved key and plaintext positions remain '?'; no full plaintext is claimed."),
            "assumptions_reference": "result.explanation.supplied_assumptions",
            "recovered_values": {"key_pattern": candidate["key_pattern"], "key_complete": candidate["key_complete"],
                                 "canonical_period": candidate["canonical_period"], "fitting_declared_periods": candidate["declared_periods"],
                                 "selected_route_index": candidate["route_index"], "selected_route_aliases": candidate["route_aliases"],
                                 "plaintext_mask": candidate["plaintext_mask"]},
            "encryption_recipe": recipe,
            "verification": _evidence(candidate["plaintext"], candidate["plaintext_mask"], recipe, ciphertext, known),
            "authenticated_solution": False,
        }
    return result


def explain_layers(result, request, ciphertext, cribs, known, limits):
    model = result["model"]
    search = {"algorithm": "Solve exact bipartite modular crib constraints; enumerate each distinct plaintext once after removing key shifts that change no plaintext.",
              "bounds": limits, "feasibility_checked": True, "evaluated": result.get("evaluated", 0),
              "enumeration_complete": result.get("enumeration_complete", False), "stop_reason": result.get("stop_reason"),
              "ranking": "Built-in English heuristic, excluding every crib position and features touching it; not solution confidence.",
              "ranking_retains_at_most": limits["top"]}
    plaintext_word = "plaintext" if result.get("distinct_plaintext_count") == 1 else "plaintexts"
    summary = ("The stated two-additive-substitution/route model contradicts the cribs." if not result["feasible"]
               else f"Exact layered constraints admit {result['distinct_plaintext_count']} distinct {plaintext_word}; enumerated {result['evaluated']} and retained {len(result['candidates'])}.")
    result["explanation"] = _run("layers", request, ciphertext, cribs, model, search, summary)
    for candidate in result.get("candidates", []):
        keys = iter(candidate["keys"])
        stages = [_gather(model["permutation"]) if stage == "T" else _substitution(next(keys)) for stage in model["order"]]
        recipe = _recipe(model["alphabet"], stages)
        candidate["explanation"] = {
            "classification": "complete_candidate",
            "summary": f"Candidate from exact crib-constrained additive layers in order {model['order']}, with key periods {model['periods'][0]} and {model['periods'][1]}; literal re-encryption verified.",
            "assumptions_reference": "result.explanation.supplied_assumptions",
            "recovered_values": {"representative_keys": list(candidate["keys"]), "plaintext": candidate["plaintext"]},
            "chosen_values": {"plaintext_freedom_values": list(candidate["freedom_values"]),
                              "key_note": "Representative keys include fixed gauge choices; other keys can encode this same plaintext."},
            "encryption_recipe": recipe,
            "verification": _evidence(candidate["plaintext"], candidate["plaintext"], recipe, ciphertext, known),
            "rank_is_authentication": False, "authenticated_solution": False,
        }
    return result


def explain_grid(result, request, ciphertext, cribs, known):
    model = result["model"]
    search = {"algorithm": "Propagate exact row-plus-column shift constraints in a bipartite graph; count connected-component freedoms and forced plaintext positions.",
              "bounds": {"models": 1, "text_positions": len(ciphertext), "crib_positions": len(known), "key_slots": result["key_slots"]},
              "complete": True, "language_scoring": "none", "key_enumeration": "none"}
    summary = ("The declared occupied-grid shift model contradicts the cribs." if not result["feasible"] else
               f"The grid constraints admit {result['distinct_plaintext_count']} plaintexts. The displayed representative is a consistency witness, with unresolved choices preserved in the mask.")
    explanation = _run("grid", request, ciphertext, cribs, model, search, summary)
    explanation["classification"] = "consistency_witness" if result["feasible"] else "infeasible_model"
    if result["feasible"]:
        shifts = {}
        for axis, field in (("row", "row_keys"), ("column", "column_keys")):
            shifts[axis] = {"operation": "coordinate_shift", "axis": axis,
                            "lookup_offset": model[axis + "_shift"],
                            "keys": [{"coordinate": coordinate, "shift": value} for coordinate, value in sorted(result[field].items())],
                            "formula": "output[i]=alphabet[(idx(input[i])+key[cells[(i+lookup_offset)%n][axis]])%26]"}
        stages = [shifts[axis] for axis in ("row", "column") if model[axis + "_frame"] == "source"]
        stages.append(_gather(model["permutation"]))
        stages += [shifts[axis] for axis in ("row", "column") if model[axis + "_frame"] == "destination"]
        recipe = _recipe(model["alphabet"], stages, model["cells"])
        explanation.update(
            recovered_values={"forced_plaintext_mask": result["plaintext_mask"], "plaintext_dimension": result["plaintext_dimension"],
                              "distinct_plaintext_count": result["distinct_plaintext_count"], "forced_unknown_positions": result["forced_unknown_positions"]},
            chosen_values={"row_keys": result["row_keys"], "column_keys": result["column_keys"],
                           "component_roots": "all zero; these include gauge choices and, when present, arbitrary unresolved plaintext choices"},
            encryption_recipe=recipe,
            verification=_evidence(result["representative_plaintext"], result["plaintext_mask"], recipe, ciphertext, known),
        )
    result["explanation"] = explanation
    return result


def explain_residues(result, request, ciphertext, cribs):
    assumptions = {"alphabet": _alphabet(result["alphabet"]), "modulus": result["modulus"], "step": result["step"],
                   "position_origin": 1, "formula": "idx(C[i])=F(P[i])+step*i modulo modulus, where F is an unknown bijection"}
    search = {"algorithm": "Check repeated-letter residue consistency and bijection class capacities; count balanced residue partitions combinatorially.",
              "bounds": {"models": 1, "text_positions": len(ciphertext)}, "complete": True, "plaintext_search": "none"}
    result["explanation"] = _run("residues", request, ciphertext, cribs, assumptions, search,
                                  "This is a residue-constraint check only. No full substitution, plaintext, or encryption recipe has been recovered.")
    result["explanation"].update(classification="constraint_only", encryption_recipe=None,
        recovered_values={"residue_constraint_feasible": result["feasible"],
                          "letter_residues": result.get("letter_residues"),
                          "residue_partition_completions": result.get("residue_partition_completions")},
        verification={"status": "constraint_check_only", "literal_reencryption_matches": None,
                      "external_verification_performed": False, "authentication": "not established"})
    return result
