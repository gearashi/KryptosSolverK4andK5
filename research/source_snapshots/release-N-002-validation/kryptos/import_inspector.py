"""Bounded inspection of inert exports; no imported path or code is executed.

This literal replayer deliberately does not import search or replay modules.
Positions in its trace are zero-based. Display layers may add one for humans.
"""
import hashlib
import json
import math
import string

LETTERS = string.ascii_uppercase
KRYPTOS = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MAX_BYTES = 1572864
MAX_LETTERS = 512
MAX_CANDIDATES = 1000
SCHEMA = "kryptos.import-inspection.v1"
UNSAFE_FIELDS = {"checkpoint_path", "resume_path", "output_path", "state_dir",
                 "executable", "script_path", "shell_command", "argv"}


def _canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("Artifact must be bounded finite JSON") from error


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON object field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Nonfinite JSON number")


def _load(artifact):
    raw_hash = None
    if isinstance(artifact, str):
        try:
            raw = artifact.encode("utf-8")
        except UnicodeError as error:
            raise ValueError("Artifact must contain valid Unicode") from error
        if len(raw) > MAX_BYTES:
            raise ValueError("Artifact exceeds the 1.5 MiB limit")
        raw_hash = _hash(raw)
        try:
            artifact = json.loads(artifact, object_pairs_hook=_pairs,
                                  parse_constant=_invalid_constant)
        except (json.JSONDecodeError, RecursionError) as error:
            raise ValueError("Artifact is not valid bounded JSON") from error
    raw = _canonical(artifact)
    if len(raw) > MAX_BYTES:
        raise ValueError("Artifact exceeds the 1.5 MiB limit")
    stack, count = [(artifact, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 40:
            raise ValueError("Artifact exceeds structural limits")
        if isinstance(value, dict):
            if any(type(key) is not str for key in value):
                raise ValueError("Object keys must be strings")
            if UNSAFE_FIELDS & set(value):
                raise ValueError("Imported execution or checkpoint controls are not accepted")
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif value is not None and type(value) not in (str, bool, int, float):
            raise ValueError("Artifact must contain only JSON values")
        elif type(value) is float and not math.isfinite(value):
            raise ValueError("Nonfinite JSON number")
    if not isinstance(artifact, dict):
        raise ValueError("Artifact must be a JSON object")
    return artifact, _hash(raw), raw_hash


def _letters(value, label):
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_LETTERS or any(c not in LETTERS for c in value):
        raise ValueError(f"{label} must contain 1..512 complete uppercase A-Z letters")
    return value


def _alphabet(value):
    value = {"standard": LETTERS, "kryptos": KRYPTOS}.get(value, value) if isinstance(value, str) else value
    if not isinstance(value, str) or len(value) != 26 or set(value) != set(LETTERS):
        raise ValueError("Alphabet must be a permutation of uppercase A-Z")
    return value


def _known(cribs, n):
    if not isinstance(cribs, list) or len(cribs) > MAX_LETTERS:
            raise ValueError("Explicit cribs must be a list of at most 512 entries")
    known = {}
    for crib in cribs:
        if not isinstance(crib, dict) or set(crib) != {"start", "text"}:
            raise ValueError("Each crib needs only start and text")
        start, word = crib["start"], _letters(crib["text"], "Crib")
        if type(start) is not int or start < 1 or start + len(word) - 1 > n:
            raise ValueError("One-based crib is outside the message")
        for i, letter in enumerate(word, start - 1):
            if i in known and known[i] != letter:
                raise ValueError("Overlapping cribs disagree")
            known[i] = letter
    return known


def _fields(value, allowed, label):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ValueError(f"Unsupported {label} fields")


def _replay(plaintext, recipe):
    schema = recipe.get("schema") if isinstance(recipe, dict) else None
    if schema not in ("kryptos.encryption-recipe.v1", "kryptos.expanded-recipe.v1"):
        raise ValueError("Unsupported encryption recipe schema")
    _fields(recipe, {"schema", "alphabet", "cells", "index_origin", "arithmetic", "stages", "key_sharing_convention"}, "recipe")
    if type(recipe.get("index_origin", 0)) is not int or recipe.get("index_origin", 0) != 0 or recipe.get("arithmetic", "modulo 26") != "modulo 26":
        raise ValueError("Only zero-based modulo26 recipes are supported")
    expanded = schema == "kryptos.expanded-recipe.v1"
    global_alphabet = None if expanded else _alphabet(recipe.get("alphabet"))
    stages = recipe.get("stages")
    if not isinstance(stages, list) or not 1 <= len(stages) <= 16:
        raise ValueError("Recipe needs1..16 stages")
    n, text, origins, trace = len(plaintext), plaintext, list(range(len(plaintext))), []
    for number, stage in enumerate(stages, 1):
        if not isinstance(stage, dict):
            raise ValueError("Stage must be an object")
        operation = stage.get("operation")
        inputs, prior_origins, mapping = text, origins[:], list(range(n))
        details = {}
        if operation == "gather":
            _fields(stage, {"operation", "permutation", "formula"}, "gather")
            route = stage.get("permutation")
            if not isinstance(route, list) or len(route) != n or any(type(i) is not int for i in route) or sorted(route) != list(range(n)):
                raise ValueError("Gather must be a zero-based bijection of all positions")
            mapping = route[:]
            text = "".join(inputs[i] for i in mapping)
            origins = [prior_origins[i] for i in mapping]
            details["formula"] = "output[j] = input[permutation[j]]"
        elif operation == "repeat_substitution":
            _fields(stage, {"operation", "cipher", "key_pattern", "key_origin", "formula", "alphabet"}, "substitution")
            if type(stage.get("key_origin", 0)) is not int or stage.get("key_origin", 0) != 0:
                raise ValueError("Only a zero-origin literal key pattern is supported")
            if not expanded and "alphabet" in stage:
                raise ValueError("Per-stage alphabets require the expanded-recipe schema")
            alphabet = _alphabet(stage.get("alphabet")) if expanded else global_alphabet
            key, cipher = stage.get("key_pattern"), stage.get("cipher")
            if not isinstance(key, str) or not 1 <= len(key) <= MAX_LETTERS or any(c not in LETTERS + "?" for c in key):
                raise ValueError("Invalid key pattern")
            if expanded and len(key) != n:
                raise ValueError("Expanded keys must cover exactly every message position")
            if cipher not in ("vigenere", "beaufort", "variant"):
                raise ValueError("Unsupported substitution equation")
            indexes = {c: i for i, c in enumerate(alphabet)}
            output, keys = [], []
            for i, letter in enumerate(inputs):
                symbol = key[i % len(key)]
                if symbol == "?":
                    raise ValueError("Replay encounters an unresolved key position")
                p, k = indexes[letter], indexes[symbol]
                value = p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k
                output.append(alphabet[value % 26])
                keys.append(symbol)
            text = "".join(output)
            details.update(alphabet=alphabet, cipher=cipher, key_symbols="".join(keys),
                           key_positions=[i % len(key) for i in range(n)],
                           formula={"vigenere": "C=P+K mod26", "beaufort": "C=K-P mod26", "variant": "C=P-K mod26"}[cipher])
        elif operation == "coordinate_shift" and not expanded:
            _fields(stage, {"operation", "axis", "lookup_offset", "keys", "formula"}, "coordinate shift")
            cells, axis, offset, keys = recipe.get("cells"), stage.get("axis"), stage.get("lookup_offset"), stage.get("keys")
            if not isinstance(cells, list) or len(cells) != n or any(not isinstance(c, list) or len(c) != 2 or any(type(v) is not int or abs(v) > 1000000 for v in c) for c in cells):
                raise ValueError("Coordinate geometry must match occupied message positions")
            if axis not in ("row", "column") or type(offset) is not int or abs(offset) > 1000000:
                raise ValueError("Invalid coordinate axis or offset")
            if not isinstance(keys, list) or len(keys) > n or any(not isinstance(k, dict) or set(k) != {"coordinate", "shift"} or type(k["coordinate"]) is not int or type(k["shift"]) is not int or not 0 <= k["shift"] < 26 for k in keys):
                raise ValueError("Invalid coordinate shifts")
            key_map = {k["coordinate"]: k["shift"] for k in keys}
            coordinate_index = 0 if axis == "row" else 1
            if len(key_map) != len(keys) or set(key_map) != {c[coordinate_index] for c in cells}:
                raise ValueError("Coordinate shifts must cover occupied labels exactly")
            lookup = [(i + offset) % n for i in range(n)]
            coordinates = [cells[i][coordinate_index] for i in lookup]
            shifts = [key_map[c] for c in coordinates]
            text = "".join(global_alphabet[(global_alphabet.index(c) + shift) % 26] for c, shift in zip(inputs, shifts))
            details.update(alphabet=global_alphabet, axis=axis, lookup_offset=offset,
                           lookup_positions=lookup, coordinates=coordinates, shifts=shifts,
                           formula="C[i]=P[i]+key[cells[(i+offset)%n][axis]] mod26")
        else:
            raise ValueError("Unsupported recipe operation")
        inverse = [0] * n
        original_to_output = [0] * n
        for j, i in enumerate(mapping):
            inverse[i] = j
        for j, i in enumerate(origins):
            original_to_output[i] = j
        trace.append({"stage": number, "operation": operation, "input": inputs,
                      "output": text, "output_sha256": _hash(text.encode("ascii")),
                      "output_to_input": mapping, "input_to_output": inverse,
                      "output_to_original": origins[:], "original_to_output": original_to_output,
                      **details})
    return text, trace


def inspect_import(body):
    """Inspect one exported candidate. This function performs no I/O or search."""
    _fields(body, {"artifact", "candidate_index"}, "inspection request")
    if "artifact" not in body:
        raise ValueError("Supply artifact JSON")
    artifact, digest, raw_digest = _load(body["artifact"])
    schema = artifact.get("schema")
    if schema == "kryptos.local-run.v1":
        request, candidates, legacy = artifact.get("request"), artifact.get("candidates"), False
    elif schema in (None, "kryptos.candidate-export.v1") and "request" in artifact and "candidate" in artifact:
        request, candidates, legacy = artifact["request"], [artifact["candidate"]], schema is None
    else:
        raise ValueError("Unsupported export schema; import a run or candidate export")
    if not isinstance(request, dict) or "ciphertext" not in request or "cribs" not in request:
        raise ValueError("Export must contain explicit ciphertext and cribs")
    ciphertext = _letters(request["ciphertext"], "Ciphertext")
    known = _known(request["cribs"], len(ciphertext))
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES or any(not isinstance(c, dict) for c in candidates):
        raise ValueError("Export must contain1..1000 candidate objects")
    selected = body.get("candidate_index", 0)
    if type(selected) is not int or not 0 <= selected < len(candidates):
        raise ValueError("Candidate index is outside the imported list")
    candidate = candidates[selected]
    plaintext = _letters(candidate.get("plaintext"), "Plaintext")
    if len(plaintext) != len(ciphertext):
        raise ValueError("Plaintext and ciphertext lengths disagree")
    explanation = candidate.get("explanation", {})
    if not isinstance(explanation, dict):
        raise ValueError("Candidate explanation must be an object")
    recipe = candidate.get("encryption_recipe") or explanation.get("encryption_recipe")
    actual, trace = _replay(plaintext, recipe)
    crib_failures = [{"position": i, "expected": c, "actual": plaintext[i]} for i, c in sorted(known.items()) if plaintext[i] != c]
    differences = [{"position": i, "expected": c, "actual": actual[i]} for i, c in enumerate(ciphertext) if actual[i] != c]
    valid = not crib_failures and not differences
    return {"schema": SCHEMA, "valid": valid, "classification": "replayed_model_consistency" if valid else "verification_failed",
            "artifact_sha256": digest, "raw_artifact_sha256": raw_digest,
            "artifact_schema": schema or "legacy_candidate_wrapper", "legacy_wrapper": legacy,
            "recipe_sha256": _hash(_canonical(recipe)), "ciphertext_sha256": _hash(ciphertext.encode("ascii")),
            "candidate_index": selected, "candidate_count": len(candidates),
            "candidates": [{"index": i, "preview": str(c.get("plaintext") or c.get("plaintext_mask") or "incomplete")[:64]} for i, c in enumerate(candidates)],
            "declared_target": request.get("target", "unspecified"), "ciphertext": ciphertext,
            "plaintext": plaintext, "reencrypted_ciphertext": actual, "trace": trace,
            "position_convention": "zero-based", "crib_matches": len(known) - len(crib_failures), "crib_total": len(known),
            "crib_failures": crib_failures, "ciphertext_differences": differences,
            "reencryption_matches": not differences, "source_identity_match": None,
            "provenance_note": "Artifact and recipe hashes identify supplied data. Saved verification, source/model hashes and path strings are untrusted metadata; no imported path was opened. Current source identity was not compared.",
            "authenticated_solution": False, "search_started": False,
            "interpretation": "Literal replay checks the supplied recipe and clues only. It does not authenticate the ciphertext, plaintext, source identity or Kryptos solution."}
