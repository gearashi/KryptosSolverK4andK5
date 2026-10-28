"""Explicit finite language and semantic hypotheses with replayable witnesses.

No dictionaries, codebooks, foreign-language claims or K5 plaintext are invented.
Callers supply the finite models and their origins. These routines can reject
only within those models, and never rewrite confirmed plaintext crib positions.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
import json


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _source(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("an explicit source or hypothesis description is required")
    return value


def _bounded_text(value, name="text", maximum=512):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must contain 1..{maximum} characters")
    return value


def _int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def expand_morphology(stems, suffixes, *, source):
    """Compile a caller-declared finite stem/suffix relation to lexical entries.

    Each stem is {text, class, score}; each suffix is {text, classes, tag, score}.
    A suffix licenses only its explicit stem classes. This is a model-building
    aid, not an assertion that a Latin or Romance grammar is complete.
    """
    _source(source)
    if not isinstance(stems, list) or not isinstance(suffixes, list) or not 1 <= len(stems)*len(suffixes) <= 10000:
        raise ValueError("supply a nonempty stem/suffix product of at most 10000")
    entries = {}; witnesses = defaultdict(list); checks = 0
    for stem in stems:
        if not isinstance(stem, dict) or set(stem) != {"text", "class", "score"}:
            raise ValueError("stem requires text, class, score")
        _bounded_text(stem["text"], "stem", 128)
        _source(stem["class"]); _int(stem["score"], "stem score", -1000000, 1000000)
        for suffix in suffixes:
            checks += 1
            if not isinstance(suffix, dict) or set(suffix) != {"text", "classes", "tag", "score"} or not isinstance(suffix["text"], str) or len(suffix["text"]) > 128 or not isinstance(suffix["classes"], list) or any(not isinstance(c, str) for c in suffix["classes"]):
                raise ValueError("suffix requires bounded text, classes, tag, score")
            _source(suffix["tag"]); _int(suffix["score"], "suffix score", -1000000, 1000000)
            if stem["class"] not in suffix["classes"]:
                continue
            text = stem["text"]+suffix["text"]
            key = (text, suffix["tag"])
            score = stem["score"]+suffix["score"]
            entries[key] = max(entries.get(key, score), score)
            witnesses[key].append({"stem": stem["text"], "suffix": suffix["text"], "class": stem["class"], "score": score})
    return {"entries": [{"text": text, "tag": tag, "score": score} for (text, tag), score in sorted(entries.items())],
            "witnesses": [{"text": text, "tag": tag, "derivations": witnesses[(text, tag)]} for text, tag in sorted(entries)],
            "source": source, "work": {"stem_suffix_checks": checks}}


def segment_lattice(text, lexicons, *, unknown_score=-10, max_switches=0,
                    switch_penalty=0, grammar=None, max_states=200000):
    """Exact Viterbi lattice over boundaries, tags, language and switch count.

    Unknown characters always remain possible with the declared single-character
    score. Grammar entries are additive scores, not silently forbidden pairs.
    The objective and supplied finite lexicons are explicit; this is guidance,
    never a hard proof about natural-language plaintext.
    """
    _bounded_text(text)
    _int(unknown_score, "unknown_score", -1000000, 1000000)
    _int(max_switches, "max_switches", 0, 16)
    _int(switch_penalty, "switch_penalty", -1000000, 1000000)
    _int(max_states, "max_states", 1, 2000000)
    if not isinstance(lexicons, list) or not 1 <= len(lexicons) <= 8:
        raise ValueError("supply 1..8 explicitly sourced lexicons")
    languages, indexed = [], {}
    for lex in lexicons:
        if not isinstance(lex, dict) or set(lex) != {"language", "source", "entries"}:
            raise ValueError("lexicon requires language, source and entries")
        language = _source(lex["language"]); _source(lex["source"])
        if language in languages:
            raise ValueError("language labels must be unique")
        languages.append(language)
        if not isinstance(lex["entries"], list) or len(lex["entries"]) > 10000:
            raise ValueError("at most 10000 entries per lexicon")
        normalized = {}
        for entry in lex["entries"]:
            if not isinstance(entry, dict) or set(entry) != {"text", "tag", "score"}:
                raise ValueError("lexical entry requires text, tag, score")
            token = _bounded_text(entry["text"], "token", 256)
            tag = _source(entry["tag"]); score = _int(entry["score"], "lexical score", -1000000, 1000000)
            normalized[(token, tag)] = max(normalized.get((token, tag), score), score)
        byfirst = defaultdict(list)
        for (token, tag), score in sorted(normalized.items()):
            byfirst[token[0]].append((token, tag, score, False))
        indexed[language] = byfirst
    grammar = [] if grammar is None else grammar
    if not isinstance(grammar, list) or len(grammar) > 10000:
        raise ValueError("grammar must be a bounded list of scored tag pairs")
    transitions = {}
    for entry in grammar:
        if not isinstance(entry, dict) or set(entry) != {"previous", "next", "score"}:
            raise ValueError("grammar requires previous, next, score")
        key = (_source(entry["previous"]), _source(entry["next"]))
        if key in transitions:
            raise ValueError("duplicate grammar transition")
        transitions[key] = _int(entry["score"], "grammar score", -1000000, 1000000)
    # key = (last language, switches used, last tag); value = (score, tokens).
    lattice = [dict() for _ in range(len(text)+1)]
    lattice[0][(None, 0, "<s>")] = (0, ())
    work = {"states": 1, "transitions": 0, "lexical_match_checks": 0, "merged_prefixes": 0}
    def canonical(tokens):
        return tuple((t[0], t[1], t[2], t[3], t[4]) for t in tokens)
    for position in range(len(text)):
        for (previous, switches, prevtag), (score, tokens) in list(lattice[position].items()):
            for language in languages:
                changed = previous is not None and previous != language
                new_switches = switches+changed
                if new_switches > max_switches:
                    continue
                options = list(indexed[language].get(text[position], ()))+[(text[position], "<unknown>", unknown_score, True)]
                for token, tag, value, unknown in options:
                    work["lexical_match_checks"] += 1
                    if work["lexical_match_checks"] > max_states:
                        raise ValueError("language lattice match budget reached; no optimum reported")
                    if not text.startswith(token, position):
                        continue
                    work["transitions"] += 1
                    if work["transitions"] > max_states:
                        raise ValueError("language lattice transition budget reached; no optimum reported")
                    stop = position+len(token)
                    newscore = score+value+transitions.get((prevtag, tag), 0)+(switch_penalty if changed else 0)
                    newtokens = tokens+((position, stop, language, tag, token, unknown, value),)
                    key = (language, new_switches, tag)
                    old = lattice[stop].get(key)
                    if old is not None:
                        work["merged_prefixes"] += 1
                    if old is None or newscore > old[0] or newscore == old[0] and canonical(newtokens) < canonical(old[1]):
                        if old is None:
                            work["states"] += 1
                        lattice[stop][key] = (newscore, newtokens)
    ranked = [(score, tokens, key) for key, (score, tokens) in lattice[-1].items()]
    score, tokens, key = min(ranked, key=lambda entry: (-entry[0], canonical(entry[1]), entry[2]))
    witness = [{"start": a, "stop": b, "language": language, "tag": tag, "text": token,
                "unknown": unknown, "lexical_score": value} for a, b, language, tag, token, unknown, value in tokens]
    if "".join(t["text"] for t in witness) != text:
        raise AssertionError("segmentation witness failed reconstruction")
    return {"schema": "kryptos.language-lattice.v1", "text": text, "score": score,
            "tokens": witness, "switches": key[1], "work": work, "complete": True,
            "model_sha256": _digest({"lexicons": lexicons, "grammar": grammar, "unknown_score": unknown_score,
                                     "max_switches": max_switches, "switch_penalty": switch_penalty}),
            "interpretation": "Optimum of supplied finite scoring model; unknown characters remain available; not plaintext authentication."}


def verify_suggestions(ciphertext, suggestions, *, cribs=None, max_suggestions=1000):
    """Replay untrusted chat/LLM seeds; source text is data, never instructions."""
    from .explanations import replay_recipe
    _bounded_text(ciphertext, "ciphertext", 4096)
    _int(max_suggestions, "max_suggestions", 1, 10000)
    if not isinstance(suggestions, list) or len(suggestions) > max_suggestions:
        raise ValueError("suggestion count exceeds declared bound")
    cribs = {} if cribs is None else cribs
    if not isinstance(cribs, dict):
        raise ValueError("cribs must map positions to literal symbols")
    known = {}
    for raw, value in cribs.items():
        try:
            i = int(raw)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid crib position") from error
        if str(i) != str(raw) or not 0 <= i < len(ciphertext) or not isinstance(value, str) or len(value) != 1:
            raise ValueError("invalid literal crib")
        known[i] = value
    accepted, rejected, duplicate = [], [], 0
    seen = set()
    for number, suggestion in enumerate(suggestions):
        if not isinstance(suggestion, dict) or set(suggestion) != {"plaintext", "recipe", "source"}:
            raise ValueError("suggestion requires plaintext, recipe, source")
        _source(suggestion["source"])
        text = suggestion["plaintext"]
        identity = _digest(suggestion)
        if identity in seen:
            duplicate += 1; continue
        seen.add(identity)
        try:
            if not isinstance(text, str) or len(text) != len(ciphertext) or any(text[i] != c for i, c in known.items()):
                raise ValueError("length or literal crib mismatch")
            trace = replay_recipe(text, suggestion["recipe"])
            if trace["ciphertext"] != ciphertext:
                raise ValueError("recipe does not reproduce supplied ciphertext")
            accepted.append({**suggestion, "replay": trace, "verified": True})
        except (ValueError, TypeError, KeyError) as error:
            rejected.append({"index": number, "reason": str(error)})
    return {"accepted": accepted, "rejected": rejected, "duplicates_removed": duplicate,
            "interpretation": "Verified seeds only; neither a language model claim nor re-encryption authenticates Kryptos."}


def decode_codebook(text, codebook, *, source, target=None, target_length=None,
                    inventory=None, residues=None, necessary_filters=True,
                    max_states=200000, max_outputs=10000):
    """Decode an explicit finite word-to-code transducer with boundary DP.

    Equivalent (source position, output text) prefixes merge with witness counts.
    Optional length/inventory/residue suffix filters are necessary conditions,
    never independent assumptions. Input matches are literal and case-sensitive.
    """
    _bounded_text(text, maximum=256); _source(source)
    _int(max_states, "max_states", 1, 2000000); _int(max_outputs, "max_outputs", 1, 100000)
    if type(necessary_filters) is not bool:
        raise ValueError("necessary_filters must be boolean")
    if not isinstance(codebook, dict) or not 1 <= len(codebook) <= 256:
        raise ValueError("codebook requires 1..256 explicit entries")
    for key, value in codebook.items():
        _bounded_text(key, "codebook source", 256); _bounded_text(value, "codebook output", 256)
    if target is not None:
        _bounded_text(target, "target", 512)
        if target_length is not None and target_length != len(target):
            raise ValueError("target_length conflicts with target")
        target_length = len(target)
    if target_length is not None:
        _int(target_length, "target_length", 1, 512)
    inventory = {} if inventory is None else inventory
    if not isinstance(inventory, dict) or len(inventory) > 64:
        raise ValueError("inventory must map up to 64 symbols to exact output counts")
    for char, count in inventory.items():
        if not isinstance(char, str) or len(char) != 1:
            raise ValueError("inventory symbols must be single characters")
        _int(count, "inventory count", 0, 512)
    residues = [] if residues is None else residues
    if not isinstance(residues, list) or len(residues) > 32:
        raise ValueError("at most 32 modular count requirements")
    for entry in residues:
        if not isinstance(entry, dict) or set(entry) != {"symbol", "modulus", "value"} or not isinstance(entry["symbol"], str) or len(entry["symbol"]) != 1:
            raise ValueError("residue requires symbol, modulus and value")
        _int(entry["modulus"], "modulus", 2, 64)
        _int(entry["value"], "residue value", 0, entry["modulus"]-1)
    matches = [[(key, value) for key, value in sorted(codebook.items()) if text.startswith(key, i)] for i in range(len(text))]+[[]]
    work = {"setup_match_checks": len(text)*len(codebook), "suffix_transitions": 0,
            "states": 1, "transitions": 0, "merged_prefixes": 0, "filter_rejections": 0,
            "complete_interpretations": 0, "complete_output_evaluations": 0}
    # Suffix reachability is exact for length and each single count projection.
    lengths = [set() for _ in range(len(text)+1)]; lengths[-1] = {0}
    projections = {(c, None): [set() for _ in range(len(text)+1)] for c in inventory}
    projections.update({(r["symbol"], r["modulus"]): [set() for _ in range(len(text)+1)] for r in residues})
    for table in projections.values():
        table[-1] = {0}
    if necessary_filters:
        for i in range(len(text)-1, -1, -1):
            for key, value in matches[i]:
                stop = i+len(key)
                for length in lengths[stop]:
                    work["suffix_transitions"] += 1
                    total = length+len(value)
                    if total <= 512:
                        lengths[i].add(total)
                for (char, modulus), table in projections.items():
                    for count in table[stop]:
                        work["suffix_transitions"] += 1
                        total = count+value.count(char)
                        table[i].add(total if modulus is None else total % modulus)
                if work["suffix_transitions"] > max_states:
                    raise ValueError("codebook preprocessing budget reached")
    def feasible(position, output):
        if target is not None and not target.startswith(output):
            return False
        if len(output) > 512 or target_length is not None and len(output) > target_length:
            return False
        if not necessary_filters:
            return True
        if not lengths[position]:
            return False
        if target_length is not None and target_length-len(output) not in lengths[position]:
            return False
        for char, count in inventory.items():
            if count-output.count(char) not in projections[(char, None)][position]:
                return False
        for r in residues:
            if (r["value"]-output.count(r["symbol"])) % r["modulus"] not in projections[(r["symbol"], r["modulus"])][position]:
                return False
        return True
    lattice = [dict() for _ in range(len(text)+1)]
    if feasible(0, ""):
        lattice[0][""] = (1, ())
    else:
        work["filter_rejections"] += 1
    for position in range(len(text)):
        for output, (count, witness) in lattice[position].items():
            for key, value in matches[position]:
                work["transitions"] += 1
                if work["transitions"] > max_states:
                    raise ValueError("codebook transition budget reached")
                stop = position+len(key); newoutput = output+value
                if not feasible(stop, newoutput):
                    work["filter_rejections"] += 1; continue
                newwitness = witness+((position, stop, key, value),)
                if newoutput in lattice[stop]:
                    oldcount, oldwitness = lattice[stop][newoutput]
                    lattice[stop][newoutput] = (count+oldcount, min(newwitness, oldwitness))
                    work["merged_prefixes"] += 1
                else:
                    lattice[stop][newoutput] = (count, newwitness)
                    work["states"] += 1
    outputs = []
    for output, (count, witness) in sorted(lattice[-1].items()):
        work["complete_output_evaluations"] += 1
        work["complete_interpretations"] += count
        if target is not None and output != target or target_length is not None and len(output) != target_length or any(output.count(c) != count for c, count in inventory.items()) or any(output.count(r["symbol"]) % r["modulus"] != r["value"] for r in residues):
            continue
        if "".join(w[2] for w in witness) != text or "".join(w[3] for w in witness) != output:
            raise AssertionError("codebook witness failed replay")
        outputs.append({"text": output, "interpretation_count": count,
                        "segments": [{"start": a, "stop": b, "input": key, "output": value} for a, b, key, value in witness]})
        if len(outputs) > max_outputs:
            raise ValueError("codebook output budget reached")
    return {"schema": "kryptos.codebook-lattice.v1", "input": text, "outputs": outputs, "work": work,
            "source": source, "model_sha256": _digest(codebook), "complete": True,
            "interpretation": "Exact within supplied codebook and output constraints; ENE/BC are not substitutions for confirmed literal cribs."}


def source_keys(sources, transforms, *, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", max_keys=10000):
    """Finite source-derived key transducers with shortest-period quotient.

    Sources and each transform are retained as aliases. The quotient is exact
    for repeating keys only, not autokey or source-text hypotheses.
    """
    if not isinstance(alphabet, str) or len(alphabet) < 2 or len(set(alphabet)) != len(alphabet):
        raise ValueError("distinct alphabet symbols required")
    _int(max_keys, "max_keys", 1, 100000)
    if not isinstance(sources, list) or not isinstance(transforms, list) or not 1 <= len(sources)*len(transforms) <= max_keys:
        raise ValueError("source/transform product exceeds declared bound")
    grouped = {}; attempted = 0
    if any(not isinstance(s, dict) or not isinstance(s.get("text"), str) for s in sources):
        raise ValueError("key sources must contain text")
    if sum(len(s["text"]) for s in sources)*len(transforms) > 2000000:
        raise ValueError("source transform character-work bound exceeded")
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"id", "text", "source"}:
            raise ValueError("key source requires id, text, source")
        _source(source["id"]); _source(source["source"]); _bounded_text(source["text"], "source text", 100000)
        for transform in transforms:
            attempted += 1
            if not isinstance(transform, dict) or set(transform)-{"operation", "reverse", "stride", "offset"} or transform.get("operation") not in ("letters", "initials"):
                raise ValueError("transform operation must be letters or initials")
            reverse = transform.get("reverse", False)
            if type(reverse) is not bool:
                raise ValueError("reverse must be boolean")
            stride = _int(transform.get("stride", 1), "stride", 1, 128)
            offset = _int(transform.get("offset", 0), "offset", 0, stride-1)
            raw = source["text"].upper()
            text = "".join(c for c in raw if c in alphabet) if transform["operation"] == "letters" else "".join(word[0] for word in raw.split() if word and word[0] in alphabet)
            if reverse:
                text = text[::-1]
            key = text[offset::stride]
            if not key:
                continue
            prefix = [0]*len(key)
            for i in range(1, len(key)):
                j = prefix[i-1]
                while j and key[i] != key[j]:
                    j = prefix[j-1]
                if key[i] == key[j]:
                    j += 1
                prefix[i] = j
            period = len(key)-prefix[-1]
            primitive = key[:period] if len(key) % period == 0 else key
            grouped.setdefault(primitive, []).append({"source_id": source["id"], "source": source["source"],
                "input_sha256": sha256(source["text"].encode()).hexdigest(), "transform": transform, "raw_key": key})
    return {"keys": [{"key": key, "aliases": aliases} for key, aliases in sorted(grouped.items())],
            "work": {"transforms": attempted, "distinct_repeating_keys": len(grouped)},
            "interpretation": "Explicit bounded source hypotheses; deduplication applies only to repeating-key semantics."}


def robust_rank(candidates, models, *, objective="minimum", max_candidates=10000):
    """Rank a finite bank using a declared integer corpus-robust objective.

    Every model supplies n-gram integer weights, a default and positive scale.
    The minimum scaled corpus score or their sum is fixed before ranking. Equal
    texts are scored once and all caller labels are retained.
    """
    _int(max_candidates, "max_candidates", 1, 100000)
    if objective not in ("minimum", "sum"):
        raise ValueError("objective must be minimum or sum")
    if not isinstance(candidates, list) or len(candidates) > max_candidates or not isinstance(models, list) or not 1 <= len(models) <= 8:
        raise ValueError("invalid bounded candidate/model bank")
    for model in models:
        if not isinstance(model, dict) or set(model) != {"id", "source", "n", "weights", "default", "scale"}:
            raise ValueError("model requires id/source/n/weights/default/scale")
        _source(model["id"]); _source(model["source"])
        _int(model["n"], "n", 1, 8); _int(model["default"], "default", -1000000, 1000000)
        _int(model["scale"], "scale", 1, 1000000)
        if not isinstance(model["weights"], dict) or len(model["weights"]) > 100000:
            raise ValueError("bounded weight table required")
        for gram, weight in model["weights"].items():
            if not isinstance(gram, str) or len(gram) != model["n"]:
                raise ValueError("n-gram length mismatch")
            _int(weight, "weight", -1000000, 1000000)
    if len({m["id"] for m in models}) != len(models):
        raise ValueError("model IDs must be distinct")
    grouped = defaultdict(list)
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {"id", "text"}:
            raise ValueError("candidate requires id and text")
        _source(candidate["id"]); _bounded_text(candidate["text"], maximum=4096)
        grouped[candidate["text"]].append(candidate["id"])
    ranked = []; factors = 0
    if sum(max(0, len(text)-m["n"]+1) for text in grouped for m in models) > 2000000:
        raise ValueError("robust objective factor-work bound exceeded")
    for text, aliases in grouped.items():
        vector = []
        for model in models:
            score = 0
            for i in range(len(text)-model["n"]+1):
                score += model["weights"].get(text[i:i+model["n"]], model["default"])
                factors += 1
            vector.append(score*model["scale"])
        score = min(vector) if objective == "minimum" else sum(vector)
        ranked.append({"text": text, "aliases": aliases, "score": score, "corpus_scores": vector})
    ranked.sort(key=lambda c: (-c["score"], c["text"]))
    return {"candidates": ranked, "objective": objective, "model_sha256": _digest(models),
            "work": {"complete_candidate_evaluations": len(grouped), "model_evaluations": len(grouped)*len(models), "factor_evaluations": factors},
            "interpretation": "Exact ranking for the declared corpus objective; robustness does not authenticate plaintext."}


def compile_joint_cribs(length, extractions, *, literal_cribs=None):
    """Pull independently declared K5 output constraints back to K4 positions.

    Each extraction names input indices, output cribs and an independent source.
    Without an independent constraint the request is rejected, preventing a
    self-generated K5 interpretation from validating its own K4 candidate.
    """
    _int(length, "length", 1, 4096)
    if not isinstance(extractions, list) or not 1 <= len(extractions) <= 64:
        raise ValueError("supply 1..64 independently constrained extraction models")
    if literal_cribs is not None and not isinstance(literal_cribs, dict):
        raise ValueError("literal_cribs must be a position-to-symbol mapping")
    known = {}; witnesses = []; conflicts = []
    for position, symbol in (literal_cribs or {}).items():
        p = int(position)
        if str(p) != str(position) or not 0 <= p < length or not isinstance(symbol, str) or len(symbol) != 1:
            raise ValueError("invalid literal crib")
        known[p] = symbol
    for extraction in extractions:
        if not isinstance(extraction, dict) or set(extraction) != {"id", "indices", "output_cribs", "independent_source"}:
            raise ValueError("extraction requires id/indices/output_cribs/independent_source")
        _source(extraction["id"]); _source(extraction["independent_source"])
        indices = extraction["indices"]
        if not isinstance(indices, list) or not 1 <= len(indices) <= 4096 or any(type(i) is not int or not 0 <= i < length for i in indices):
            raise ValueError("extraction indices must address the input")
        cribs = extraction["output_cribs"]
        if not isinstance(cribs, dict) or not cribs:
            raise ValueError("independent output constraints are required")
        for raw, symbol in cribs.items():
            position = int(raw)
            if str(position) != str(raw) or not 0 <= position < len(indices) or not isinstance(symbol, str) or len(symbol) != 1:
                raise ValueError("invalid extraction output crib")
            parent = indices[position]
            if parent in known and known[parent] != symbol:
                conflicts.append({"input_position": parent, "first": known[parent], "second": symbol, "extraction": extraction["id"]})
            else:
                known[parent] = symbol
            witnesses.append({"extraction": extraction["id"], "output_position": position, "input_position": parent,
                              "symbol": symbol, "independent_source": extraction["independent_source"]})
    return {"feasible": not conflicts, "cribs": {str(p): c for p, c in sorted(known.items())}, "witnesses": witnesses,
            "conflicts": conflicts, "interpretation": "Conditional on caller-declared independent evidence and simultaneous extraction constraints; no K5 text is assumed."}


def extraction_bank(text, rules, *, max_rules=10000):
    """Source-traceable finite K5 extraction hypotheses, quotient by output."""
    _bounded_text(text, maximum=4096); _int(max_rules, "max_rules", 1, 100000)
    if not isinstance(rules, list) or not 1 <= len(rules) <= max_rules:
        raise ValueError("extraction rule count exceeds bound")
    grouped = defaultdict(list)
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"id", "indices", "source"}:
            raise ValueError("rule requires id, indices, source")
        _source(rule["id"]); _source(rule["source"])
        indices = rule["indices"]
        if not isinstance(indices, list) or not 1 <= len(indices) <= 4096 or any(type(i) is not int or not 0 <= i < len(text) for i in indices):
            raise ValueError("rule indices must address the input")
        output = "".join(text[i] for i in indices)
        grouped[output].append({**rule, "rule_sha256": _digest(rule), "input_sha256": sha256(text.encode()).hexdigest(),
                                "mapping": [{"output_position": j, "input_position": i, "symbol": text[i]} for j, i in enumerate(indices)]})
    return {"outputs": [{"text": output, "witnesses": aliases} for output, aliases in sorted(grouped.items())],
            "work": {"raw_rules": len(rules), "distinct_output_evaluations": len(grouped), "character_gathers": sum(len(r["indices"]) for r in rules)},
            "interpretation": "Finite caller-specified extraction bank; equal outputs share downstream work but retain distinct rule witnesses."}
