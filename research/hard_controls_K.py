"""Frozen crib-compatible nulls with 17,576 complete alternatives per input.

Method-known, single-model exhaustive recovery. Existing checkpoint-J language
models stay unchanged. No K4 target is searched or scored, and no result tunes
this protocol. Nulls preserve every supplied letter and plaintext inventory.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
from itertools import islice
import json
import math
from pathlib import Path
import platform
import random
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.language import CharacterNgramModel
from kryptos.layer_plan import compile_layer_plan
from research.multilingual_pilot import corpus_body

LANGUAGES = ("english", "spanish", "french", "italian", "latin")
ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MASK = tuple(range(21, 34)) + tuple(range(63, 74))
GRAM_STARTS = tuple(i for i in range(95) if not set(range(i, i + 3)).intersection(MASK))
SEED = 2026101306
OFFSET, LENGTH, DIMENSION, CANDIDATES = 50000, 97, 3, 17576
PERIODS = (3, 14)
MODEL_DIRECTORY = "research/runs/evaluation-J-001/artifacts"
MANIFEST = "research/evaluation_corpora_J.json"
CODE_PATHS = ("research/hard_controls_K.py", "kryptos/language.py", "kryptos/layer_plan.py", "kryptos/data.py",
              "research/multilingual_pilot.py", MANIFEST)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(text):
    return sha256(text.encode("utf-8")).hexdigest()


def input_paths():
    books = json.loads((ROOT / MANIFEST).read_text())["books"]
    heldout = [b for b in books if b["role"] == "validation"]
    return CODE_PATHS + tuple(f"{MODEL_DIRECTORY}/{lang}-two-author-trigram.json" for lang in LANGUAGES) + tuple(
        p for book in heldout for p in (book["path"], book["metadata_path"]))


def hashes():
    return {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in input_paths()}


def load_inputs():
    manifest = json.loads((ROOT / MANIFEST).read_text())
    models, samples, sources = {}, {}, {}
    for language in LANGUAGES:
        model_path = ROOT / MODEL_DIRECTORY / (language + "-two-author-trigram.json")
        model = CharacterNgramModel.from_json(model_path.read_text())
        assert (model.order, model.alpha, model.normalization, model.alphabet) == (3, 0.1, "identity", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert len(model.corpora) == 2 and sum(model.counts.values()) == 99996
        model_source_urls = {c.source.split("#")[0] for c in model.corpora}
        train_urls = {b["source_url"] for b in manifest["books"] if b["language"] == language and b["role"] == "training"}
        assert model_source_urls == train_urls
        book, = [b for b in manifest["books"] if b["language"] == language and b["role"] == "validation"]
        assert book["source_url"] not in train_urls
        raw, metadata = (ROOT / book["path"]).read_bytes(), (ROOT / book["metadata_path"]).read_bytes()
        assert sha256(raw).hexdigest() == book["sha256"] and sha256(metadata).hexdigest() == book["metadata_sha256"]
        normalized, provenance = corpus_body(raw)
        assert provenance == book["preprocessing"]
        text = normalized[OFFSET:OFFSET + LENGTH]
        assert len(text) == LENGTH and set(text) <= set(ALPHABET)
        models[language], samples[language] = model, text
        sources[language] = {"source_url": book["source_url"], "author": book["author"],
                             "normalized_span_half_open": [OFFSET, OFFSET + LENGTH],
                             "text_sha256": digest(text), "model_id": model.model_id,
                             "model_file_sha256": sha256(model_path.read_bytes()).hexdigest()}
    return models, samples, sources


def shuffled_plaintext(text, seed):
    result = list(text)
    positions = [i for i in range(LENGTH) if i not in MASK]
    letters = [text[i] for i in positions]
    random.Random(seed).shuffle(letters)
    for i, c in zip(positions, letters):
        result[i] = c
    value = "".join(result)
    assert value != text and Counter(value) == Counter(text)
    assert all(value[i] == text[i] for i in MASK)
    return value


def literal_encrypt(text, keys):
    """Independent direct SST/identity formula, not the recovery implementation."""
    index = {c: i for i, c in enumerate(ALPHABET)}
    a, b = ([index[c] for c in key] for key in keys)
    return "".join(ALPHABET[(index[c] + a[i % len(a)] + b[i % len(b)]) % 26] for i, c in enumerate(text))


def keys_for_case(index):
    return tuple("".join(ALPHABET[(index * 7 + 5 * phase + phase * phase + offset) % 26]
                         for phase in range(period)) for period, offset in zip(PERIODS, (3, 11)))


def fast_scores(models, text):
    # Same ordered additions/table entries as CharacterNgramModel.score, omitting
    # repeated layout construction. Independent equality is tested below.
    grams = tuple(text[i:i + 3] for i in GRAM_STARTS)
    scores = []
    for model in models.values():
        total = 0.0
        for gram in grams:
            total += model._log_probabilities.get(gram, model._unknown_log_probability)
        scores.append(total / len(grams))
    return tuple(scores)


def score_check(models, text):
    fast = fast_scores(models, text)
    reference = tuple(model.score(text, MASK).mean_log_probability for model in models.values())
    assert fast == reference and len(GRAM_STARTS) == 67 and all(math.isfinite(s) for s in fast)


def complete_records(ciphertext, known, plan, models, limit=None):
    """Recovery receives only C, supplied letters, declared model and score models."""
    solved = plan.solve(ciphertext, known, ALPHABET)
    assert solved["feasible"] and plan.plaintext_dimension == DIMENSION
    solution = solved["solution"]
    assert solution.distinct_plaintext_count == CANDIDATES
    iterator = solution.enumerate_plaintexts(CANDIDATES)
    if limit is not None:
        iterator = islice(iterator, limit)
    stream, records = sha256(), []
    for values, plaintext in iterator:
        keys = solution.keys(values)
        assert literal_encrypt(plaintext, keys) == ciphertext
        assert all(plaintext[i] == c for i, c in known.items())
        scores = fast_scores(models, plaintext)
        stream.update((canonical([list(values), plaintext, list(scores)]) + "\n").encode())
        records.append((plaintext, scores, values))
    assert len({r[0] for r in records}) == len(records)
    if limit is None:
        assert len(records) == CANDIDATES
    return records, stream.hexdigest(), solution


def assess(records, true_plaintext, solution, models, stream_digest):
    truth, = [r for r in records if r[0] == true_plaintext]
    selected = sorted(records, key=lambda r: (-max(r[1]), r[0]))
    selected_score = max(truth[1])
    sensitivity = {}
    for i, language in enumerate(LANGUAGES):
        ranked = sorted(records, key=lambda r: (-r[1][i], r[0]))
        sensitivity[language] = {"truth_score": truth[1][i], "best_score": ranked[0][1][i],
            "truth_competition_rank": 1 + sum(r[1][i] > truth[1][i] for r in records),
            "truth_score_ties": sum(r[1][i] == truth[1][i] for r in records),
            "truth_lexical_tiebreak_rank": next(j + 1 for j, r in enumerate(ranked) if r[0] == true_plaintext),
            "top_plaintext_sha256": digest(ranked[0][0])}
    tops = []
    for text, scores, values in selected[:5]:
        score_check(models, text)
        winner = min(range(len(LANGUAGES)), key=lambda i: (-scores[i], LANGUAGES[i]))
        tops.append({"plaintext": text, "plaintext_sha256": digest(text), "free_residues": list(values),
                     "representative_keys": list(solution.keys(values)),
                     "scores": dict(zip(LANGUAGES, scores)), "selected_language": LANGUAGES[winner],
                     "selected_score": scores[winner]})
    return {"complete": True, "distinct_completed_plaintexts": len(records), "wrong_alternatives": len(records) - 1,
            "literal_reencryptions": len(records), "ordered_family_sha256": stream_digest,
            "family_hash_format": "SHA256 of UTF8 canonical JSON [residues,plaintext,5ordered scores] plus LF in lexicographic residue enumeration",
            "truth_sha256": digest(true_plaintext), "truth_free_residues": list(truth[2]),
            "truth_selected_score": selected_score, "best_selected_score": max(selected[0][1]),
            "truth_competition_rank": 1 + sum(max(r[1]) > selected_score for r in records),
            "truth_score_ties": sum(max(r[1]) == selected_score for r in records),
            "truth_lexical_tiebreak_rank": next(j + 1 for j, r in enumerate(selected) if r[0] == true_plaintext),
            "per_frozen_model": sensitivity, "top_candidates": tops}


def contract():
    return {"languages": list(LANGUAGES), "seed": SEED, "heldout_offset": OFFSET, "length": LENGTH,
            "mask_zero_based": list(MASK), "trigram_windows": len(GRAM_STARTS), "model_bank_size": 1,
            "model": {"order": "SST", "route": "identity", "periods": list(PERIODS), "alphabet": ALPHABET},
            "plaintext_dimension": DIMENSION, "distinct_completions_per_input": CANDIDATES,
            "positive_inputs": 5, "paired_crib_preserving_shuffled_plaintexts": 5,
            "full_reencryptions": 10 * CANDIDATES, "scoring": "frozen J five models, masked67trigrams; max across five; lexical tie break",
            "no_training_no_K4_search": True}


def preflight():
    models, samples, _ = load_inputs()
    plan = compile_layer_plan(LENGTH, MASK, "SST", range(LENGTH), *PERIODS)
    text = samples["english"]
    score_check(models, text)
    score_check(models, shuffled_plaintext(text, SEED))
    cipher = literal_encrypt(text, keys_for_case(0))
    started = perf_counter()
    records, _, _ = complete_records(cipher, {i: text[i] for i in MASK}, plan, models, limit=100)
    seconds = perf_counter() - started
    for candidate in records[:3]:
        score_check(models, candidate[0])
    return {"contract": contract(), "preflight_candidates_only": len(records), "sample_seconds": seconds,
            "linear_candidate_time_estimate_seconds": seconds * 10 * CANDIDATES / len(records),
            "estimate_caveat": "Not a guarantee; excludes final sorting, assessment, source loading and output. Full suite has not run."}


def run():
    started, before = perf_counter(), hashes()
    models, samples, sources = load_inputs()
    plan = compile_layer_plan(LENGTH, MASK, "SST", range(LENGTH), *PERIODS)
    assert plan.plaintext_dimension == DIMENSION
    pairs = []
    for i, language in enumerate(LANGUAGES):
        truth = samples[language]
        null = shuffled_plaintext(truth, SEED + i)
        keys, known = keys_for_case(i), {j: truth[j] for j in MASK}
        pair = {"language": language, "source": sources[language], "null_seed": SEED + i,
                "known_zero_based": [[j, c] for j, c in known.items()], "generating_keys": list(keys)}
        for label, text in (("positive", truth), ("null", null)):
            score_check(models, text)
            ciphertext = literal_encrypt(text, keys)
            records, stream, solution = complete_records(ciphertext, known, plan, models)
            pair[label] = {"generating_plaintext": text, "ciphertext": ciphertext,
                           **assess(records, text, solution, models, stream)}
        positive, null_result = pair["positive"], pair["null"]
        pair["comparison"] = {"null_best_minus_positive_best": null_result["best_selected_score"] - positive["best_selected_score"],
            "null_best_at_least_positive_best": null_result["best_selected_score"] >= positive["best_selected_score"],
            "null_best_at_least_actual_positive_score": null_result["best_selected_score"] >= positive["truth_selected_score"],
            "per_model_null_best_minus_positive_best": {lang: null_result["per_frozen_model"][lang]["best_score"] - positive["per_frozen_model"][lang]["best_score"] for lang in LANGUAGES}}
        pairs.append(pair)
    after = hashes()
    if before != after:
        raise RuntimeError("A frozen input changed; no result is written")
    return {"schema": "kryptos.surviving-null-controls.v1", "python": platform.python_version(), "contract": contract(),
            "pairs": pairs, "summary": {"inputs": 10, "all_inputs_completed": True,
                "total_literal_reencryptions": 10 * CANDIDATES,
                "positive_rank_one": sum(p["positive"]["truth_competition_rank"] == 1 for p in pairs),
                "null_generating_plaintext_rank_one": sum(p["null"]["truth_competition_rank"] == 1 for p in pairs),
                "null_best_at_least_positive_best": sum(p["comparison"]["null_best_at_least_positive_best"] for p in pairs)},
            "input_sha256_before": before, "input_sha256_after": after, "elapsed_seconds": perf_counter() - started,
            "nonclaims": ["Method-known, one-family conditional experiment; route/order/periods are supplied equally for every input.",
                          "Five historical-literature windows and their shuffles are artificial controls, not a real false-positive probability.",
                          "Masking removes supplied positions and crossing trigrams; other alphabetic structure can remain forced by the declared cipher.",
                          "No thresholds, corpus settings, keys, masks or hypotheses are tuned after observing scores.",
                          "Ranks/ties use the unchanged floating point score convention, not exact probability products.",
                          "No K4 or K5 target score/search or external submission occurs."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    if args.preflight:
        if args.output:
            parser.error("Preflight cannot write the full result")
        print(json.dumps(preflight(), indent=2))
    else:
        if args.output is None:
            parser.error("--output requires a fresh result file")
        if args.output.exists():
            raise FileExistsError("Use a fresh result path")
        result = run()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"summary": result["summary"], "elapsed_seconds": result["elapsed_seconds"]}))
