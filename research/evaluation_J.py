"""Frozen document-separated multilingual scoring and small whole-pipeline controls.

Two training authors and one held-out author per language. No K4 target search,
corpus selection, threshold tuning, or download takes place during this run.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import random
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CRIBS
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.layer_plan import compile_layer_plan
from kryptos.sculpture import fixed_routes
from research.layer_constraints import apply_layers
from research.multilingual_pilot import corpus_body

LANGUAGES = ("english", "spanish", "french", "italian", "latin")
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CIPHER_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
SEED = 20261013
ORDER, ALPHA = 3, 0.1
SKIP, TRAIN_LENGTH = 5000, 50000
WINDOW_LENGTH, WINDOWS, STRIDE, SHUFFLES = 97, 20, 1000, 8
PIPELINE_POSITIVES_PER_LANGUAGE = 2
PIPELINE_PERIOD_MAX = 4
PIPELINE_MAX_DIMENSION = 0
PIPELINE_CANDIDATE_CAP = 768
CORPUS_MANIFEST = ROOT / "research/evaluation_corpora_J.json"
CODE_PATHS = (
    "research/evaluation_J.py", "research/evaluation_corpora_J.json", "kryptos/language.py",
    "kryptos/data.py", "kryptos/layer_plan.py", "kryptos/sculpture.py", "research/sculpture_layout.json",
    "research/layer_constraints.py", "research/multilingual_pilot.py",
    "research/source_snapshots/sculpture-J/dunin_transcript.html.txt",
    "research/source_snapshots/sculpture-J/cia_sculpture.html.txt",
    "research/source_snapshots/evaluation-J/retrievals.json",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return sha256(value.encode("utf-8")).hexdigest()


def input_paths():
    books = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))["books"]
    return tuple(CODE_PATHS) + tuple(path for book in books for path in (book["path"], book["metadata_path"]))


def file_hashes(paths):
    return {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}


def mask_positions():
    mask = tuple(sorted({c["start"] - 1 + i for c in K4_CRIBS for i in range(len(c["text"]))}))
    if mask != tuple(range(21, 34)) + tuple(range(63, 74)):
        raise ValueError("The fixed 24-position mask changed")
    return mask


def prepare_corpora():
    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))
    if manifest["schema"] != "kryptos.document-separated-corpora.v1":
        raise ValueError("Unsupported corpus manifest")
    books, groups = manifest["books"], {}
    if len(books) != 15 or len({b["gutenberg_id"] for b in books}) != 15 or len({b["sha256"] for b in books}) != 15:
        raise ValueError("Exactly fifteen distinct source books are required")
    for language in LANGUAGES:
        selected = [b for b in books if b["language"] == language]
        training = [b for b in selected if b["role"] == "training"]
        validation = [b for b in selected if b["role"] == "validation"]
        if len(training) != 2 or len(validation) != 1 or len({b["author"] for b in selected}) != 3:
            raise ValueError("Each language requires two training authors and a separate validation author")
        documents, coverage, heldout = [], [], None
        for book in selected:
            raw = (ROOT / book["path"]).read_bytes()
            metadata = (ROOT / book["metadata_path"]).read_bytes()
            if (sha256(raw).hexdigest() != book["sha256"] or sha256(metadata).hexdigest() != book["metadata_sha256"]
                    or book["source_rights_statement"] != "Public domain in the USA."):
                raise ValueError("A retained source or its verified metadata changed")
            normalized, provenance = corpus_body(raw)
            if provenance != book["preprocessing"] or len(normalized) != book["normalized_letters"]:
                raise ValueError("Corpus normalization differs from frozen source manifest")
            if book["role"] == "training":
                excerpt = normalized[SKIP:SKIP + TRAIN_LENGTH]
                if len(excerpt) != TRAIN_LENGTH:
                    raise ValueError("Insufficient fixed training span")
                documents.append(CorpusDocument(excerpt, book["source_url"] + f"#normalized-{SKIP}-{SKIP + TRAIN_LENGTH}",
                                                book["retention_note"]))
                coverage.append({"gutenberg_id": book["gutenberg_id"], "author": book["author"],
                                 "normalized_span_half_open": [SKIP, SKIP + TRAIN_LENGTH],
                                 "letters": len(excerpt), "sha256": digest(excerpt)})
            else:
                samples = [normalized[SKIP + STRIDE * i:SKIP + STRIDE * i + WINDOW_LENGTH] for i in range(WINDOWS)]
                if any(len(sample) != WINDOW_LENGTH for sample in samples) or len(set(samples)) != WINDOWS:
                    raise ValueError("Invalid held-out sample spans")
                if any(sample in document.text for sample in samples for document in documents):
                    raise ValueError("A complete held-out sample duplicates training text")
                heldout = {"book": book, "samples": samples}
        # Recheck after both training documents are known, independently of input order.
        if any(sample in document.text for sample in heldout["samples"] for document in documents):
            raise ValueError("A complete held-out sample duplicates training text")
        groups[language] = {"documents": documents, "training_coverage": coverage, "heldout": heldout}
    return manifest, groups


def shuffle_unmasked(text, mask, seed):
    result = list(text)
    positions = [i for i in range(len(text)) if i not in mask]
    symbols = [text[i] for i in positions]
    random.Random(seed).shuffle(symbols)
    for i, symbol in zip(positions, symbols):
        result[i] = symbol
    return "".join(result)


def model_scores(models, text, mask):
    scores = {}
    for language, model in models.items():
        score = model.score(text, mask)
        if score.windows != 67 or score.mean_log_probability is None or not math.isfinite(score.mean_log_probability):
            raise AssertionError("All samples must supply the same 67 unmasked trigram windows")
        scores[language] = score.mean_log_probability
    return scores


def selected_score(scores):
    winner = min(scores, key=lambda key: (-scores[key], key))
    return winner, scores[winner]


def score_controls(models, groups, mask):
    records, summaries = [], []
    for language_index, language in enumerate(LANGUAGES):
        wins = ties = selected_wins = selected_ties = classified = 0
        confusion = Counter()
        for index, text in enumerate(groups[language]["heldout"]["samples"]):
            positive = model_scores(models, text, mask)
            winner, best = selected_score(positive)
            confusion[winner] += 1
            classified += winner == language
            controls = []
            for repeat in range(SHUFFLES):
                seed = SEED + language_index * 10000 + index * SHUFFLES + repeat
                control = shuffle_unmasked(text, mask, seed)
                if control == text or Counter(control) != Counter(text) or any(control[i] != text[i] for i in mask):
                    raise AssertionError("Matched score control unexpectedly duplicates or changes its prescribed inventory/mask")
                values = model_scores(models, control, mask)
                control_winner, control_best = selected_score(values)
                wins += positive[language] > values[language]
                ties += positive[language] == values[language]
                selected_wins += best > control_best
                selected_ties += best == control_best
                controls.append({"seed": seed, "text_sha256": digest(control), "scores": values,
                                 "selected_language": control_winner, "selected_score": control_best})
            records.append({"language": language, "sample_index": index,
                            "source_url": groups[language]["heldout"]["book"]["source_url"],
                            "normalized_span_half_open": [SKIP + STRIDE * index, SKIP + STRIDE * index + WINDOW_LENGTH],
                            "positive_sha256": digest(text), "scores": positive, "selected_language": winner,
                            "selected_score": best, "controls": controls})
        summaries.append({"language": language, "training_books": 2, "validation_books": 1,
                          "heldout_windows": WINDOWS, "paired_shuffle_comparisons": WINDOWS * SHUFFLES,
                          "same_language_positive_strict_wins": wins, "same_language_ties": ties,
                          "selected_across_five_models_positive_strict_wins": selected_wins,
                          "selected_across_five_models_ties": selected_ties,
                          "language_label_correct_windows": classified, "language_label_confusion": dict(confusion)})
    return {"summary": summaries, "records": records}


def compile_bank(mask):
    routes = fixed_routes("K4")
    bank = []
    for route_index, route in enumerate(routes):
        for order in ("SST", "STS", "TSS"):
            for a in range(1, PIPELINE_PERIOD_MAX + 1):
                for b in range(1, PIPELINE_PERIOD_MAX + 1):
                    plan = compile_layer_plan(WINDOW_LENGTH, mask, order, route["permutation"], a, b)
                    bank.append(({"route_index": route_index, "order": order, "period_a": a, "period_b": b}, plan))
    if len(bank) > PIPELINE_CANDIDATE_CAP:
        raise AssertionError("Fixed model bank exceeds the declared completion cap")
    return routes, bank


def run_pipeline(ciphertext, known, bank, models):
    """Same full selection procedure for positives/nulls; no unknown truth/key input."""
    candidates, feasible = {}, []
    contradicted = reencrypted = higher_dimension = 0
    for metadata, plan in bank:
        solved = plan.solve(ciphertext, known, CIPHER_ALPHABET)
        if not solved["feasible"]:
            contradicted += 1
            continue
        feasible.append({**metadata, "plaintext_dimension": plan.plaintext_dimension})
        if plan.plaintext_dimension > PIPELINE_MAX_DIMENSION:
            higher_dimension += 1
            continue
        solution = solved["solution"]
        plaintext, keys = solution.plaintext(()), solution.keys(())
        if apply_layers(plaintext, *keys, CIPHER_ALPHABET, metadata["order"], plan.permutation) != ciphertext:
            raise AssertionError("Whole-pipeline candidate re-encryption failed")
        if any(plaintext[i] != ch for i, ch in known.items()):
            raise AssertionError("Whole-pipeline candidate violates a supplied letter")
        reencrypted += 1
        if plaintext in candidates:
            candidates[plaintext]["model_multiplicity"] += 1
            continue
        values = model_scores(models, plaintext, known)
        winner, best = selected_score(values)
        candidates[plaintext] = {"plaintext": plaintext, "scores": values, "selected_language": winner,
                                 "selected_score": best, "model_multiplicity": 1,
                                 "representative_model": {**metadata, "key_a": keys[0], "key_b": keys[1]}}
    ranked = sorted(candidates.values(), key=lambda c: (-c["selected_score"], c["plaintext"]))
    return {"status": "complete-within-declared-zero-dimension-subset", "parameter_combinations": len(bank),
            "contradicted_models": contradicted, "feasible_models": feasible,
            "excluded_higher_dimension_models": higher_dimension, "literal_reencryptions": reencrypted,
            "distinct_completed_plaintexts": len(ranked), "ranked_candidates": ranked,
            "selected_score": ranked[0]["selected_score"] if ranked else None}


def pipeline_controls(models, groups, mask):
    routes, bank = compile_bank(mask)
    cases = []
    for language_index, language in enumerate(LANGUAGES):
        for sample_index in range(PIPELINE_POSITIVES_PER_LANGUAGE):
            case_index = len(cases)
            plaintext = groups[language]["heldout"]["samples"][sample_index]
            route_index = case_index % len(routes)
            order = ("SST", "STS", "TSS")[case_index % 3]
            key_a = "".join(CIPHER_ALPHABET[(case_index * 3 + v) % 26] for v in (0, 7, 13))
            key_b = "".join(CIPHER_ALPHABET[(case_index * 5 + v) % 26] for v in (3, 11))
            ciphertext = apply_layers(plaintext, key_a, key_b, CIPHER_ALPHABET, order, routes[route_index]["permutation"])
            known = {i: plaintext[i] for i in mask}
            seed = SEED + 100000 + case_index
            shuffled = list(ciphertext)
            random.Random(seed).shuffle(shuffled)
            null_ciphertext = "".join(shuffled)
            if null_ciphertext == ciphertext or Counter(null_ciphertext) != Counter(ciphertext):
                raise AssertionError("Invalid matched ciphertext control")
            positive = run_pipeline(ciphertext, known, bank, models)
            null = run_pipeline(null_ciphertext, known, bank, models)
            ranked = positive["ranked_candidates"]
            truth = next(((i, r) for i, r in enumerate(ranked) if r["plaintext"] == plaintext), None)
            if truth is None:
                raise AssertionError("The selected planted zero-dimension model was not recovered")
            index, record = truth
            cases.append({"case_index": case_index, "source_language": language, "sample_index": sample_index,
                          "fixture": {"plaintext": plaintext, "ciphertext": ciphertext, "route_index": route_index,
                                      "order": order, "periods": [3, 2], "keys": [key_a, key_b]},
                          "known_zero_based": [[i, ch] for i, ch in known.items()],
                          "null_ciphertext": null_ciphertext, "null_seed": seed,
                          "positive": positive, "null": null,
                          "assessment": {"true_plaintext_lexical_tiebreak_rank": index + 1,
                                         "true_plaintext_competition_rank": 1 + sum(r["selected_score"] > record["selected_score"] for r in ranked),
                                         "true_score_ties": sum(r["selected_score"] == record["selected_score"] for r in ranked),
                                         "null_has_completed_candidate": bool(null["ranked_candidates"]),
                                         "null_selected_score_at_least_positive_selected_score":
                                             null["selected_score"] is not None and null["selected_score"] >= positive["selected_score"]}})
    return {"model_bank": {"distinct_routes": len(routes), "routes": [{"permutation": r["permutation"], "aliases": r["aliases"]} for r in routes],
                           "orders": ["SST", "STS", "TSS"], "period_range": [1, PIPELINE_PERIOD_MAX],
                           "parameter_combinations_per_input": len(bank), "maximum_plaintext_dimension": PIPELINE_MAX_DIMENSION,
                           "maximum_raw_completions_per_input": PIPELINE_CANDIDATE_CAP},
            "summary": {"positive_inputs": len(cases), "matched_null_inputs": len(cases),
                        "exact_plaintext_recovered": len(cases),
                        "true_plaintext_rank_one": sum(c["assessment"]["true_plaintext_competition_rank"] == 1 for c in cases),
                        "null_inputs_with_completed_candidates": sum(c["assessment"]["null_has_completed_candidate"] for c in cases),
                        "null_selected_score_at_least_positive_selected_score": sum(c["assessment"]["null_selected_score_at_least_positive_selected_score"] for c in cases)},
            "cases": cases}


def self_test():
    mask = mask_positions()
    text = (ALPHABET * 4)[:97]
    shuffled = shuffle_unmasked(text, mask, SEED)
    assert Counter(text) == Counter(shuffled) and all(text[i] == shuffled[i] for i in mask) and text != shuffled
    model = train_ngram_model([CorpusDocument("ABCDE", "tiny/train/a"), CorpusDocument("FGHIJ", "tiny/train/b")],
                              label="tiny", order=3, alpha=0.1, normalization="identity")
    assert dict(model.counts) == {"ABC": 1, "BCD": 1, "CDE": 1, "FGH": 1, "GHI": 1, "HIJ": 1}
    known = {i: text[i] for i in mask}
    cipher = apply_layers(text, "KRY", "PT", CIPHER_ALPHABET, "SST", list(range(97)))
    plan = compile_layer_plan(97, known, "SST", range(97), 3, 2)
    metadata = {"route_index": 0, "order": "SST", "period_a": 3, "period_b": 2}
    result = run_pipeline(cipher, known, [(metadata, plan)], {"tiny": model})
    assert result["ranked_candidates"][0]["plaintext"] == text and result["literal_reencryptions"] == 1
    return {"independent_document_boundary_counts": True, "matched_inventory_and_mask": True,
            "tiny_complete_pipeline_known_answer": True, "full_evaluation_performed": False}


def prepare_evaluation():
    started, paths = perf_counter(), input_paths()
    before = file_hashes(paths)
    self_test()
    manifest, groups = prepare_corpora()
    mask, models, model_files, coverage = mask_positions(), {}, {}, []
    for language in LANGUAGES:
        model = train_ngram_model(groups[language]["documents"], label=f"{language}: two-author checkpoint J",
                                  order=ORDER, alpha=ALPHA, alphabet=ALPHABET, normalization="identity")
        if len(model.corpora) != 2 or sum(model.counts.values()) != 2 * (TRAIN_LENGTH - ORDER + 1):
            raise AssertionError("Training crosses a document boundary or misses the fixed coverage")
        models[language] = model
        filename = language + "-two-author-trigram.json"
        model_files[filename] = model.to_json() + "\n"
        coverage.append({"language": language, "model_file": filename, "model_id": model.model_id,
                         "training_coverage": groups[language]["training_coverage"],
                         "training_letters": 100000, "training_windows": sum(model.counts.values()),
                         "counts_settings_sha256": digest(canonical({"counts": dict(model.counts), "order": ORDER, "alpha": ALPHA})),
                         "validation_source": groups[language]["heldout"]["book"]})
    diagnostics = score_controls(models, groups, mask)
    pipeline = pipeline_controls(models, groups, mask)
    after = file_hashes(paths)
    if before != after:
        raise RuntimeError("An input changed during evaluation; no result is written")
    result = {"experiment": "document-separated-multilingual-and-pipeline-controls-J", "python_version": platform.python_version(),
              "settings": {"languages": list(LANGUAGES), "training_books_per_language": 2, "validation_books_per_language": 1,
                           "normalization": "Gutenberg body; NFKD; combining marks removed; uppercase ASCII A-Z only; spaces removed",
                           "training_span_per_book": [SKIP, SKIP + TRAIN_LENGTH], "order": ORDER, "alpha": ALPHA,
                           "heldout_windows_per_language": WINDOWS, "window_length": WINDOW_LENGTH, "window_stride": STRIDE,
                           "first_heldout_offset": SKIP, "shuffle_replicates_per_window": SHUFFLES, "seed": SEED,
                           "excluded_positions_zero_based": list(mask), "scored_positions_per_sample": 73,
                           "trigram_windows_per_sample": 67},
              "corpus_manifest": manifest, "language_coverage": coverage, "score_controls": diagnostics,
              "whole_pipeline_controls": pipeline, "inputs_unchanged": True,
              "inputs": [{"path": p, "sha256_before": before[p], "sha256_after": after[p]} for p in paths],
              "runtime_seconds": perf_counter() - started,
              "non_claims": ["Two training authors and one validation author per language remain a narrow historical-literature sample.",
                             "Source catalog language labels do not certify every passage; fixed normalization can retain prefaces or editorial material.",
                             "Control win counts, language classifications and score ranks are empirical diagnostics, not calibrated probabilities.",
                             "Maximizing across five models is repeated for controls; this covers that selection, not every prior hypothesis tried.",
                             "Whole-pipeline positives/nulls repeat the same bounded route/order/period search; dimensions above zero are explicitly excluded.",
                             "Pipeline results do not validate arbitrary keyed alphabets, column orders, fractionation, semantic searches, or bigger key periods.",
                             "The positive generating family is included in the bank; recovery does not receive truth keys, route, order or periods.",
                             "No K4 target score or cipher search, K5 identification, external submission, or original-model modification occurs."]}
    model_files["results.json"] = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    return result, model_files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.output is not None:
            parser.error("--self-test does not produce the full evaluation")
        print(json.dumps(self_test(), indent=2))
        return
    if args.output is None:
        parser.error("--output requires a fresh output directory")
    if args.output.exists():
        raise FileExistsError("Use a fresh output directory")
    result, files = prepare_evaluation()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (args.output / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    print(json.dumps({"models": len(LANGUAGES), "heldout_windows": len(LANGUAGES) * WINDOWS,
                      "score_controls": len(LANGUAGES) * WINDOWS * SHUFFLES,
                      "pipeline": result["whole_pipeline_controls"]["summary"],
                      "runtime_seconds": result["runtime_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
