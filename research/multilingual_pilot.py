"""One bounded explicit-corpus pilot; never infer a K4 language or K5 text.

Reads retained, authorized Gutenberg files and existing complete K4 strings.
No downloads, key/route search, corpus selection, or cross-model score sorting.
Run once into a NEW output directory. Only the standard library is required.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import statistics
import sys
import time
import unicodedata


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.language import ALPHABET, CorpusDocument, calibrate_controls, train_ngram_model


BOOKS = (
    (1342, "english", "Pride and Prejudice", "Jane Austen",
     "3f6bb9d6f78e0293b56acd4714dd68cb7d6d1d293402031ce9d5a216bcaf9d75"),
    (2000, "spanish", "Don Quijote", "Miguel de Cervantes Saavedra",
     "534f41d59f7142163fa0964076ac6351845c006ea6433778be637fac6d5b04d7"),
    (17489, "french", "Les misérables Tome I: Fantine", "Victor Hugo",
     "a5de514ba7b9f2e1790e7e259c4e8b7a35ae1d29e4bf9a5f8767039c58b80503"),
    (52484, "italian", "Le avventure di Pinocchio: Storia di un burattino", "Carlo Collodi",
     "b51a398da257709bfd2c0007e42980935751276cdca4178d738fa4c92f799ae6"),
    (218, "latin", "C. Iuli Caesaris De Bello Gallico, I-IV", "Julius Caesar",
     "84ac8411841a4d8f5f4a49b6a2cd1f466917c6a5af72916d5e0b2b1ecb2f659c"),
)
SKIP = 5_000
TRAIN_LENGTH = 50_000
GAP = 1_000
WINDOW_LENGTH = 97
HOLDOUT_COUNT = 20
SHUFFLES_PER_WINDOW = 8
SEED = 20261012
ORDER = 3
ALPHA = 0.1
PRIOR_RESULTS = ROOT / "research/runs/complete-predictions-001/results.json"
LICENSE = "Project Gutenberg license retained in source; USA public-domain status verified by parent task"


def sha256(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def encode(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def input_hashes(paths):
    return {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()) for path in paths}


def corpus_body(raw: bytes):
    """Exact marker delimitation; fixed text normalization, no editorial choices."""
    text = raw.decode("utf-8-sig")
    marker = r"^\*\*\* %s OF (?:THE|THIS) PROJECT GUTENBERG EBOOK .*\*\*\*\s*$"
    starts = list(re.finditer(marker % "START", text, re.M))
    ends = list(re.finditer(marker % "END", text, re.M))
    if len(starts) != 1 or len(ends) != 1 or starts[0].end() >= ends[0].start():
        raise ValueError("expected exactly one ordered Gutenberg START/END marker pair")
    body = text[starts[0].end():ends[0].start()]
    decomposed = unicodedata.normalize("NFKD", body)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c)).upper()
    removed_letters = Counter(c for c in stripped if c.isalpha() and c not in ALPHABET)
    normalized = "".join(c for c in stripped if c in ALPHABET)
    provenance = {
        "decoded_body_span_zero_based_half_open": [starts[0].end(), ends[0].start()],
        "start_marker": starts[0].group().strip(), "end_marker": ends[0].group().strip(),
        "body_characters": len(body), "body_sha256_utf8": sha256(body),
        "normalized_letters": len(normalized), "normalized_body_sha256": sha256(normalized),
        "non_ascii_letters_dropped_after_nfkd_uppercase": dict(sorted(removed_letters.items())),
    }
    return normalized, provenance


def canonical_candidates():
    prior = json.loads(PRIOR_RESULTS.read_bytes())
    mask = tuple(sorted({crib["start"] - 1 + offset for crib in K4_CRIBS
                         for offset in range(len(crib["text"]))}))
    known = {crib["start"] - 1 + offset: char for crib in K4_CRIBS
             for offset, char in enumerate(crib["text"])}
    if len(K4_CIPHERTEXT) != WINDOW_LENGTH or len(mask) != 24:
        raise ValueError("canonical K4 length/mask changed")
    if tuple(i - 1 for i in prior["excluded_positions_one_based"]) != mask:
        raise ValueError("prior candidate mask differs from canonical K4")
    records = prior["ranked_plaintexts"]
    if len(records) != 46 or prior["distinct_plaintexts"] != 46:
        raise ValueError("expected the 46 previously inspected complete strings")
    texts = [record["plaintext"] for record in records]
    if len(set(texts)) != 46:
        raise ValueError("prior candidates are not distinct")
    for text in texts:
        if (len(text) != WINDOW_LENGTH or any(c not in ALPHABET for c in text)
                or any(text[i] != c for i, c in known.items())):
            raise ValueError("prior complete string has invalid length/symbols/cribs")
    return records, mask


def shuffled_controls(windows, mask, identifier):
    eligible = tuple(i for i in range(WINDOW_LENGTH) if i not in mask)
    controls, paired_indices = [], []
    for window_index, text in enumerate(windows):
        indices = []
        for shuffle_index in range(SHUFFLES_PER_WINDOW):
            seed = SEED + window_index * SHUFFLES_PER_WINDOW + shuffle_index
            letters = [text[i] for i in eligible]
            random.Random(seed).shuffle(letters)
            shuffled = list(text)
            for position, letter in zip(eligible, letters):
                shuffled[position] = letter
            shuffled = "".join(shuffled)
            if shuffled == text:
                raise ValueError("control unexpectedly equals its positive; do not silently resample")
            indices.append(len(controls))
            controls.append(CorpusDocument(
                shuffled, f"gutenberg/{identifier}/heldout/{window_index}/shuffle/{shuffle_index}/seed/{seed}",
                LICENSE))
        paired_indices.append(indices)
    return controls, paired_indices


def prepare_pilot():
    started = time.perf_counter()
    paths = [Path(__file__), ROOT / "kryptos/language.py", ROOT / "kryptos/data.py", PRIOR_RESULTS]
    paths += [ROOT / f"research/corpora/pg{identifier}.txt" for identifier, *_ in BOOKS]
    before = input_hashes(paths)
    candidates, mask = canonical_candidates()
    # Preflight every corpus before training any model or writing any output.
    corpora = []
    for identifier, language, title, author, expected_hash in BOOKS:
        source = ROOT / f"research/corpora/pg{identifier}.txt"
        raw = source.read_bytes()
        if sha256(raw) != expected_hash:
            raise ValueError(f"authorized corpus snapshot changed: {source}")
        normalized, provenance = corpus_body(raw)
        stop = SKIP + TRAIN_LENGTH + GAP + WINDOW_LENGTH * HOLDOUT_COUNT
        if len(normalized) < stop:
            raise ValueError(f"pg{identifier} has insufficient normalized body for fixed splits")
        corpora.append((identifier, language, title, author, expected_hash, normalized, provenance))

    files, languages = {}, []
    for identifier, language, title, author, raw_hash, normalized, provenance in corpora:
        url = f"https://www.gutenberg.org/ebooks/{identifier}"
        training = normalized[SKIP:SKIP + TRAIN_LENGTH]
        holdout_start = SKIP + TRAIN_LENGTH + GAP
        windows = [normalized[holdout_start + i * WINDOW_LENGTH:holdout_start + (i + 1) * WINDOW_LENGTH]
                   for i in range(HOLDOUT_COUNT)]
        model = train_ngram_model(
            [CorpusDocument(training, f"{url}#normalized-body-{SKIP}-{SKIP + TRAIN_LENGTH}", LICENSE)],
            label=f"{language}: single-book Gutenberg {identifier} pilot", order=ORDER,
            alpha=ALPHA, alphabet=ALPHABET, normalization="identity")
        filename = f"pg{identifier}-{language}-trigram.json"
        files[filename] = model.to_json() + "\n"
        controls, paired = shuffled_controls(windows, mask, identifier)
        calibration = calibrate_controls(
            model, controls, excluded_positions=mask,
            description="160 seeded within-window shuffles of eligible letters from 20 later 97-letter windows; fixed K4 mask; not independent search controls")
        heldout, wins, ties, deltas = [], 0, 0, []
        for i, text in enumerate(windows):
            score = model.score(text, mask)
            assessment = calibration.assess(model, text, mask)
            if assessment.exact_training_duplicate or assessment.exact_control_duplicate:
                raise ValueError("positive unexpectedly duplicates training/control text")
            paired_scores = [calibration.scores[j] for j in paired[i]]
            wins += sum(score.mean_log_probability > s for s in paired_scores)
            ties += sum(score.mean_log_probability == s for s in paired_scores)
            delta = score.mean_log_probability - statistics.mean(paired_scores)
            deltas.append(delta)
            heldout.append({
                "window_index": i, "normalized_body_span_zero_based_half_open":
                    [holdout_start + i * WINDOW_LENGTH, holdout_start + (i + 1) * WINDOW_LENGTH],
                "text_sha256": sha256(text), "score": score.to_dict(),
                "paired_control_indices": paired[i], "paired_control_scores": paired_scores,
                "score_minus_paired_shuffle_mean": delta, "assessment": assessment.to_dict(),
            })
        ranked = []
        for input_index, prior in enumerate(candidates):
            text = prior["plaintext"]
            assessment = calibration.assess(model, text, mask)
            ranked.append({
                "prior_record_index_zero_based": input_index, "plaintext": text,
                "plaintext_sha256": sha256(text), "generating_model_count": prior["model_count"],
                "unknown_only_mask": "".join("." if i in mask else c for i, c in enumerate(text)),
                "assessment_against_this_book_shuffle_controls": assessment.to_dict(),
            })
        ranked.sort(key=lambda item: (-item["assessment_against_this_book_shuffle_controls"]["score"]["mean_log_probability"], item["plaintext"]))
        for rank, item in enumerate(ranked, 1):
            item["rank_within_this_model"] = rank
        languages.append({
            "language_label": language, "gutenberg_id": identifier, "title": title, "author": author,
            "source_url": url, "retained_source_path": f"research/corpora/pg{identifier}.txt",
            "retained_source_sha256": raw_hash, "preprocessing": provenance,
            "training_span_zero_based_half_open": [SKIP, SKIP + TRAIN_LENGTH],
            "training_sha256": sha256(training), "training_windows": sum(model.counts.values()),
            "model_file": filename, "model_id": model.model_id,
            "model_file_sha256": sha256(files[filename]), "calibration": calibration.to_dict(),
            "heldout_windows": heldout,
            "heldout_diagnostic": {
                "paired_comparisons": HOLDOUT_COUNT * SHUFFLES_PER_WINDOW,
                "positive_strictly_exceeds_paired_shuffle": wins, "ties": ties,
                "strict_win_fraction": wins / (HOLDOUT_COUNT * SHUFFLES_PER_WINDOW),
                "mean_positive_minus_paired_shuffle_mean": statistics.mean(deltas),
                "positive_windows_above_paired_shuffle_mean": sum(d > 0 for d in deltas),
            },
            "existing_candidates_ranked_only_within_this_model": ranked,
        })
    after = input_hashes(paths)
    if before != after:
        raise ValueError("an input changed during the pilot; refusing to save output")
    result = {
        "schema": "kryptos.multilingual-pilot.v1", "base_checkpoint": "K4-20261012-H",
        "created_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "unicode_version": unicodedata.unidata_version, "input_hashes_before": before,
        "input_hashes_after": after, "inputs_unchanged": True,
        "settings": {"normalization": "Gutenberg START/END body; NFKD; remove combining marks; uppercase; retain ASCII A-Z only; no spaces",
                     "initial_normalized_letters_skipped": SKIP, "training_letters": TRAIN_LENGTH,
                     "train_holdout_gap": GAP, "holdout_windows": HOLDOUT_COUNT,
                     "window_length": WINDOW_LENGTH, "shuffles_per_window": SHUFFLES_PER_WINDOW,
                     "shuffle_base_seed": SEED, "order": ORDER, "alpha": ALPHA,
                     "excluded_positions_zero_based": mask, "eligible_letters_per_sample": 73,
                     "complete_trigram_windows_per_sample": 67},
        "scope": "Five fixed single-book models and the same 46 previously completed K4 strings; no new cipher search",
        "non_claims": [
            "One source per language and a short later block do not constitute a generic language classifier.",
            "Fixed skip and marker removal retain internal contents, introductions, notes and editorial material.",
            "Removed spaces/diacritics are an explicit ciphertext-oriented preprocessing assumption.",
            "Raw scores and standardized scores are not used to select or declare a K4 language.",
            "Book-derived shuffles are score diagnostics, not controls for the complete cipher/semantic selection procedure.",
            "Candidate scores against book-derived controls also reflect differing character inventories; they are not language confidence.",
            "Neither ranking nor a favorable score authenticates a decipherment or identifies K5.",
        ],
        "languages": languages, "runtime_seconds": time.perf_counter() - started,
    }
    files["results.json"] = encode(result)
    files["provenance.json"] = encode({
        "schema": "kryptos.multilingual-pilot-provenance.v1", "input_hashes": before,
        "output_hashes": {name: sha256(content) for name, content in files.items()},
        "source_urls": [f"https://www.gutenberg.org/ebooks/{book[0]}" for book in BOOKS],
        "license_note": LICENSE, "inputs_unchanged": True,
    })
    return files, result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "research/models/multilingual-001",
                        help="NEW directory under research/models; existing paths are refused")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    allowed = (ROOT / "research/models").resolve()
    try:
        if output == allowed or not output.is_relative_to(allowed):
            raise ValueError("output must be a new subdirectory under research/models")
        if output.exists():
            raise ValueError("output exists; this fixed pilot must not replace previous evidence")
        files, result = prepare_pilot()
        output.mkdir(parents=True, exist_ok=False)
        for name, content in files.items():
            with (output / name).open("x", encoding="utf-8", newline="\n") as file:
                file.write(content)
        print(encode({"output": str(output), "models": len(BOOKS),
                      "candidates_per_model": 46, "runtime_seconds": result["runtime_seconds"]}), end="")
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
