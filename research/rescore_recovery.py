"""Rescore fixed saved candidate sets with the predeclared English pilot model.

No cipher search or hyperparameter tuning. Preserve every dimension<=1 saved
candidate. Compare recovery ranks and repeat best-candidate selection on the
already materialized K4/control sets. Neither experiment is independent proof.
Exact trained ranks use the saved alpha's IEEE-754 binary64 rational value,
not a reinterpretation of the decimal spelling 0.1 as exactly one tenth.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.language import CharacterNgramModel
from kryptos.scoring import english_score


MATRIX = ROOT / "research/runs/recovery-matrix-001/results.json"
CALIBRATION = ROOT / "research/runs/calibration-002/results.json"
JOURNAL = ROOT / "research/runs/calibration-002/journal.jsonl"
PILOT = ROOT / "research/models/multilingual-001/artifacts"
MODEL = PILOT / "pg1342-english-trigram.json"
ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode("utf-8")).hexdigest()


def hashes(paths):
    return {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in paths}


def strict_json(text):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON field: {key}")
            value[key] = item
        return value

    def bad_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(text, object_pairs_hook=unique, parse_constant=bad_constant)


def read_json(path):
    return strict_json(path.read_bytes())


def valid_permutation(permutation):
    require(isinstance(permutation, list) and len(permutation) == 97
            and all(type(i) is int for i in permutation)
            and sorted(permutation) == list(range(97)), "invalid saved gather permutation")


def literal_encrypt(plaintext, keys, order, permutation):
    """Direct stage replay, independent of the saved graph plan/solution objects."""
    valid_permutation(permutation)
    require(order in ("SST", "STS", "TSS"), "invalid saved stage order")
    require(isinstance(keys, (list, tuple)) and len(keys) == 2
            and all(isinstance(key, str) and key and set(key) <= set(ALPHABET) for key in keys),
            "invalid saved key strings")
    lookup = {char: i for i, char in enumerate(ALPHABET)}
    text, key_number = plaintext, 0
    for stage in order:
        if stage == "T":
            text = "".join(text[i] for i in permutation)
        else:
            key = keys[key_number]
            key_number += 1
            text = "".join(ALPHABET[(lookup[char] + lookup[key[i % len(key)]]) % 26]
                           for i, char in enumerate(text))
    return text


def validate_plaintext(text, known):
    require(isinstance(text, str) and len(text) == 97 and set(text) <= set(ALPHABET),
            "invalid saved candidate text")
    require(all(text[i] == char for i, char in known.items()), "saved candidate violates cribs")


class FixedScorer:
    def __init__(self, model, known):
        self.model, self.known, self.cache = model, known, {}
        self.alpha_numerator, self.alpha_denominator = model.alpha.as_integer_ratio()
        self.denominator = (sum(model.counts.values()) * self.alpha_denominator
                            + self.alpha_numerator * len(model.alphabet) ** model.order)

    def score(self, text):
        if text in self.cache:
            return self.cache[text]
        validate_plaintext(text, self.known)
        score = self.model.score(text, self.known)
        require(score.available and score.windows == 67 and len(score.eligible_positions) == 73,
                "candidate score does not have the declared common coverage")
        product, windows = 1, 0
        for i in range(len(text) - self.model.order + 1):
            if any(j in self.known for j in range(i, i + self.model.order)):
                continue
            count = self.model.counts.get(text[i:i + self.model.order], 0)
            product *= count * self.alpha_denominator + self.alpha_numerator
            windows += 1
        require(windows == 67, "exact scorer window count differs")
        exact_formula_log = (math.log(product) - windows * math.log(self.denominator)) / windows
        require(math.isclose(score.mean_log_probability, exact_formula_log, rel_tol=0, abs_tol=1e-12),
                "model log score disagrees with its exact smoothed-count formula")
        result = {
            "trained_mean_log_probability": score.mean_log_probability,
            "exact_product_sha256": digest(str(product)), "exact_product_bits": product.bit_length(),
            "exact_training_document_duplicate": digest(text) in {p.sha256 for p in self.model.corpora},
        }
        self.cache[text] = product, result
        return self.cache[text]


def ranking(text_to_score, truth=None):
    ordered = sorted(text_to_score, key=lambda text: (-text_to_score[text], text))
    require(bool(ordered), "empty candidate set cannot be ranked")
    counts = Counter(text_to_score.values())
    ranks, preceding = {}, 0
    for score in sorted(counts, reverse=True):
        ranks[score] = preceding + 1
        preceding += counts[score]
    records = {text: {"competition_rank": ranks[text_to_score[text]],
                      "lexical_tiebreak_rank": i + 1, "score_tie_count": counts[text_to_score[text]]}
               for i, text in enumerate(ordered)}
    summary = {"best_plaintext": ordered[0], "top_score_tie_count": counts[text_to_score[ordered[0]]],
               "candidate_count": len(ordered)}
    if truth is not None:
        require(truth in text_to_score, "saved recovery set no longer includes its truth")
        summary.update(truth=records[truth], truth_is_top_tied=records[truth]["competition_rank"] == 1,
                       truth_is_unique_top=records[truth]["competition_rank"] == 1
                                           and records[truth]["score_tie_count"] == 1,
                       truth_wins_lexical_tiebreak=records[truth]["lexical_tiebreak_rank"] == 1)
    return ordered, records, summary


def compare_set(saved_scores, scorer, truth=None):
    baseline_order, baseline_ranks, baseline = ranking(saved_scores, truth)
    exact = {text: scorer.score(text)[0] for text in saved_scores}
    trained_order, trained_ranks, trained = ranking(exact, truth)
    records = [{"plaintext": text, "baseline_score": saved_scores[text],
                "baseline_rank": baseline_ranks[text], "trained_rank": trained_ranks[text],
                **scorer.score(text)[1]} for text in trained_order]
    return {"baseline": baseline, "trained": trained, "ranked_candidates": records,
            "candidate_membership_sha256": digest(canonical(sorted(saved_scores))),
            "candidate_membership_unchanged": set(baseline_order) == set(trained_order)}, exact[trained_order[0]]


def rescore_matrix(matrix, scorer, known):
    require(matrix["experiment"] == "deterministic-in-family-recovery-matrix", "wrong matrix experiment")
    require(matrix["config"]["maximum_plaintext_dimension"] == 1, "matrix dimension bound changed")
    require(matrix["config"]["alphabet"] == ALPHABET, "matrix alphabet changed")
    require(dict(matrix["config"]["cribs_zero_based"]) == known, "matrix mask changed")
    require(len(matrix["cases"]) == 12, "expected twelve matrix cases")
    require(matrix["resolved_inputs_sha256"] == digest(canonical({
        "config": matrix["config"], "fixtures": [case["fixture"] for case in matrix["cases"]]})),
        "matrix resolved-input hash mismatch")
    routes = {route["id"]: route["permutation"] for route in matrix["config"]["routes"]}
    output, literal_checks = [], 0
    for case in matrix["cases"]:
        fixture, saved = case["fixture"], case["recovery"]
        require(saved["status"] == "complete" and saved["raw_completions_required"] == saved["raw_completions_evaluated"],
                "matrix contains incomplete/budget-limited recovery")
        candidates = saved["ranked_candidates"]
        require(digest(canonical(candidates)) == saved["ranked_candidates_sha256"], "matrix candidate hash mismatch")
        require(len({row["plaintext"] for row in candidates}) == len(candidates) == saved["distinct_plaintexts"],
                "matrix candidate count/uniqueness mismatch")
        scores = {}
        for row in candidates:
            text, representative = row["plaintext"], row["representative_model"]
            validate_plaintext(text, known)
            require(row["score"] == english_score(text, known), "matrix baseline score changed")
            keys = [representative["key_a"], representative["key_b"]]
            require([len(k) for k in keys] == [representative["period_a"], representative["period_b"]],
                    "matrix key periods mismatch")
            require(literal_encrypt(text, keys, representative["order"], routes[representative["route_id"]])
                    == fixture["ciphertext"], "matrix candidate fails literal re-encryption")
            literal_checks += 1
            scores[text] = row["score"]
        result, _ = compare_set(scores, scorer, fixture["plaintext"])
        baseline_truth = result["baseline"]["truth"]
        expected = case["evaluation"]
        for actual, old in (("competition_rank", "true_plaintext_competition_rank"),
                            ("lexical_tiebreak_rank", "true_plaintext_lexical_tiebreak_rank"),
                            ("score_tie_count", "true_score_tie_count")):
            require(baseline_truth[actual] == expected[old], "matrix baseline evaluation differs")
        output.append({"case_id": fixture["case_id"], "corpus_id": fixture["corpus_id"],
                       "true_plaintext": fixture["plaintext"], "generating_order": fixture["order"],
                       "excluded_high_dimension_models": saved["excluded_high_dimension_models"], **result})
    summary = {"cases": len(output), "literal_candidate_reencryptions": literal_checks}
    for method in ("baseline", "trained"):
        summary[method] = {key + "_cases": sum(row[method][key] for row in output)
                           for key in ("truth_is_top_tied", "truth_is_unique_top", "truth_wins_lexical_tiebreak")}
    require(summary["baseline"]["truth_is_top_tied_cases"] == matrix["summary"]["true_plaintext_rank_one_cases"],
            "matrix baseline top-one count differs")
    for word, compare in (("improved", lambda a, b: a < b), ("unchanged", lambda a, b: a == b),
                          ("worsened", lambda a, b: a > b)):
        summary[word + "_competition_rank_cases"] = sum(compare(
            row["trained"]["truth"]["competition_rank"], row["baseline"]["truth"]["competition_rank"])
            for row in output)
    return {"summary": summary, "cases": output}


def rescore_pipeline(saved, journal_lines, scorer, known):
    require(saved["complete"] is True and saved["inputs_unchanged"] is True, "incomplete calibration run")
    require(saved["config"]["maximum_plaintext_dimension"] == 1 and saved["config"]["controls_per_kind"] == 8,
            "calibration scope changed")
    require({int(i): c for i, c in saved["config"]["known_plaintext"].items()} == known, "calibration mask differs")
    header, *jobs = journal_lines
    require(header == {"identity": saved["identity"], "version": 1}, "journal identity/version mismatch")
    # ExperimentJournal serializes its job keys as canonical decimal strings;
    # the candidate payload deliberately keeps route_id as an integer.
    require(len(jobs) == saved["route_jobs_total"] == saved["route_jobs_completed"] == 2
            and all(type(job["id"]) is str for job in jobs)
            and {job["id"] for job in jobs} == {"0", "1"},
            "journal route jobs are incomplete/duplicated")
    names = ["K4"] + [f"{kind}-{i}" for kind in ("shuffle", "uniform") for i in range(8)]
    require(saved["results"]["K4"]["ciphertext"] == K4_CIPHERTEXT, "calibration K4 input changed")
    outputs, best_exact, literal_checks = {}, {}, 0
    for name in names:
        expected = saved["results"][name]
        require(expected["budget_exhausted"] is False, "calibration exhausted an input's candidate budget")
        ciphertext = saved["config"]["materialized_inputs"][name]
        require(ciphertext == expected["ciphertext"], "calibration input mismatch")
        scores, evaluations = {}, 0
        for job in jobs:
            row = job["result"]["inputs"][name]
            require(row["budget_exhausted"] is False, "journal job exhausted candidate budget")
            evaluations += row["candidates_evaluated"]
            for text, candidate in row["plaintexts"].items():
                validate_plaintext(text, known)
                require(candidate["score"] == english_score(text, known), "calibration baseline score changed")
                require(type(candidate["route_id"]) is int and candidate["route_id"] == int(job["id"]),
                        "journal candidate route id mismatch")
                require(candidate["periods"] == [len(key) for key in candidate["keys"]], "journal key periods differ")
                require(literal_encrypt(text, candidate["keys"], candidate["order"], candidate["permutation"])
                        == ciphertext, "journal candidate fails literal re-encryption")
                literal_checks += 1
                if text in scores:
                    require(scores[text] == candidate["score"], "duplicate plaintext has inconsistent baseline score")
                scores[text] = candidate["score"]
        require(evaluations == expected["candidates_evaluated"] and len(scores) == expected["distinct_plaintexts"],
                "aggregated calibration candidate counts differ")
        result, best = compare_set(scores, scorer)
        require(result["baseline"]["best_plaintext"] == expected["best_plaintext"]
                and scores[expected["best_plaintext"]] == expected["best_score"], "saved calibration winner differs")
        best_exact[name] = best
        outputs[name] = {"ciphertext_sha256": digest(ciphertext),
                         "excluded_high_dimension_models": expected["skipped_by_dimension"], **result}
    comparisons = {}
    for kind in ("shuffle", "uniform"):
        controls = [f"{kind}-{i}" for i in range(8)]
        baseline_count = sum(saved["results"][name]["best_score"] >= saved["results"]["K4"]["best_score"]
                             for name in controls)
        require(baseline_count == saved["comparisons"][kind]["at_least_observed"], "baseline control comparison changed")
        comparisons[kind] = {
            "controls": 8, "baseline_controls_at_least_k4": baseline_count,
            "trained_controls_at_least_k4": sum(best_exact[name] >= best_exact["K4"] for name in controls),
            "trained_controls_strictly_above_k4": sum(best_exact[name] > best_exact["K4"] for name in controls),
            "trained_controls_exactly_tied_with_k4": sum(best_exact[name] == best_exact["K4"] for name in controls),
        }
    return {"inputs": outputs, "comparisons": comparisons, "literal_saved_candidate_checks": literal_checks,
            "unused_saved_inputs": sorted(set(saved["results"]) - set(names)),
            "scope": "K4 plus sixteen materialized controls; identical saved candidate sets and maximum selection for both scorers"}


def analyze():
    started = time.perf_counter()
    paths = [Path(__file__), ROOT / "kryptos/data.py", ROOT / "kryptos/language.py", ROOT / "kryptos/scoring.py",
             MATRIX, CALIBRATION, JOURNAL, MODEL, PILOT / "results.json", PILOT / "provenance.json"]
    before = hashes(paths)
    matrix, saved, pilot, provenance = (read_json(path) for path in
                                        (MATRIX, CALIBRATION, PILOT / "results.json", PILOT / "provenance.json"))
    model = CharacterNgramModel.from_json(MODEL.read_bytes().decode("utf-8"))
    english = next(row for row in pilot["languages"] if row["language_label"] == "english")
    require(model.model_id == english["model_id"] and english["model_file"] == MODEL.name
            and digest(MODEL.read_bytes()) == english["model_file_sha256"] == provenance["output_hashes"][MODEL.name],
            "trained English model does not match pinned pilot provenance")
    require(digest((PILOT / "results.json").read_bytes()) == provenance["output_hashes"]["results.json"],
            "pilot results hash mismatch")
    require(model.label == "english: single-book Gutenberg 1342 pilot" and model.order == 3 and model.alpha == 0.1
            and model.alphabet == "ABCDEFGHIJKLMNOPQRSTUVWXYZ" and model.normalization == "identity"
            and len(model.corpora) == 1 and model.corpora[0].characters == 50_000,
            "English model differs from the predeclared pilot settings")
    scoring_hash = digest((ROOT / "kryptos/scoring.py").read_bytes())
    require(next(row["sha256_before"] for row in matrix["inputs"] if row["path"] == "kryptos/scoring.py")
            == scoring_hash, "baseline scoring source differs from the saved matrix")
    require(next(value for path, value in saved["identity"]["inputs"].items() if Path(path).name == "scoring.py")
            == scoring_hash, "baseline scoring source differs from saved calibration")
    known = {crib["start"] - 1 + i: c for crib in K4_CRIBS for i, c in enumerate(crib["text"])}
    require(len(known) == 24, "canonical mask changed")
    scorer = FixedScorer(model, known)
    matrix_result = rescore_matrix(matrix, scorer, known)
    journal = [strict_json(line) for line in JOURNAL.read_bytes().splitlines() if line.strip()]
    pipeline = rescore_pipeline(saved, journal, scorer, known)
    after = hashes(paths)
    require(before == after, "an input changed during rescoring")
    return {
        "schema": "kryptos.fixed-recovery-rescore.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "input_hashes_before": before, "input_hashes_after": after, "inputs_unchanged": True,
        "model_id": model.model_id, "model_label": model.label,
        "tie_policy": {
            "baseline": "exact equality/order of saved binary64 heuristic scores, independently recomputed",
            "trained": "integer product of count*alpha_denominator+alpha_numerator over67 eligible trigrams; common denominator cancels; alpha is the saved IEEE-754 binary64 rational, not exact decimal1/10",
            "alpha_numerator": str(scorer.alpha_numerator), "alpha_denominator": str(scorer.alpha_denominator),
            "per_window_common_denominator": str(scorer.denominator),
            "lexical_tiebreak": "ascending plaintext; competition rank and tie counts also reported",
        },
        "scored_positions": 73, "complete_trigram_windows": 67,
        "excluded_positions_zero_based": sorted(known), "recovery_matrix": matrix_result,
        "fixed_pipeline_controls": pipeline, "unique_strings_scored": len(scorer.cache),
        "runtime_seconds": time.perf_counter() - started,
        "non_claims": [
            "No training order, alpha, corpus, mask, or candidate membership was tuned on these recovery outcomes.",
            "The 12 cases reuse four authored texts and related cipher families; they are not independent language trials.",
            "Crib insertion and97-letter truncation create artificial prose joins; single-book training has domain bias.",
            "Recovery measures plaintext selection within the recorded family, not authentic-key identification.",
            "Higher-dimensional hypotheses excluded by the original runs remain excluded; this is not an exhaustive cipher search.",
            "The16 controls are exploratory; rescoring an inspected benchmark is retrospective, not independent validation.",
            "A stronger recovery rank or control separation neither authenticates K4 nor establishes its language or K5.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new result JSON file; no overwrite")
    args = parser.parse_args(argv)
    try:
        output = args.output.resolve()
        require(output.is_relative_to(ROOT / "research") and not output.exists(),
                "output must be a new file under research")
        result = analyze()
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as file:
            json.dump(result, file, indent=2, ensure_ascii=True, allow_nan=False)
            file.write("\n")
        print(json.dumps({"output": str(output), "recovery": result["recovery_matrix"]["summary"],
                          "controls": result["fixed_pipeline_controls"]["comparisons"],
                          "runtime_seconds": result["runtime_seconds"]}, indent=2))
    except (ValueError, OSError, KeyError, TypeError, StopIteration) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
