"""Tiny synthetic checks only: no authentic language corpus or app process."""

import hashlib
import io
import json
import math
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
import unittest
import uuid

from kryptos.language import CorpusDocument, CharacterNgramModel, calibrate_controls, main, train_ngram_model


@contextmanager
def fixture_directory():
    # Python 3.14's mode-0700 Windows temp directory ACL is incompatible with
    # some restricted tokens. Use a disposable sibling with inherited ACLs.
    directory = Path(__file__).resolve().parent / ("_language_fixture_" + uuid.uuid4().hex)
    directory.mkdir()
    try:
        yield directory
    finally:
        for file in directory.iterdir():
            file.unlink()
        directory.rmdir()


class CharacterModelTests(unittest.TestCase):
    def model(self, text="ABABABABABABAB", **kwargs):
        return train_ngram_model([CorpusDocument(text, "synthetic/train", "test fixture")],
                                  label="synthetic alternating pattern", order=2, **kwargs)

    def test_synthetic_held_out_patterns_rank_as_trained(self):
        # Different document lengths, explicit synthetic provenance. This tests
        # mechanics, not natural-language generalization or a recovery rate.
        alternating = self.model()
        repeated = self.model("AAAAAAAABBBBBBBB")
        held_out = "ABABAB"
        other = "AAAABB"
        self.assertGreater(alternating.score(held_out).mean_log_probability,
                           alternating.score(other).mean_log_probability)
        self.assertGreater(repeated.score(other).mean_log_probability,
                           repeated.score(held_out).mean_log_probability)
        self.assertEqual(alternating.score(held_out).windows, 5)

    def test_exact_counts_joint_smoothing_and_document_boundaries(self):
        model = train_ngram_model([CorpusDocument("AB", "fixture/a"),
                                   CorpusDocument("BA-AB", "fixture/b")],
                                  label="fixture", alphabet="AB", order=2, alpha=1)
        self.assertEqual(dict(model.counts), {"AB": 2, "BA": 1})
        self.assertAlmostEqual(model.score("AB").mean_log_probability, math.log(3 / 7))
        self.assertAlmostEqual(model.score("AA").mean_log_probability, math.log(1 / 7))

    def test_masked_symbols_never_influence_score_or_bridge_gaps(self):
        model = self.model("ABBCBCBCAB")
        left = model.score("AXBC", [1])
        changed = model.score("AQBC", [1])
        expected = model.score("BC")
        self.assertEqual(left, changed)
        self.assertEqual(left.mean_log_probability, expected.mean_log_probability)
        self.assertEqual(left.windows, 1)
        self.assertEqual(left.eligible_positions, (0, 2, 3))
        self.assertEqual(left.scored_positions, (2, 3))
        self.assertEqual(model.score("AXB", [1]).windows, 0)

    def test_unsupported_symbols_and_unicode_expansions_are_boundaries(self):
        model = self.model("ABBCBCBCAB")
        for text in ("A-BC", "AßBC", "a bc"):
            score = model.score(text)
            self.assertEqual(score.mean_log_probability, model.score("BC").mean_log_probability)
            self.assertEqual(score.unsupported_positions, (1,))
            self.assertEqual(score.scored_positions, (2, 3))
        unicode_model = train_ngram_model([CorpusDocument("äöäö", "fixture/unicode")],
                                          label="synthetic Unicode", alphabet="äö",
                                          normalization="identity", order=2)
        self.assertEqual(unicode_model.score("äö").windows, 1)

    def test_empty_or_short_coverage_is_unavailable(self):
        model = self.model()
        for text, mask in (("AB", [0, 1]), ("", []), ("A", [])):
            score = model.score(text, mask)
            self.assertFalse(score.available)
            self.assertIsNone(score.mean_log_probability)
            self.assertEqual(score.log_probability_sum, 0)
        for mask in ((-1,), (2,), (True,), (1, True)):
            with self.assertRaises(ValueError):
                model.score("AB", mask)

    def test_serialized_provenance_and_counts_roundtrip(self):
        model = self.model()
        encoded = model.to_json()
        value = json.loads(encoded)
        self.assertEqual(value["corpora"][0]["sha256"],
                         hashlib.sha256(b"ABABABABABABAB").hexdigest())
        self.assertNotIn("text", value["corpora"][0])
        restored = CharacterNgramModel.from_json(encoded)
        self.assertEqual(restored.to_json(), encoded)
        self.assertEqual(restored.score("ABABAB"), model.score("ABABAB"))
        with self.assertRaises(TypeError):
            restored.counts["AB"] = 999
        value["counts"]["AB"] += 1
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            CharacterNgramModel.from_json(json.dumps(value))

    def test_invalid_or_absent_training_is_rejected(self):
        for kwargs in ({"order": 0}, {"alpha": 0}, {"alpha": math.inf},
                       {"alphabet": "AA"}, {"normalization": "guess"}):
            with self.assertRaises(ValueError):
                train_ngram_model([CorpusDocument("ABAB", "fixture")], label="fixture", **kwargs)
        for documents in ([], [CorpusDocument("A", "fixture")]):
            with self.assertRaises(ValueError):
                train_ngram_model(documents, label="no windows", order=2)
        with self.assertRaises(ValueError):
            train_ngram_model([CorpusDocument("AB", "same"), CorpusDocument("BA", "same")],
                              label="duplicate source", order=2)

    def test_model_loading_rejects_ambiguous_and_rehashed_invalid_data(self):
        encoded = self.model().to_json()
        for bad in (encoded.replace('"label":', '"label":"ignored","label":', 1),
                    encoded.replace('"alpha":0.1', '"alpha":NaN', 1),
                    encoded.replace('"alpha":0.1', '"alpha":1e9999', 1)):
            with self.assertRaises(ValueError):
                CharacterNgramModel.from_json(bad)

        def rehash(value):
            value.pop("model_id")
            canonical = json.dumps(value, sort_keys=True, ensure_ascii=True,
                                   separators=(",", ":"), allow_nan=False)
            value["model_id"] = hashlib.sha256(canonical.encode()).hexdigest()
            return json.dumps(value)

        for field, invalid in (("order", True), ("counts", [["AB", 13]]),
                               ("created_utc", "not a date"),
                               ("created_utc", "2026-10-12T00:00:00"),
                               ("created_utc", "2026-10-12T00:00:00+01:00")):
            value = json.loads(encoded)
            value[field] = invalid
            with self.assertRaises(ValueError):
                CharacterNgramModel.from_json(rehash(value))
        value = json.loads(encoded)
        value["corpora"][0]["eligible_characters"] = 2
        with self.assertRaises(ValueError):
            CharacterNgramModel.from_json(rehash(value))

    def test_large_finite_smoothing_does_not_overflow(self):
        model = self.model(alpha=1e308)
        self.assertTrue(math.isfinite(model.score("ABAB").mean_log_probability))

    def test_controls_calibrate_each_model_separately(self):
        model = self.model()
        controls = [CorpusDocument(text, f"synthetic/control/{i}")
                    for i, text in enumerate(("AAAAAA", "BBBBBB", "BBAAAA", "AABBBB"))]
        calibration = calibrate_controls(model, controls, description="fixed synthetic controls")
        assessment = calibration.assess(model, "ABABAB")
        self.assertGreater(assessment.standardized_score, 0)
        self.assertEqual(assessment.smoothed_control_exceedance, 1 / 5)
        self.assertFalse(assessment.exact_training_duplicate)
        self.assertFalse(assessment.exact_control_duplicate)
        self.assertTrue(calibration.assess(model, "AAAAAA").exact_control_duplicate)
        self.assertEqual(calibration.to_dict()["controls"][0]["source"], "synthetic/control/0")
        with self.assertRaises(ValueError):
            calibration.assess(self.model("AAAAAAAABBBBBBBB"), "ABABAB")
        with self.assertRaises(ValueError):
            calibration.assess(model, "ABABAB", [0])

    def test_control_layout_overlap_and_zero_variance_guards(self):
        model = self.model()
        controls = [CorpusDocument("AA-AA", "control/a"), CorpusDocument("BB-BB", "control/b")]
        calibration = calibrate_controls(model, controls, description="equal-score controls")
        self.assertIsNone(calibration.assess(model, "AB-AB").standardized_score)
        with self.assertRaises(ValueError):
            calibration.assess(model, "A-BAB")  # Same eligible count, different gaps.
        for bad in ([CorpusDocument("ABABABABABABAB", "control/traincopy")],
                    [CorpusDocument("AAAA", "synthetic/train")],
                    [CorpusDocument("AAAA", "a"), CorpusDocument("AAAA", "b")],
                    [CorpusDocument("AA-AA", "a"), CorpusDocument("A-AAA", "b")]):
            with self.assertRaises(ValueError):
                calibrate_controls(model, bad, description="invalid controls")

    def test_train_and_calibrated_score_cli_roundtrip(self):
        with fixture_directory() as directory:
            folder = Path(directory)
            training, model_path, request, output = (folder / name for name in
                                                     ("train.json", "model.json", "request.json", "score.json"))
            training.write_text(json.dumps({"label": "synthetic CLI fixture", "order": 2,
                                             "documents": [{"text": "ABABABABABABAB",
                                                            "source": "synthetic/train"}]}), encoding="utf-8")
            self.assertEqual(main(["train", "--input", str(training), "--output", str(model_path)]), 0)
            original = model_path.read_bytes()
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failed:
                main(["train", "--input", str(training), "--output", str(model_path)])
            self.assertEqual(failed.exception.code, 2)
            self.assertEqual(model_path.read_bytes(), original)
            request.write_text(json.dumps({"text": "ABABAB", "excluded_positions": [1],
                                            "controls": [{"text": "AAAAAA", "source": "control/a"},
                                                         {"text": "BBAAAA", "source": "control/b"}],
                                            "control_description": "synthetic CLI controls"}), encoding="utf-8")
            main(["score", "--model", str(model_path), "--input", str(request), "--output", str(output)])
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["score"]["excluded_positions"], [1])
            self.assertEqual(result["assessment"]["control_count"], 2)
            self.assertEqual(result["calibration"]["model_id"], result["model_id"])

    def test_corpus_file_cli_preserves_exact_newlines_and_rejects_ignored_settings(self):
        with fixture_directory() as directory:
            corpus = Path(directory) / "synthetic.txt"
            raw = b"ABABAB\r\nBABABA"
            corpus.write_bytes(raw)
            output = io.StringIO()
            with redirect_stdout(output):
                main(["train", "--corpus", str(corpus), "--label", "synthetic file", "--order", "2"])
            model = CharacterNgramModel.from_json(output.getvalue())
            self.assertEqual(model.corpora[0].sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(model.corpora[0].source, str(corpus.resolve()))
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failed:
                main(["train", "--input", str(corpus), "--order", "2"])
            self.assertEqual(failed.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
