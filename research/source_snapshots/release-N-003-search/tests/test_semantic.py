"""Fixed-rule examples; no assertion that an example is Kryptos's codebook."""

import hashlib
import io
import json
from contextlib import contextmanager, redirect_stderr
from pathlib import Path
import unittest
import uuid

from kryptos.semantic import apply_codebook, extract_initials, main


@contextmanager
def fixture_directory():
    directory = Path(__file__).resolve().parent / ("_semantic_fixture_" + uuid.uuid4().hex)
    directory.mkdir()
    try:
        yield directory
    finally:
        for file in directory.iterdir():
            file.unlink()
        directory.rmdir()


class SemanticExtractionTests(unittest.TestCase):
    def test_segmentation_controls_initials(self):
        text = "EASTNORTHEAST"
        two = extract_initials(text, [(0, 4), (4, 13)], rule_source="hypothesis/two words")
        three = extract_initials(text, [(0, 4), (4, 9), (9, 13)],
                                 rule_source="hypothesis/three words")
        self.assertEqual(two.transformed_text, "EN")
        self.assertEqual(three.transformed_text, "ENE")
        self.assertNotEqual(two.segmentation_sha256, three.segmentation_sha256)
        self.assertEqual(two.input_sha256, hashlib.sha256(text.encode()).hexdigest())

    def test_explicit_phrase_mapping_preserves_unknowns(self):
        text = "????EASTNORTHEAST???BERLINCLOCK??"
        result = apply_codebook(
            text, [(0, 4), (4, 17), (17, 20), (20, 31), (31, 33)],
            {"EASTNORTHEAST": "ENE", "BERLINCLOCK": "BC", "UNUSED": "U"},
            rule_source="user hypothesis; phrase replacements, not decipherment")
        self.assertEqual(result.transformed_text, "????ENE???BC??")
        self.assertEqual(result.recognized_tokens, 2)
        self.assertEqual(result.covered_characters, 24)
        self.assertEqual(result.unused_codebook_entries, ("UNUSED",))
        self.assertEqual(result.to_dict()["character_coverage"], 24 / 33)
        self.assertFalse(result.tokens[0].recognized)
        self.assertEqual(result.tokens[0].output, "????")
        self.assertEqual("".join(t.original for t in result.tokens), text)

    def test_no_partial_match_case_change_or_guessing(self):
        text = "XEASTEASTeast"
        result = apply_codebook(text, [(0, 5), (5, 9), (9, 13)], {"EAST": "E"},
                                rule_source="exact only")
        self.assertEqual(result.transformed_text, "XEASTEeast")
        self.assertEqual(result.recognized_tokens, 1)
        unknown = extract_initials("?EAST", [(0, 1), (1, 5)], rule_source="initials test")
        self.assertEqual(unknown.transformed_text, "?E")
        self.assertEqual(unknown.covered_characters, 4)

    def test_partitions_must_cover_input_without_overlap_or_gaps(self):
        for spans in ([(0, 2)], [(1, 3)], [(0, 2), (1, 3)], [(0, 1), (2, 3)],
                      [(0, 0), (0, 3)], [(0, 4)], [(False, 3)], [(0, 1, 3)]):
            with self.assertRaises(ValueError):
                apply_codebook("ABC", spans, {}, rule_source="invalid partition")

    def test_rule_provenance_is_deterministic_and_sensitive(self):
        first = apply_codebook("AB", [(0, 1), (1, 2)], {"A": "X", "B": "Y"},
                               rule_source="test rule")
        reordered = apply_codebook("AB", [(0, 1), (1, 2)], {"B": "Y", "A": "X"},
                                   rule_source="test rule")
        changed = apply_codebook("AB", [(0, 1), (1, 2)], {"A": "Z", "B": "Y"},
                                 rule_source="test rule")
        self.assertEqual(first.to_dict(), reordered.to_dict())
        self.assertNotEqual(first.rule_sha256, changed.rule_sha256)
        saved = first.to_dict()
        canonical_rule = json.dumps(dict(rule=saved["rule"], source=saved["rule_source"],
                                        codebook=saved["codebook"], parameters=saved["rule_parameters"]),
                                    sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        self.assertEqual(saved["rule_sha256"], hashlib.sha256(canonical_rule.encode()).hexdigest())

    def test_bounds_invalid_mappings_and_empty_input(self):
        self.assertEqual(apply_codebook("", [], {}, rule_source="empty fixture")
                         .to_dict()["character_coverage"], 0)
        for mapping in ({"A": ""}, {"": "X"}, {"A": 1}):
            with self.assertRaises(ValueError):
                apply_codebook("A", [(0, 1)], mapping, rule_source="invalid")
        with self.assertRaises(ValueError):
            apply_codebook("ABC", [(0, 3)], {}, rule_source="bound", max_characters=2)
        with self.assertRaises(ValueError):
            apply_codebook("ABC", [(0, 1), (1, 3)], {}, rule_source="bound", max_segments=1)
        with self.assertRaises(ValueError):
            apply_codebook("AAAA", [(0, 1), (1, 2), (2, 3), (3, 4)], {"A": "BBBB"},
                           rule_source="output bound", max_characters=8)
        with self.assertRaises(ValueError):
            apply_codebook("A", [(0, 1)], {}, rule_source="")

    def test_cli_explicit_mapping_and_output_protection(self):
        with fixture_directory() as directory:
            request, output = Path(directory) / "request.json", Path(directory) / "output.json"
            payload = {"method": "codebook", "text": "???BERLINCLOCK??",
                       "segments": [[0, 3], [3, 14], [14, 16]],
                       "codebook": {"BERLINCLOCK": "BC"}, "rule_source": "synthetic CLI hypothesis"}
            request.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(main(["--input", str(request), "--output", str(output)]), 0)
            original = output.read_bytes()
            result = json.loads(original)
            self.assertEqual(result["transformed_text"], "???BC??")
            self.assertEqual(result["covered_characters"], 11)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failed:
                main(["--input", str(request), "--output", str(output)])
            self.assertEqual(failed.exception.code, 2)
            self.assertEqual(output.read_bytes(), original)

    def test_cli_rejects_duplicate_or_ignored_rules(self):
        with fixture_directory() as directory:
            request = Path(directory) / "request.json"
            payload = {"method": "initials", "text": "AB", "segments": [[0, 2]],
                       "rule_source": "synthetic rule", "codebook": {"AB": "X"}}
            bad_requests = [json.dumps(payload), json.dumps(payload).replace(
                '"method": "initials"', '"method":"codebook","method":"initials"')]
            for bad in bad_requests:
                request.write_text(bad, encoding="utf-8")
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failed:
                    main(["--input", str(request)])
                self.assertEqual(failed.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
