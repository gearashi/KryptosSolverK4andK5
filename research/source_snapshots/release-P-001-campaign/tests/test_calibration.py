"""Small whole/resumed calibration equivalence checks, not application tests."""

from contextlib import contextmanager
import itertools
import json
from pathlib import Path
import unittest
import uuid

from kryptos.layer_plan import compile_layer_plan
from research.calibrate_layers import analyze


@contextmanager
def journal_directory():
    parent = Path(__file__).resolve().parent
    folder = parent / ("calibration_test_" + uuid.uuid4().hex)
    folder.mkdir()
    try:
        yield folder
    finally:
        if not folder.resolve().is_relative_to(parent):
            raise RuntimeError("temporary directory escaped tests workspace")
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()


def comparable(result):
    # JSON is the persisted scientific representation; tuples intentionally
    # become lists on resume. Wall time is operational, not a scientific value.
    result = json.loads(json.dumps(result, allow_nan=False))
    result.pop("runtime_seconds")
    return result


class CalibrationTests(unittest.TestCase):
    def test_checkpoint_rejects_unplanned_jobs(self):
        with journal_directory() as folder:
            path = folder / "state.jsonl"
            analyze(controls=1, max_period=3, journal_path=path, max_route_jobs=1)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"id": "unexpected", "result": {}}) + "\n")
            with self.assertRaises(ValueError):
                analyze(controls=1, max_period=3, journal_path=path)

    def test_exact_integer_bounds(self):
        with self.assertRaises(ValueError):
            analyze(controls=True)
        with self.assertRaises(ValueError):
            analyze(max_route_jobs=True)

    def test_whole_equals_resume_and_completed_resume_is_noop(self):
        settings = dict(controls=1, max_period=3, max_dimension=0,
                        candidate_budget=100, seed=20261012)
        whole = analyze(**settings)
        self.assertTrue(whole["results"]["synthetic"]["synthetic_plaintext_recovered"])
        with journal_directory() as folder:
            path = folder / "state.jsonl"
            first = analyze(**settings, journal_path=path, max_route_jobs=1)
            self.assertFalse(first["complete"])
            self.assertEqual(first["route_jobs_completed"], 1)
            resumed = analyze(**settings, journal_path=path, max_route_jobs=1)
            self.assertEqual(comparable(whole), comparable(resumed))
            saved = path.read_bytes()
            repeated = analyze(**settings, journal_path=path)
            self.assertEqual(comparable(whole), comparable(repeated))
            self.assertEqual(path.read_bytes(), saved)

    def test_resume_preserves_global_candidate_budget(self):
        settings = dict(controls=1, max_period=4, max_dimension=1,
                        candidate_budget=1, seed=41)
        whole = analyze(**settings)
        with journal_directory() as folder:
            path = folder / "state.jsonl"
            analyze(**settings, journal_path=path, max_route_jobs=1)
            resumed = analyze(**settings, journal_path=path)
            self.assertEqual(comparable(whole), comparable(resumed))
        self.assertTrue(any(row["budget_exhausted"] for row in whole["results"].values()))
        self.assertTrue(all(row["candidates_evaluated"] <= 1 for row in whole["results"].values()))

    def test_resume_rejects_changed_configuration(self):
        with journal_directory() as folder:
            path = folder / "state.jsonl"
            analyze(controls=1, max_period=3, journal_path=path, max_route_jobs=1)
            saved = path.read_bytes()
            with self.assertRaises(ValueError):
                analyze(controls=1, max_period=4, journal_path=path)
            self.assertEqual(path.read_bytes(), saved)

    def test_small_enumeration_matches_literal_inverse_layers(self):
        # Exhaust 26^3 keys for two-character examples, independently undoing
        # each actual stage. No graph equations or production encrypt helper.
        alphabet, cipher, route = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "BD", (1, 0)
        for order in ("SST", "STS", "TSS"):
            plan = compile_layer_plan(2, [0], order, route, 2, 1)
            solution = plan.solve(cipher, {0: "A"}, alphabet)["solution"]
            actual = [text for _, text in solution.enumerate_plaintexts(26)]
            expected = set()
            for a0, a1, b0 in itertools.product(range(26), repeat=3):
                values = [1, 3]
                keys = iter(((b0,), (a0, a1)))
                for operation in reversed(order):
                    if operation == "T":
                        original = [None] * 2
                        for output, source in enumerate(route):
                            original[source] = values[output]
                        values = original
                    else:
                        key = next(keys)
                        values = [(value-key[i % len(key)]) % 26 for i, value in enumerate(values)]
                text = "".join(alphabet[value] for value in values)
                if text[0] == "A":
                    expected.add(text)
            self.assertEqual(len(actual), len(set(actual)))
            self.assertEqual(set(actual), expected)
            self.assertEqual(solution.distinct_plaintext_count, len(expected))


if __name__ == "__main__":
    unittest.main()
