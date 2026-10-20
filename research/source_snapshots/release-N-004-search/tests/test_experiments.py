import json
from pathlib import Path
import unittest
import uuid
from contextlib import contextmanager
from kryptos.experiments import ExperimentJournal, fingerprint, control_summary


@contextmanager
def workspace_temp():
    root = Path(__file__).resolve().parent
    folder = root / ("experiment_test_" + uuid.uuid4().hex)
    folder.mkdir()
    try:
        yield folder
    finally:
        if not folder.resolve().is_relative_to(root):
            raise RuntimeError("test directory escaped workspace")
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()


class ExperimentsTests(unittest.TestCase):
    def test_resume_and_stale_inputs(self):
        with workspace_temp() as folder:
            root = Path(folder)
            source = root / "input.txt"
            source.write_text("first")
            identity = fingerprint({"seed": 12}, [source])
            journal = ExperimentJournal(root / "state.jsonl", identity)
            journal.record("first", {"count": 12})
            resumed = ExperimentJournal(root / "state.jsonl", identity)
            self.assertEqual(resumed.records, {"first": {"count": 12}})
            with self.assertRaises(ValueError):
                resumed.record("first", {})
            source.write_text("changed")
            with self.assertRaises(ValueError):
                ExperimentJournal(root / "state.jsonl", fingerprint({"seed": 12}, [source]))

    def test_corruption_and_nonfinite_rejected(self):
        with workspace_temp() as folder:
            path = Path(folder) / "state.jsonl"
            journal = ExperimentJournal(path, {"tag": "test"})
            with self.assertRaises(ValueError):
                journal.record("bad", {"score": float("nan")})
            with path.open("a") as stream:
                stream.write('{"interrupted":')
            with self.assertRaises(json.JSONDecodeError):
                ExperimentJournal(path, {"tag": "test"})

    def test_controls_account_for_ties_and_absent_scores(self):
        self.assertEqual(control_summary(1, [None, 0, 1, 2])["at_least_observed"], 2)
        self.assertIsNone(control_summary(None, [1])["at_least_observed"])

    def test_strict_checkpoint_json(self):
        for bad in ('{"id":"x","result":NaN}', '{"id":"x","result":1e400}',
                    '{"id":"x","id":"y","result":{}}', '{"id":"","result":{}}'):
            with workspace_temp() as folder:
                path = folder / "state.jsonl"
                ExperimentJournal(path, {"tag": "test"})
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(bad + "\n")
                with self.assertRaises(ValueError):
                    ExperimentJournal(path, {"tag": "test"})


if __name__ == "__main__":
    unittest.main()
