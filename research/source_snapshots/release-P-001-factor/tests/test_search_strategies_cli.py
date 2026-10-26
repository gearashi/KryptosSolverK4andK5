import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

from kryptos.__main__ import _target
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.next_cli import run_next


class StrategyCliTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path("research") / ("test-strategies-" + uuid.uuid4().hex)
        self.folder.mkdir()
        model = train_ngram_model([CorpusDocument("THISISATESTOFEXACTSCORES" * 3, "synthetic-control")],
                                  label="synthetic", order=2, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", normalization="identity")
        self.model = self.folder / "model.json"
        self.model.write_text(model.to_json(), encoding="utf-8")

    def tearDown(self):
        for file in self.folder.iterdir():
            file.unlink()
        self.folder.rmdir()

    def request(self, **extra):
        return {"target": "custom", "ciphertext": "BCDEFGHI", "cribs": [{"start": 1, "text": "A"}],
                "alphabet": "standard", "model_path": str(self.model),
                "stages": [{"operation": "substitution", "period": 2}], **extra}

    def test_guided_general_and_scheduled_replay_and_combined_scan(self):
        for kind in ("general", "scheduled"):
            stages = ([{"operation": "substitution", "period": 2}] if kind == "general" else
                      [{"operation": "substitution", "key_id": "k", "key_length": 2}])
            request = self.request(layer_model=kind, stages=stages, max_nodes=0,
                guided_seed={"max_evaluations": 40, "seed": 7, "restarts": 3},
                seed_scan={"backend": "cpu", "batch_size": 4, "top": 2})
            result = run_next("optimize-plus", request, _target)["optimization"]
            report = result["search"]["guided_seed"]
            self.assertEqual(report["status"], "verified")
            self.assertGreater(report["verified_seeds"], 0)
            self.assertEqual(report["verified_seeds"], report["literal_replays_verified"])
            self.assertTrue(result["candidate"]["evidence"]["literal_reencryption_matches"])
            self.assertFalse(result["candidate"]["authenticated_solution"])

    def test_resume_does_not_repeat_seed_budgets(self):
        request = self.request(guided_seed={"max_evaluations": 20},
            seed_scan={"backend": "cpu", "batch_size": 4}, decomposition="auto", max_nodes=0,
            checkpoint_path=str(self.folder/"a.json"))
        initial = run_next("optimize-plus", request, _target)
        request.update(max_nodes=1, resume_path=str(self.folder/"a.json"), checkpoint_path=str(self.folder/"b.json"))
        with patch("kryptos.guided_search.guided_seeds") as guided, patch("kryptos.accelerated.scan_batch") as scan:
            result = run_next("optimize-plus", request, _target)["optimization"]
        guided.assert_not_called()
        scan.assert_not_called()
        self.assertTrue(result["search"]["complete"])
        self.assertEqual(result["search"]["guided_seed"]["status"], "skipped_resume")
        self.assertEqual(result["search"]["seed_scan"]["status"], "skipped_resume")


if __name__ == "__main__":
    unittest.main()
