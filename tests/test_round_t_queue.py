"""Regression checks for the dashboard's fixed, durable Round T queue."""
import hashlib
import json
import shutil
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from kryptos.app import round_t_queue
from kryptos.app_jobs import RunManager, round_t_completed, validate_start
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS


class RoundTQueueTests(unittest.TestCase):
    def test_fixed_recipe(self):
        config = {"command": "round-t", "request": {"preset": "shared-pair"}}
        saved = validate_start(config)["request"]
        self.assertEqual(len(saved["ciphertext"]), 97)
        self.assertEqual(validate_start({**config, "request": saved})["request"], saved)
        for change in ({"preset": "missing"}, {"target": "custom"}, {"cribs": []}, {"extra": 7}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_start({**config, "request": {**saved, **change}})
        with self.assertRaises(ValueError):
            validate_start({**config, "kind": "accelerated"})
        self.assertGreaterEqual(len(round_t_queue()), 2)

    def test_mismatched_evidence_does_not_recommend_from_a_different_source(self):
        source = {"schema": "kryptos.round-t.coverage.v1", "results": [],
                  "cribs": K4_CRIBS, "ciphertext_sha256": "0" * 64}
        self.addCleanup(round_t_queue.cache_clear)
        for field, changed in (("ciphertext_sha256", "0" * 64), ("cribs", [])):
            source.update(cribs=K4_CRIBS, ciphertext_sha256=hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest())
            source[field] = changed
            round_t_queue.cache_clear()
            with self.subTest(field=field), patch.object(Path, "read_text", return_value=json.dumps(source)):
                self.assertEqual(round_t_queue(), [])

    def test_control_failure_and_restart(self):
        # Exercise the job/ledger boundary without consuming a pending K4 preset.
        research = Path(__file__).resolve().parents[1] / "research"
        directory = (research / (".round-t-test-" + uuid.uuid4().hex)).resolve()
        self.assertEqual(directory.parent, research)
        directory.mkdir()
        self.addCleanup(shutil.rmtree, directory)
        runs = directory / "runs"
        manager = RunManager(runs)
        try:
            for preset, ok in (("shared-pair", False), ("column-plain", True)):
                result = {"preset": preset, "completed": ok, "tested": 12 if ok else 0, "planned": 12,
                          "flagged_count": 0, "held_out": 7, "controls": {"passed": ok, "planted_found": 2,
                          "planted_total": 2, "shuffled_flagged": 0, "shuffled_total": 20}}
                self.assertFalse(round_t_completed({**result, "held_out": 5}))
                self.assertFalse(round_t_completed({**result, "tested": 1}))
                self.assertFalse(round_t_completed({**result, "controls": {**result["controls"], "shuffled_flagged": 1}}))
                with patch.object(manager, "_launch", return_value=result):
                    run = manager.start({"command": "round-t", "request": {"preset": preset}})
                    manager.thread.join(timeout=15)
                saved = manager.view(run["id"])
                self.assertEqual(saved["state"], "completed" if ok else "limited", saved.get("error"))
                self.assertEqual(saved["progress"]["completed"], result["tested"])
        finally:
            manager.close()
        reopened = RunManager(runs)
        try:
            self.assertEqual(reopened.round_t_coverage(), ["column-plain"])
        finally:
            reopened.close()
