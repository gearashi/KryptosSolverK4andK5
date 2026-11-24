"""Regression checks for the dashboard's fixed, durable Round T queue."""
import shutil
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from kryptos.app import round_t_queue
from kryptos.app_jobs import RunManager, validate_start


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
                result = {"preset": preset, "completed": ok, "tested": 12 if ok else 0,
                          "controls": {"passed": ok}}
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
