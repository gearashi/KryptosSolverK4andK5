import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from kryptos.__main__ import _target
from kryptos.next_cli import run_next


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"


def request(**extra):
    return {"target": "custom", "ciphertext": "BCDEFG", "cribs": [{"start": 1, "text": "ABCDEF"}],
            "alphabet": "standard", "stages": [{"operation": "substitution", "period": 1}],
            "model_path": str(MODEL), **extra}


class NextCliBudgetTests(unittest.TestCase):
    def test_scheduled_budget_is_unresolved_with_model_and_phase_provenance(self):
        stages = [{"operation": "substitution", "key_id": "k", "key_length": 2,
                   "schedule": {"kind": "row_reset", "frame": "current"}}]
        for cap, value in (("max_key_slots", 0), ("max_matrix_cells", 1), ("max_operations", 1)):
            supplied = {"ciphertext": "ABCDEF", "cribs": [], "alphabet": "standard", "stages": stages,
                        "cells": [[i // 3, i % 3] for i in range(6)], cap: value}
            with self.subTest(cap=cap):
                result = run_next("scheduled", supplied, _target)
                self.assertIsNone(result["feasible"])
                self.assertFalse(result["complete"])
                self.assertFalse(result["enumeration_complete"])
                self.assertEqual(result["stop_reason"], "algebra_budget")
                self.assertEqual(result["bounds"][cap], value)
                self.assertEqual(result["candidates"], [])
                self.assertEqual(result["phase_provenance"][0]["phase_map"], [0, 1, 0, 0, 1, 0])
                self.assertEqual(result["explanation"]["supplied_request"], supplied)

    def test_optimizer_budget_keeps_frozen_scoring_model_hash(self):
        for layer_model in ("general", "scheduled"):
            stages = ([{"operation": "substitution", "key_id": "k", "key_length": 1}]
                      if layer_model == "scheduled" else [{"operation": "substitution", "period": 1}])
            supplied = request(layer_model=layer_model, stages=stages, max_operations=1)
            result = run_next("optimize-plus", supplied, _target)
            self.assertIsNone(result["feasible"])
            self.assertFalse(result["complete"])
            self.assertEqual(result["stop_reason"], "algebra_budget")
            self.assertNotIn("optimization", result)
            self.assertEqual(result["model_file_sha256"], hashlib.sha256(MODEL.read_bytes()).hexdigest())
            self.assertTrue(result["scoring_model_id"])
            self.assertEqual(result["model_assumptions"]["stages"], stages)

    def test_batch_keeps_budget_contradiction_and_success_separate(self):
        jobs = [{"id": "success", "request": request()},
                {"id": "budget", "request": request(max_key_slots=0)},
                {"id": "contradiction", "request": request(ciphertext="AB", cribs=[{"start": 1, "text": "AA"}])}]
        result = run_next("batch", {"jobs": jobs, "workers": 1}, _target)
        records = {row["id"]: row for row in result["jobs"]}
        self.assertIsNone(records["budget"]["feasible"])
        self.assertFalse(records["budget"]["complete"])
        self.assertEqual(records["budget"]["model"]["stop_reason"], "algebra_budget")
        self.assertFalse(records["contradiction"]["feasible"])
        self.assertTrue(records["contradiction"]["complete"])
        self.assertTrue(records["success"]["feasible"])
        self.assertTrue(records["success"]["optimization"]["search"]["complete"])
        self.assertEqual(records["success"]["optimization"]["candidate"]["plaintext"], "ABCDEF")
        self.assertEqual(result["job_count"], 3)
        self.assertEqual(result["requested_jobs"], 3)
        self.assertEqual(result["optimization_job_count"], 1)
        self.assertEqual(result["inconclusive_algebra_jobs"], 1)
        self.assertFalse(result["all_searches_complete"])
        self.assertFalse(result["all_objectives_proved_optimal"])

    def test_all_budget_batch_returns_records_without_workers(self):
        with patch("kryptos.parallel_search.optimize_batch") as execute:
            result = run_next("batch", {"jobs": [{"id": "budget", "request": request(max_matrix_cells=1)}], "workers": 2}, _target)
        execute.assert_not_called()
        self.assertEqual(result["job_count"], 1)
        self.assertEqual(result["optimization_job_count"], 0)
        self.assertIsNone(result["jobs"][0]["feasible"])
        self.assertFalse(result["all_searches_complete"])

    def test_invalid_batch_ids_are_rejected_before_any_model_work(self):
        for bad in ("", "x" * 129, None, 4):
            with self.subTest(bad=bad), patch("kryptos.next_cli._optimization_job") as build:
                with self.assertRaises(ValueError):
                    run_next("batch", {"jobs": [{"id": "ok", "request": request()},
                                                 {"id": bad, "request": request(max_operations=1)}]}, _target)
                build.assert_not_called()
        with patch("kryptos.next_cli._optimization_job") as build:
            with self.assertRaises(ValueError):
                run_next("batch", {"jobs": [{"id": "same", "request": request()},
                                             {"id": "same", "request": request()}]}, _target)
            build.assert_not_called()

    def test_invalid_input_still_raises_instead_of_becoming_budget_result(self):
        with self.assertRaises(ValueError):
            run_next("optimize-plus", request(max_operations=True), _target)
        with self.assertRaises(OSError):
            run_next("optimize-plus", request(max_operations=1, model_path=str(ROOT / "not-a-model.json")), _target)


if __name__ == "__main__":
    unittest.main()
