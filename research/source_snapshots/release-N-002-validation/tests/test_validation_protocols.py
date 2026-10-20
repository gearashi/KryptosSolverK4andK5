import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.validation_protocols import run_validation, select_family_bank

ROOT=Path(__file__).resolve().parents[1]


def example(name):
    value=json.loads((ROOT/"examples"/(name+".json")).read_text())
    value["model_paths"]=[str(ROOT/p) for p in value["model_paths"]]
    return value


class ValidationProtocolTests(unittest.TestCase):
    def test_doctor_describes_backends_without_claiming_readiness(self):
        from kryptos.__main__ import doctor
        with patch("kryptos.__main__.platform.platform",return_value="test platform"),patch("kryptos.__main__.shutil.which",return_value="nvidia-smi"),patch("kryptos.__main__.subprocess.run",return_value=SimpleNamespace(returncode=0,stdout="test GPU")) as query:
            result=doctor()
        self.assertIn("optional compiled CUDA",result["execution"])
        self.assertIn("not compiled CUDA readiness",result["gpu"]["interpretation"])
        self.assertEqual(query.call_count,1)

    def test_both_public_cli_commands_execute_their_presets(self):
        for command in ("validate-holdout","validate-controls"):
            with self.subTest(command=command):
                completed=subprocess.run([sys.executable,"-B","-m","kryptos",command,"--request",f"examples/{command}.json"],
                    cwd=ROOT,capture_output=True,text=True,timeout=40,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
                self.assertEqual(completed.returncode,0,completed.stderr)
                result=json.loads(completed.stdout)
                self.assertEqual(result["command"],command)
                self.assertTrue(result["complete"])

    def test_holdout_labels_cannot_affect_fitting_or_ranking(self):
        request=example("validate-holdout")
        calls=[]
        def boundary(cipher,training,mask,bank,models,bounds,deadline):
            calls.append((dict(training),list(mask)))
            self.assertNotIn(4,training)
            self.assertNotIn(5,training)
            self.assertEqual(mask,[0,1,2,3,4,5])
            return select_family_bank(cipher,training,mask,bank,models,bounds,deadline)
        with patch("kryptos.validation_protocols.select_family_bank",side_effect=boundary):
            original=run_validation("validate-holdout",request)
            mutated=copy.deepcopy(request)
            mutated["cribs"][0]["text"]=mutated["cribs"][0]["text"][:4]+"ZZ"
            changed=run_validation("validate-holdout",mutated)
        self.assertEqual(calls[0],calls[1])
        self.assertEqual(original["selection"],changed["selection"])
        self.assertNotEqual(original["assessment"]["answers"],changed["assessment"]["answers"])
        self.assertTrue(original["complete"])
        self.assertGreater(original["assessment"]["evaluated_candidates_matching_all"],0)

    def test_controls_search_multiple_surviving_families_and_all_nulls(self):
        result=run_validation("validate-controls",example("validate-controls"))
        self.assertTrue(result["complete"])
        self.assertEqual(result["summary"]["candidate_visits"],2808)
        self.assertEqual(result["summary"]["completed_comparisons"],2)
        self.assertEqual(result["summary"]["nulls_with_surviving_wrong_candidates"],2)
        for pair in result["cases"]:
            for label in ("positive","null"):
                value=pair[label]
                selection=value["selection"]
                self.assertEqual([r["distinct_plaintext_count"] for r in selection["model_records"]],[26,676])
                self.assertTrue(all(r["complete"] and r["feasible"] for r in selection["model_records"]))
                self.assertTrue(value["assessment"]["truth_present_in_evaluated_candidates"])
                self.assertGreater(value["assessment"]["wrong_alternatives"],0)
                self.assertEqual(selection["best_selected_score"],max(c["selected_score"] for c in selection["candidates"]))
            self.assertTrue(pair["comparison"]["complete_comparison"])
            self.assertEqual(pair["comparison"]["null_best_minus_positive_best"],pair["null"]["selection"]["best_selected_score"]-pair["positive"]["selection"]["best_selected_score"])

    def test_censoring_is_not_a_success_or_comparison(self):
        request=example("validate-controls")
        request["max_candidates_per_family"]=25
        result=run_validation("validate-controls",request)
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["summary"]["completed_comparisons"],0)
        for pair in result["cases"]:
            self.assertIsNone(pair["comparison"]["null_best_minus_positive_best"])
            self.assertEqual(pair["positive"]["selection"]["evaluated"],0)

    def test_model_and_mask_comparability_validation(self):
        request=example("validate-controls")
        for delta in ({"model_paths":request["model_paths"]*2},{"crib_positions":[0,0]},
                      {"crib_positions":[100]}, {"time_limit_seconds":float("nan")},
                      {"model_bank":[request["model_bank"][0]]}):
            with self.assertRaises(ValueError): run_validation("validate-controls",dict(request,**delta))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"order2.json"
            path.write_text(train_ngram_model([CorpusDocument("ABRACADABRA","unit-test")],label="test",order=2).to_json())
            with self.assertRaises(ValueError):
                run_validation("validate-controls",dict(request,model_paths=request["model_paths"]+[str(path)]))
        changed=copy.deepcopy(request)
        changed["cases"][1]["plaintext"]=changed["cases"][1]["plaintext"][:-1]
        with self.assertRaises(ValueError): run_validation("validate-controls",changed)

    def test_actual_k4_mask_remains_distinct_from_authored_controls(self):
        from kryptos.data import K4_CIPHERTEXT,K4_CRIBS
        mask=[i for c in K4_CRIBS for i in range(c["start"]-1,c["start"]-1+len(c["text"]))]
        self.assertEqual(len(mask),24)
        self.assertNotEqual(mask,example("validate-controls")["crib_positions"])
        request=example("validate-holdout")
        request.update(target="k4",ciphertext=K4_CIPHERTEXT,cribs=K4_CRIBS,withheld_positions=list(range(63,74)),max_candidates_per_family=26)
        result=run_validation("validate-holdout",request)
        self.assertEqual(result["selection"]["score_mask"],sorted(mask))
        self.assertIn("retrospectively",result["holdout_caveat"])


if __name__=="__main__": unittest.main()
