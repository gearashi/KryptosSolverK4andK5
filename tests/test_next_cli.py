import unittest

from kryptos.__main__ import _target
from kryptos.next_cli import run_next


def run(command,request):
    return run_next(command,request,_target)


class NextCliTests(unittest.TestCase):
    def test_joint_full_and_partial_evidence(self):
        result=run("joint",{"ciphertext":"DKBIJHIFGN","cribs":[{"start":1,"text":"ABCDEFGHIJ"}],
            "period":2,"width":4,"order":"TS","alphabet":"standard"})
        self.assertTrue(result["complete"])
        self.assertTrue(result["candidates"])
        for row in result["candidates"]:
            self.assertTrue(row["evidence"]["literal_reencryption_matches"])
        partial=run("joint",{"ciphertext":"ABCDEFGH","cribs":[{"start":1,"text":"A"}],
            "period":3,"width":2,"alphabet":"standard"})
        self.assertTrue(any(c["plaintext"] is None for c in partial["candidates"]))

    def test_shared_schedule_cancellation_and_source_frame(self):
        p=[2,0,4,1,3]
        stages=[{"operation":"substitution","key_id":"same","key_length":2},
            {"operation":"gather","permutation":p},
            {"operation":"substitution","key_id":"same","key_length":2,"cipher":"variant",
             "schedule":{"kind":"row_reset","frame":"source"}}]
        result=run("scheduled",{"ciphertext":"CAEBD","cribs":[],"alphabet":"standard",
            "cells":[[0,i] for i in range(5)],"stages":stages})
        self.assertEqual(result["distinct_plaintext_count"],1)
        self.assertEqual(result["candidates"][0]["plaintext"],"ABCDE")
        self.assertEqual(result["phase_provenance"][0]["phase_map"],[0,0,0,1,1])
        self.assertTrue(result["candidates"][0]["evidence"]["literal_reencryption_matches"])

    def test_mixed_shared_letters_and_expanded_trace(self):
        stages=[{"operation":"substitution","key_id":"same","key_length":1,"alphabet":a}
            for a in ("ABCDEFGHIJKLMNOPQRSTUVWXYZ","BACDEFGHIJKLMNOPQRSTUVWXYZ")]
        result=run("mixed",{"ciphertext":"CADE","cribs":[{"start":1,"text":"ABCD"}],"stages":stages})
        self.assertTrue(result["complete"])
        self.assertTrue(result["candidates"])
        for row in result["candidates"]:
            self.assertEqual(row["plaintext"],"ABCD")
            self.assertEqual(len(row["evidence"]["stage_outputs"]),2)

    def test_lazy_optimizer_and_batch_candidates(self):
        request={"ciphertext":"TIITITATEDRFTUXU","cribs":[{"start":1,"text":"T"}],
            "alphabet":"standard","stages":[{"operation":"substitution","period":2}],
            "model_path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"}
        single=run("optimize-plus",request)
        self.assertTrue(single["optimization"]["search"]["optimal"])
        batch=run("batch",{"workers":2,"jobs":[{"id":"one","request":request}]})
        self.assertEqual(batch["jobs"][0]["optimization"]["candidate"]["plaintext"],
            single["optimization"]["candidate"]["plaintext"])
        self.assertTrue(batch["jobs"][0]["optimization"]["candidate"]["evidence"]["literal_reencryption_matches"])

    def test_unknown_and_missing_k5_inputs_rejected(self):
        for command in ("joint","scheduled","mixed","alphabet-plus","optimize-plus"):
            with self.assertRaises(ValueError):
                run(command,{"unknown":True})
            with self.assertRaises(ValueError):
                run(command,{"target":"k5"})


if __name__=="__main__":
    unittest.main()
