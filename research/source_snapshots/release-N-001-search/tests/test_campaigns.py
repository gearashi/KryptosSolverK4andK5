from pathlib import Path
import shutil
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from kryptos.app_jobs import RunManager
from kryptos.campaigns import CampaignManager,preview_campaign


def body():
    return {"kind":"accelerated","command":"optimize-plus","request":{"target":"custom",
        "ciphertext":"BCDEFG","cribs":[],"alphabet":"standard",
        "stages":[{"operation":"substitution","period":1}],
        "model_path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"},
        "backend":"cpu","workers":1,"batch_size":26,"max_batches":10,"time_limit_seconds":10}


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.research=Path(__file__).resolve().parents[1]/"research"
        self.folder=self.research/(".campaign-test-"+uuid.uuid4().hex)
        self.manager=RunManager(self.folder/"runs")
        self.campaign=CampaignManager(self.manager)

    def tearDown(self):
        self.campaign.close()
        self.manager.close()
        resolved=self.folder.resolve()
        assert resolved.parent==self.research.resolve() and resolved.name.startswith(".campaign-test-")
        # Windows scanners may briefly retain a file handle after child exit.
        deadline=time.monotonic()+2
        while True:
            try:
                shutil.rmtree(resolved)
                break
            except PermissionError:
                if time.monotonic()>=deadline:
                    raise
                time.sleep(.02)

    def wait(self):
        self.campaign.thread.join(timeout=15)
        self.assertFalse(self.campaign.thread.is_alive(),"bounded campaign did not finish")
        return self.campaign.view()

    def restart(self):
        self.campaign.close()
        self.manager.close()
        self.manager=RunManager(self.folder/"runs")
        self.campaign=CampaignManager(self.manager)

    @staticmethod
    def fake(key,job):
        offset=job["offset"]
        total=3 if job["request"]["stages"][0]["period"]==2 else 1
        end=min(total,offset+1)
        return {"feasible":True,"complete":end==total,"total":total,"next_offset":end,
                "evaluated":end-offset,"backend_used":"cpu","ranking_exact_within_page":True,
                "candidates":[{"plaintext":"AAAAAA","score_exact":"0x1","assignment_index_decimal":str(offset)}]}

    def test_twelve_job_preview_and_duplicate_requests(self):
        plan={"base":body(),"axes":[{"path":"request.stages.0.period","values":[1,2]},
            {"path":"request.stages.0.cipher","values":["vigenere","beaufort","variant"]},
            {"path":"request.alphabet","values":["standard","kryptos"]}]}
        result=preview_campaign(plan)
        self.assertEqual(result["job_count"],12)
        self.assertEqual(len({job["id"] for job in result["jobs"]}),12)
        self.assertEqual(preview_campaign({"base":body(),"axes":[{"path":"request.stages.0.period","values":[1,1]}]})["job_count"],1)
        with self.assertRaises(ValueError):
            preview_campaign({"base":body(),"axes":[{"path":"request.stages.0.period","values":list(range(32))},
                {"path":"request.alphabet","values":["standard"]*5}]})

    def test_pause_restart_skips_completed_jobs_and_reuses_child_frontier(self):
        entered,release=threading.Event(),threading.Event()
        calls=[]
        def launch(key,job):
            period=job["request"]["stages"][0]["period"]
            calls.append((period,job["offset"]))
            if period==2 and job["offset"]==0:
                entered.set()
                release.wait(5)
            return self.fake(key,job)
        plan={"base":body(),"axes":[{"path":"request.stages.0.period","values":[1,2,3]}]}
        with patch.object(self.manager,"_launch",side_effect=launch),patch.object(self.campaign,"_task",return_value={"eligible":False}):
            started=self.campaign.start(plan)
            self.assertTrue(entered.wait(5))
            self.campaign.control("pause",started["id"])
            # Let the campaign forward pause to the active run before releasing it.
            deadline=time.monotonic()+3
            while self.manager.desired!="pause" and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertEqual(self.manager.desired,"pause")
            release.set()
            paused=self.wait()
        self.assertEqual(paused["state"],"paused",paused.get("error"))
        self.assertEqual(paused["jobs"][0]["state"],"completed")
        saved_child=paused["jobs"][1]["run_id"]
        self.restart()
        with patch.object(self.manager,"_launch",side_effect=launch),patch.object(self.campaign,"_task",return_value={"eligible":False}):
            self.campaign.control("resume",started["id"])
            complete=self.wait()
        self.assertEqual(complete["state"],"completed",complete.get("error"))
        self.assertEqual(complete["jobs"][1]["run_id"],saved_child)
        self.assertEqual(calls,[(1,0),(2,0),(2,1),(2,2),(3,0)])

    def test_reserved_child_id_recovers_both_sides_of_dispatch_gap(self):
        for child_exists in (False,True):
            with self.subTest(child_exists=child_exists):
                with patch.object(self.campaign,"_begin"):
                    started=self.campaign.start({"base":body(),"axes":[]})
                record=self.campaign.records[started["id"]]
                reserved=uuid.uuid4().hex
                record["jobs"][0]["run_id"]=reserved
                record["jobs"][0]["family_identity"]={"eligible":False}
                self.campaign._save(record)
                if child_exists:
                    with patch.object(self.manager,"_launch",side_effect=self.fake):
                        self.manager.start(body(),run_id=reserved)
                        self.manager.thread.join(timeout=5)
                    self.assertEqual(self.manager.view()["state"],"completed")
                self.restart()
                with patch.object(self.manager,"_launch",side_effect=self.fake) as worker:
                    self.campaign.control("resume",started["id"])
                    complete=self.wait()
                self.assertEqual(complete["state"],"completed",complete.get("error"))
                self.assertEqual(complete["jobs"][0]["run_id"],reserved)
                self.assertEqual(worker.call_count,0 if child_exists else 1)

    def test_real_equivalent_family_scans_once_and_replays_other_recipe(self):
        result=self.campaign.start({"base":body(),"axes":[{"path":"request.stages.0.cipher","values":["vigenere","variant"]}]})
        complete=self.wait()
        self.assertEqual(complete["state"],"completed",complete.get("error"))
        self.assertEqual([j["state"] for j in complete["jobs"]],["completed","equivalent"])
        self.assertEqual(len(self.manager.records),1)
        alias=complete["jobs"][1]
        self.assertEqual(alias["alias_of"],complete["jobs"][0]["id"])
        self.assertTrue(alias["candidates"])
        self.assertTrue(all(c["evidence"]["literal_reencryption_matches"] for c in alias["candidates"]))
        self.assertFalse(complete["authenticated_solution"])


if __name__=="__main__":
    unittest.main()
