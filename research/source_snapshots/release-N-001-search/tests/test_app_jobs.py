import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from kryptos.app_jobs import RunManager,validate_start,atomic_json


def body(**changes):
    value={"kind":"accelerated","command":"optimize-plus","request":{
        "target":"custom","ciphertext":"BCDEFG","cribs":[],"alphabet":"standard",
        "stages":[{"operation":"substitution","period":1}],
        "model_path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"},
        "backend":"cpu","workers":2,"batch_size":3,"max_batches":1,"time_limit_seconds":10}
    value.update(changes)
    return value


def wait(manager,timeout=10):
    manager.thread.join(timeout=timeout)
    if manager.thread.is_alive():
        raise AssertionError("bounded test job did not finish")
    return manager.view()


class AppJobsTests(unittest.TestCase):
    def setUp(self):
        self.folder=Path("research")/(".app-test-"+uuid.uuid4().hex)
        self.manager=RunManager(self.folder/"runs")

    def tearDown(self):
        self.manager.close()
        # A unique, literal test directory under the workspace only.
        folder=self.folder.resolve()
        research=Path(__file__).resolve().parents[1]/"research"
        assert folder.parent==research and folder.name.startswith(".app-test-")
        shutil.rmtree(folder)

    def fake(self,key,job):
        start=job["offset"]
        end=min(8,start+job["batch_size"])
        return {"next_offset":end,"total":8,"backend_used":"cpu","evaluated":end-start,
            "ranking_exact_within_page":True,
            "candidates":[{"plaintext":chr(65+i)*6,"score_exact":hex(i+1),"assignment_index_decimal":str(i)} for i in range(start,end)]}

    def test_exclusive_directory_ownership_and_release(self):
        with self.assertRaisesRegex(RuntimeError,"already owned"):
            RunManager(self.folder/"runs")
        self.manager.close()
        replacement=RunManager(self.folder/"runs")
        try:
            with self.assertRaisesRegex(RuntimeError,"already owned"):
                RunManager(self.folder/"runs")
            with self.assertRaisesRegex(ValueError,"closed"):
                self.manager.start(body())
        finally:
            replacement.close()

    def test_process_lock_rejects_other_process_and_has_no_stale_owner(self):
        code="""import os,sys
from kryptos.app_jobs import RunManager
try:
    manager=RunManager(sys.argv[1])
except RuntimeError as error:
    print(str(error))
    sys.exit(23)
os._exit(0)
"""
        argv=[sys.executable,"-c",code,str((self.folder/"runs").resolve())]
        options={"cwd":Path(__file__).resolve().parents[1],"capture_output":True,"text":True,"timeout":10,
                 "creationflags":subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0}
        blocked=subprocess.run(argv,**options)
        self.assertEqual(blocked.returncode,23,blocked.stderr)
        self.assertIn("already owned",blocked.stdout)
        self.manager.close()
        crashed=subprocess.run(argv,**options)
        self.assertEqual(crashed.returncode,0,crashed.stderr)
        # The child deliberately omitted close; process termination releases the lock.
        replacement=RunManager(self.folder/"runs")
        replacement.close()

    def test_initial_save_failure_does_not_publish_a_phantom_run(self):
        for failure in (OSError("control disk failure"),ValueError("control JSON failure")):
            with self.subTest(failure=type(failure).__name__):
                with patch("kryptos.app_jobs.atomic_json",side_effect=failure), patch.object(self.manager,"_begin") as begin:
                    with self.assertRaises(type(failure)):
                        self.manager.start(body())
                self.assertEqual(self.manager.records,{})
                self.assertIsNone(self.manager.current)
                self.assertIsNone(self.manager.thread)
                self.assertIsNone(self.manager.view())
                begin.assert_not_called()

    def test_resume_save_failure_preserves_state_and_current_selection(self):
        with patch.object(self.manager,"_launch",side_effect=self.fake):
            first=self.manager.start(body())
            wait(self.manager)
            second=self.manager.start(body())
            wait(self.manager)
        before=self.manager.view(first["id"])
        path=self.folder/"runs"/first["id"]/"run.json"
        saved=path.read_bytes()
        for failure in (OSError("control disk failure"),ValueError("control JSON failure")):
            with self.subTest(failure=type(failure).__name__):
                with patch("kryptos.app_jobs.atomic_json",side_effect=failure), patch.object(self.manager,"_begin") as begin:
                    with self.assertRaises(type(failure)):
                        self.manager.control("resume",first["id"])
                self.assertEqual(self.manager.view(first["id"]),before)
                self.assertEqual(self.manager.current,second["id"])
                self.assertEqual(path.read_bytes(),saved)
                begin.assert_not_called()

    def test_pause_or_stop_save_failure_does_not_queue_a_control(self):
        for action in ("pause","stop"):
            with self.subTest(action=action):
                entered=threading.Event()
                release=threading.Event()
                def launch(key,job):
                    entered.set()
                    release.wait(3)
                    return self.fake(key,job)
                with patch.object(self.manager,"_launch",side_effect=launch):
                    run=self.manager.start(body())
                    self.assertTrue(entered.wait(2))
                    before=self.manager.view()
                    path=self.folder/"runs"/run["id"]/"run.json"
                    saved=path.read_bytes()
                    try:
                        with patch("kryptos.app_jobs.atomic_json",side_effect=OSError("control save failure")):
                            with self.assertRaisesRegex(OSError,"control save failure"):
                                self.manager.control(action,run["id"])
                        self.assertEqual(self.manager.view(),before)
                        self.assertIsNone(self.manager.desired)
                        self.assertEqual(path.read_bytes(),saved)
                    finally:
                        release.set()
                    result=wait(self.manager)
                self.assertEqual(result["state"],"limited")
                self.assertEqual(result["progress"]["completed"],3)

    def test_algebra_budget_preserves_result_without_committing(self):
        result={"feasible":None,"total":None,"total_decimal":None,"next_offset":0,
                "complete":False,"stop_reason":"algebra_budget","evaluated":0,"candidates":[],
                "algebra":{"bounds":{"max_operations":1},"detail":"control budget"},"model_id":"fixture"}
        with patch.object(self.manager,"_launch",return_value=result):
            self.manager.start(body())
            value=wait(self.manager)
        self.assertEqual(value["state"],"limited")
        self.assertIsNone(value["result"]["feasible"])
        self.assertEqual(value["result"]["algebra"],result["algebra"])
        self.assertEqual(value["result"]["model_id"],"fixture")
        self.assertEqual(value["progress"]["completed"],0)
        self.assertIsNone(value["progress"]["total"])
        self.assertEqual(value["batches_committed"],0)
        self.assertTrue(value["can_resume"])
        self.assertIn("unchanged bounds",value["error"])

    def test_active_source_changes_fail_before_launch_or_commit(self):
        for when in ("before","during"):
            with self.subTest(when=when):
                calls=[]
                mutated=[False]
                def identity(request):
                    calls.append(1)
                    return {"fixture":"changed" if mutated[0] or (when=="before" and len(calls)>1) else "original"}
                def launch(key,job):
                    mutated[0]=True
                    return self.fake(key,job)
                with patch("kryptos.app_jobs.source_identity",side_effect=identity), patch.object(self.manager,"_launch",side_effect=launch) as worker:
                    self.manager.start(body())
                    value=wait(self.manager)
                self.assertEqual(value["state"],"failed")
                self.assertEqual(value["progress"]["completed"],0)
                self.assertEqual(value["batches_committed"],0)
                self.assertIn("changed",value["error"])
                self.assertEqual(worker.call_count,0 if when=="before" else 1)

    def test_aggregate_ranking_stays_approximate_after_exact_tail(self):
        def launch(key,job):
            result=self.fake(key,job)
            result.update(backend_used="cuda" if job["offset"]==0 else "cpu",
                          ranking_exact_within_page=job["offset"]!=0)
            if job["offset"]:
                result["fallback_reason"]="test fallback"
            return result
        with patch.object(self.manager,"_launch",side_effect=launch):
            self.manager.start(body(max_batches=5))
            value=wait(self.manager)
        self.assertEqual(value["state"],"completed")
        self.assertTrue(value["result"]["ranking_exact_within_page"])
        self.assertFalse(value["ranking_exact_over_committed_pages"])
        self.assertEqual(value["backends_used"],["cpu","cuda"])
        self.assertEqual(value["fallback_reasons"],["test fallback"])
        self.assertEqual(value["progress"]["completed"],8)

    def test_mismatched_worker_identity_is_not_committed(self):
        result=self.fake("unused",{"offset":0,"batch_size":3})
        result["source_sha256"]={"wrong.py":"wrong"}
        with patch.object(self.manager,"_launch",return_value=result):
            self.manager.start(body())
            value=wait(self.manager)
        self.assertEqual(value["state"],"failed")
        self.assertEqual(value["progress"]["completed"],0)
        self.assertIn("identity",value["error"])

    def test_saved_frontier_resumes_disjoint_pages_and_global_top(self):
        with patch.object(self.manager,"_launch",side_effect=self.fake):
            started=self.manager.start(body(note="Explicit control input"))
            first=wait(self.manager)
            self.assertEqual((first["state"],first["progress"]["completed"]),("limited",3))
            self.manager.control("resume",started["id"])
            second=wait(self.manager)
            self.assertEqual(second["progress"]["completed"],6)
            self.manager.control("resume",started["id"])
            final=wait(self.manager)
            self.assertEqual(final["state"],"completed")
            self.assertEqual(final["progress"]["completed"],8)
            self.assertEqual(len(final["candidates"]),8)
            self.assertEqual(final["candidates"][0]["plaintext"],"HHHHHH")
            self.assertEqual(final["note"],"Explicit control input")
        self.manager.close()
        restored=RunManager(self.folder/"runs")
        try:
            self.assertEqual(restored.view()["candidates"],final["candidates"])
        finally:
            restored.close()

    def test_pause_commits_inflight_page_then_releases_work(self):
        entered=threading.Event()
        release=threading.Event()
        def delayed(key,job):
            entered.set()
            release.wait(2)
            return self.fake(key,job)
        with patch.object(self.manager,"_launch",side_effect=delayed):
            started=self.manager.start(body(max_batches=10))
            self.assertTrue(entered.wait(2))
            self.manager.control("pause",started["id"])
            release.set()
            result=wait(self.manager)
            self.assertEqual((result["state"],result["progress"]["completed"]),("paused",3))

    def test_error_does_not_advance_frontier_and_source_change_rejects_resume(self):
        with patch.object(self.manager,"_launch",side_effect=RuntimeError("control failure")):
            started=self.manager.start(body())
            result=wait(self.manager)
            self.assertEqual(result["state"],"failed")
            self.assertEqual(result["progress"]["completed"],0)
        with patch("kryptos.app_jobs.source_identity",return_value={"changed":True}):
            with self.assertRaisesRegex(ValueError,"changed"):
                self.manager.control("resume",started["id"])

    def test_restart_marks_abandoned_running_job_interrupted(self):
        with patch.object(self.manager,"_launch",side_effect=self.fake):
            self.manager.start(body())
            record=wait(self.manager)
        record["state"]="running"
        record.pop("ranking_exact_over_committed_pages")
        atomic_json(self.folder/"runs"/record["id"]/"run.json",record)
        self.manager.close()
        restored=RunManager(self.folder/"runs")
        try:
            self.assertEqual(restored.view()["state"],"interrupted")
            self.assertEqual(restored.view()["progress"]["completed"],3)
            self.assertFalse(restored.view()["ranking_exact_over_committed_pages"])
        finally:
            restored.close()

    def test_invalid_or_untrusted_inputs_rejected_before_launch(self):
        for extra in ({"workers":True},{"backend":"remote"},{"max_batches":0},{"note":"x"*1001}):
            with self.assertRaises(ValueError):
                validate_start(body(**extra))
        for field,value in (("model_path","C:/private.json"),("checkpoint_path","out.json"),("max_nodes",10000001)):
            request=body()
            request["request"][field]=value
            with self.assertRaises(ValueError):
                validate_start(request)
        request=body()
        request["request"]={"target":"k5"}
        with self.assertRaises(ValueError):
            validate_start(request)

    def test_real_exact_worker_and_cpu_scan_replay(self):
        request={"kind":"exact","command":"joint","request":{"target":"custom","ciphertext":"DKBIJHIFGN",
            "cribs":[{"start":1,"text":"ABCDEFGHIJ"}],"period":2,"width":4,"order":"TS","alphabet":"standard"}}
        self.manager.start(request)
        result=wait(self.manager,timeout=30)
        self.assertEqual(result["state"],"completed",result["error"])
        self.assertTrue(result["candidates"][0]["evidence"]["literal_reencryption_matches"])
        # Two cold interpreter starts in a newly exported Windows checkout can
        # exceed10s. This checks26 exact candidates, not startup performance.
        request=body(max_batches=2,batch_size=13,time_limit_seconds=30)
        self.manager.start(request)
        result=wait(self.manager,timeout=30)
        self.assertEqual(result["state"],"completed",result["error"])
        self.assertEqual(result["progress"]["completed"],26)
        self.assertTrue(all(c["evidence"]["literal_reencryption_matches"] for c in result["candidates"]))


if __name__=="__main__":
    unittest.main()
