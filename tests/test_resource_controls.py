"""Transactional page-boundary controls, with deterministic fake worker pages."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from kryptos.app_jobs import RunManager, atomic_json
from kryptos.resource_governor import MAX_EVENTS, next_batch_size, validate_resources


def body(**changes):
    value={"kind":"accelerated","command":"optimize-plus","request":{
        "target":"custom","ciphertext":"BCDEFG","cribs":[],"alphabet":"standard",
        "stages":[{"operation":"substitution","period":1}],
        "model_path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"},
        "backend":"cpu","workers":1,"batch_size":3,"max_batches":20,"time_limit_seconds":10}
    value.update(changes)
    return value


def page(job,total=29):
    start=job["offset"]
    end=min(total,start+job["batch_size"])
    return {"next_offset":end,"total":total,"backend_used":"cpu","evaluated":end-start,
            "ranking_exact_within_page":True,"feasible":True,
            "candidates":[{"plaintext":"P"+str(start),"score_exact":hex(start+1),"assignment_index_decimal":str(start)}]}


class ResourceControlsTests(unittest.TestCase):
    def setUp(self):
        parent=Path(__file__).resolve().parents[1]/"research/manual-checks"
        self.temp=tempfile.TemporaryDirectory(dir=parent,prefix="resources-")
        self.manager=RunManager(Path(self.temp.name)/"runs")
        self.identity=patch("kryptos.app_jobs.source_identity",return_value={"fixture":"stable"})
        self.identity.start()
        self.pool=patch.object(self.manager,"_ensure_pool")
        self.pool.start()

    def tearDown(self):
        self.manager.close()
        self.pool.stop()
        self.identity.stop()
        self.temp.cleanup()

    def finish(self):
        self.manager.thread.join(timeout=5)
        self.assertFalse(self.manager.thread.is_alive(),"controlled fake workers did not terminate")
        return self.manager.view()

    def test_pending_controls_apply_at_boundary_and_adaptation_preserves_contiguous_coverage(self):
        entered,release=threading.Event(),threading.Event()
        calls=[]
        def launch(key,job):
            calls.append((job["offset"],job["batch_size"]))
            if job["offset"]==0:
                entered.set()
                if not release.wait(3): raise RuntimeError("test barrier expired")
            return page(job)
        with patch.object(self.manager,"_launch",side_effect=launch), patch("kryptos.app_jobs.next_batch_size",side_effect=lambda size,*_:min(8192,size*2)):
            run=self.manager.start(body())
            self.assertTrue(entered.wait(2))
            try:
                queued=self.manager.update_resources(run["id"],{"workers":3,"adaptive":True,"idle_ms":0})
                self.assertEqual(queued["settings"]["workers"],1)
                self.assertEqual(queued["pending_resources"]["workers"],3)
                self.assertEqual(queued["progress"]["completed"],0)
            finally: release.set()
            final=self.finish()
        self.assertEqual(sorted(calls),[(0,3),(3,3),(6,3),(9,3),(12,6),(18,6),(24,6)])
        coverage=[]
        for start,size in calls: coverage.extend(range(start,min(29,start+size)))
        self.assertEqual(sorted(coverage),list(range(29)))
        self.assertEqual(final["state"],"completed")
        self.assertEqual(final["progress"]["completed"],29)
        self.assertEqual(final["resource_events"][0]["offset_decimal"],"3")
        self.assertEqual(final["resource_events"][0]["reason"],"user")
        self.assertEqual(final["resource_events"][1]["offset_decimal"],"12")
        self.assertEqual(final["batches_committed"],7)

    def test_stop_after_worker_return_before_commit_discards_entire_wave(self):
        entered,release=threading.Event(),threading.Event()
        def launch(key,job):
            if job["offset"]>=3:
                entered.set()
                if not release.wait(3): raise RuntimeError("test barrier expired")
            return page(job,12)
        with patch.object(self.manager,"_launch",side_effect=launch):
            run=self.manager.start(body(workers=2))
            self.assertTrue(entered.wait(2))
            try:
                self.manager.control("stop",run["id"])
            finally: release.set()
            final=self.finish()
        self.assertEqual(final["state"],"stopped")
        self.assertEqual(final["progress"]["completed"],3)
        self.assertEqual(final["batches_committed"],1)
        self.assertEqual([c["plaintext"] for c in final["candidates"]],["P0"])
        disk=json.loads((self.manager.directory/run["id"]/"run.json").read_text())
        self.assertEqual(disk["progress"]["completed"],3)

    def test_failed_commit_does_not_advance_exact_or_scan_memory(self):
        for kind in ("accelerated","exact"):
            with self.subTest(kind=kind):
                with patch.object(self.manager,"_begin"):
                    run=self.manager.start(body(kind=kind))
                def fail_progress(path,value):
                    if value.get("progress",{}).get("completed",0)>0:
                        raise OSError("intentional commit failure")
                    atomic_json(path,value)
                result=page({"offset":0,"batch_size":3}) if kind=="accelerated" else {"candidates":[{"plaintext":"ABCDEF"}]}
                with patch.object(self.manager,"_launch",return_value=result),patch("kryptos.app_jobs.atomic_json",side_effect=fail_progress):
                    try: self.manager._run(run["id"])
                    except OSError: pass  # A final status save may also fail; frontier must still be unchanged.
                final=self.manager.view(run["id"])
                self.assertEqual(final["progress"]["completed"],0)
                self.assertEqual(final["batches_committed"],0)
                self.assertEqual(final["candidates"],[])
                disk=json.loads((self.manager.directory/run["id"]/"run.json").read_text())
                self.assertEqual(disk["progress"]["completed"],0)

    def test_resource_queue_and_boundary_save_failures_preserve_memory(self):
        with patch.object(self.manager,"_begin"):
            run=self.manager.start(body())
        before=self.manager.view()
        with patch("kryptos.app_jobs.atomic_json",side_effect=OSError("queue save")):
            with self.assertRaises(OSError): self.manager.update_resources(run["id"],{"workers":2})
        self.assertEqual(self.manager.view(),before)
        self.manager.update_resources(run["id"],{"workers":2})
        record=self.manager.records[run["id"]]
        before=copy.deepcopy(record)
        with patch("kryptos.app_jobs.atomic_json",side_effect=OSError("boundary save")):
            with self.assertRaises(OSError): self.manager._resource_boundary(record)
        self.assertEqual(record,before)

    def test_pending_user_update_reserves_last_resource_history_slot(self):
        with patch.object(self.manager,"_begin"):
            run=self.manager.start(body(adaptive=True))
        record=self.manager.records[run["id"]]
        record["resource_events"]=[{"reason":"prior"} for _ in range(MAX_EVENTS-1)]
        def launch(key,job):
            if job["offset"]==0:
                self.manager.update_resources(key,{"adaptive":False})
            return page(job,8)
        with patch.object(self.manager,"_launch",side_effect=launch),patch("kryptos.app_jobs.next_batch_size",return_value=6):
            self.manager._run(run["id"])
        final=self.manager.view()
        self.assertLessEqual(len(final["resource_events"]),MAX_EVENTS)
        self.assertFalse(final["settings"]["adaptive"])
        self.assertFalse(final["pending_resources"])

    def test_closed_manager_cannot_write_resources_after_releasing_ownership(self):
        with patch.object(self.manager,"_begin"):
            run=self.manager.start(body())
        self.manager.close()
        with patch.object(self.manager,"_save") as save:
            with self.assertRaisesRegex(ValueError,"closed"):
                self.manager.update_resources(run["id"],{"workers":2})
            save.assert_not_called()

    def test_failed_pool_shutdown_retains_directory_ownership_until_retry(self):
        class ControlledPool:
            fail = True
            calls = 0
            def close(pool):
                pool.calls += 1
                if pool.fail:
                    raise RuntimeError("owned worker is still alive")
        controlled = ControlledPool()
        self.manager.pool = controlled
        with self.assertRaisesRegex(RuntimeError, "still alive"):
            self.manager.close()
        self.assertIs(self.manager.pool, controlled)
        with self.assertRaisesRegex(RuntimeError, "already owned"):
            RunManager(self.manager.directory)
        controlled.fail = False
        self.manager.close()
        self.assertEqual(controlled.calls, 2)
        self.assertIsNone(self.manager.pool)
        replacement = RunManager(self.manager.directory)
        replacement.close()

    def test_resource_limits_and_hysteresis(self):
        for values in ({"workers":True},{"workers":5},{"idle_ms":-1},{"adaptive":1},{"target_page_seconds":float("nan")}):
            with self.assertRaises(ValueError): validate_resources(values)
        with self.assertRaises(ValueError): validate_resources({"workers":2},"cuda")
        self.assertEqual(next_batch_size(100,1.1,1),100)
        self.assertEqual(next_batch_size(100,10,1),50)
        self.assertEqual(next_batch_size(100,.01,1),200)
        self.assertEqual(next_batch_size(8192,.01,1),8192)


if __name__=="__main__": unittest.main()
