from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock,patch

from kryptos.worker_pool import PersistentWorkerPool,WorkerCancelled,WorkerFailure,source_fingerprint,retry_file


class WorkerPoolTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).resolve().parents[1]
        self.parent=self.root/"research/manual-checks"
        self.temp=tempfile.TemporaryDirectory(prefix="worker-test-",dir=self.parent)
        self.pool=PersistentWorkerPool(2,folder=self.temp.name)

    def tearDown(self):
        # Observe the actual Job Object query used by close, so a file-sharing
        # retry cannot hide a worker still running or skipped owner cleanup.
        observed=[]
        with ExitStack() as patches:
            for slot in self.pool._slots:
                process=slot.process
                if process is not None and hasattr(process,"active_processes"):
                    counts=[]
                    original=process.active_processes
                    def count(original=original,counts=counts):
                        active=original()
                        counts.append(active)
                        return active
                    patches.enter_context(patch.object(process,"active_processes",side_effect=count))
                    observed.append((process,counts))
            self.pool.close()
        for process,counts in observed:
            self.assertTrue(counts,"close did not verify owned descendants")
            self.assertEqual(counts[-1],0,"owned descendants remain alive")
            self.assertIsNone(process.job)
            self.assertIsNone(process.process)
        resolved=Path(self.temp.name).resolve()
        assert resolved.is_relative_to(self.parent.resolve()) and resolved.name.startswith("worker-test-")
        # Kernel/AV handles may briefly outlive terminated processes on Windows.
        # Only retry after the live-owner assertions above have succeeded.
        retry_file(self.temp.cleanup)

    def test_reuses_processes_and_dispatches_concurrently(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results=list(executor.map(lambda _:self.pool.execute({"kind":"ping"}),range(8)))
        self.assertEqual(len({r["pid"] for r in results}),2)
        self.assertEqual(sum(s.generation for s in self.pool._slots),2)
        self.assertTrue(all(r["protocol"]=="kryptos.private-worker.v1" for r in results))

    def test_dead_child_restarts_and_bad_job_does_not_poison_pool(self):
        self.pool.close()
        self.pool=PersistentWorkerPool(1,folder=self.temp.name)
        first=self.pool.execute({"kind":"ping"})
        slot=self.pool._slots[0]
        slot.process.kill()
        slot.process.wait(timeout=5)
        second=self.pool.execute({"kind":"ping"})
        self.assertNotEqual(first["pid"],second["pid"])
        with self.assertRaises(WorkerFailure):
            self.pool.execute({"kind":"exact","command":"not-a-command","request":{}})
        self.assertIn("pid",self.pool.execute({"kind":"ping"}))

    def test_cancel_timeout_and_reuse(self):
        with self.assertRaises(WorkerCancelled):
            self.pool.execute({"kind":"ping"},cancel=lambda:True)
        with self.assertRaises(TimeoutError):
            self.pool.execute({"kind":"ping"},timeout=0.000001)
        self.assertIn("pid",self.pool.execute({"kind":"ping"}))

    def test_cancel_active_job_kills_worker_before_reuse(self):
        self.pool.close()
        self.pool=PersistentWorkerPool(1,folder=self.temp.name)
        self.pool.execute({"kind":"ping"})
        old=self.pool._slots[0].process
        # Trigger precisely when a response wait begins, after launch/send.
        original=self.pool._read
        event=threading.Event()
        def read(slot,path,cancel,deadline):
            if path.name=="response.json":
                event.set()
            return original(slot,path,cancel,deadline)
        with patch.object(self.pool,"_read",side_effect=read),self.assertRaises(WorkerCancelled):
            self.pool.execute({"kind":"ping"},cancel=event.is_set)
        self.assertIsNotNone(old.poll())
        self.assertNotEqual(old.pid,self.pool.execute({"kind":"ping"})["pid"])

    def test_stale_source_result_is_rejected_without_editing_files(self):
        self.pool.close()
        self.pool=PersistentWorkerPool(1,folder=self.temp.name)
        self.pool.execute({"kind":"ping"})
        altered=dict(source_fingerprint(),**{"fake-audit-source.py":"0"*64})
        with patch("kryptos.worker_pool.source_fingerprint",return_value=altered),self.assertRaisesRegex(WorkerFailure,"sources changed"):
            self.pool.execute({"kind":"ping"})
        self.assertIn("pid",self.pool.execute({"kind":"ping"}))

    def test_close_and_invalid_input(self):
        for timeout in (True,0,float("nan"),float("inf")):
            with self.assertRaises(ValueError):
                self.pool.execute({"kind":"ping"},timeout=timeout)
        self.pool.close()
        with self.assertRaises(WorkerCancelled):
            self.pool.execute({"kind":"ping"})

    def test_file_retry_is_bounded_and_does_not_retry_other_errors(self):
        with patch("time.sleep"):
            operation=Mock(side_effect=[PermissionError("sharing"),PermissionError("sharing"),42])
            self.assertEqual(retry_file(operation),42)
            self.assertEqual(operation.call_count,3)
        with self.assertRaises(PermissionError):
            retry_file(lambda:(_ for _ in ()).throw(PermissionError("persistent denial")),timeout=0)
        with self.assertRaises(FileNotFoundError):
            retry_file(lambda:(_ for _ in ()).throw(FileNotFoundError("missing")))

    @unittest.skipUnless(os.name=="nt","Windows Job Object ownership")
    def test_redirected_interpreter_is_owned_and_killed_with_launcher(self):
        self.pool.close()
        self.pool=PersistentWorkerPool(1,folder=self.temp.name)
        ready=self.pool.execute({"kind":"ping"})
        process=self.pool._slots[0].process
        self.assertGreaterEqual(process.active_processes(),1)
        if ready["pid"]!=process.pid:
            self.assertGreaterEqual(process.active_processes(),2)
        process.terminate()
        process.wait(timeout=3)
        deadline=time.monotonic()+3
        while process.active_processes() and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertEqual(process.active_processes(),0)
        self.assertIn("pid",self.pool.execute({"kind":"ping"}))


if __name__=="__main__":
    unittest.main()
