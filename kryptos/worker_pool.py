"""Hidden persistent processes with atomic file messages, no multiprocessing pipes."""
from collections import deque
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid


class WorkerCancelled(InterruptedError):
    pass


class WorkerFailure(RuntimeError):
    pass


def source_fingerprint():
    root = Path(__file__).resolve().parent
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))}


def retry_file(operation,timeout=2):
    """Retry only transient Windows sharing/access failures, never a job itself."""
    deadline=time.monotonic()+timeout
    while True:
        try:
            return operation()
        except OSError as error:
            if not (isinstance(error,PermissionError) or getattr(error,"winerror",None) in (5,32,33)) or time.monotonic()>=deadline:
                raise
            time.sleep(.015)


def atomic_message(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
        retry_file(lambda:os.replace(temporary,path))
    finally:
        retry_file(lambda:temporary.unlink(missing_ok=True))


class _Slot:
    def __init__(self, folder):
        self.folder = folder
        self.process = None
        self.stderr = None
        self.generation = 0


class PersistentWorkerPool:
    """Thread-safe pool of1..4 serial workers; timeout includes queue/startup.

    A unique subdirectory is created beneath folder. env overlays the current
    environment; cwd defaults to the repository. Returned wire-format decimal
    wrappers are decoded to native integers. The caller owns durable commits.
    """
    def __init__(self, size, python=None, env=None, cwd=None, folder=None):
        if type(size) is not int or not 1 <= size <= 4:
            raise ValueError("pool size must be in1..4")
        if folder is None:
            raise ValueError("an explicit private worker folder is required")
        self.python = str(python or sys.executable)
        self.cwd = str(Path(cwd or Path(__file__).resolve().parents[1]).resolve())
        self.env = dict(os.environ, **(env or {}))
        self.folder = Path(folder).resolve()/("pool-" + uuid.uuid4().hex)
        self.folder.mkdir(parents=True)
        self._slots = [_Slot(self.folder/str(i)) for i in range(size)]
        for slot in self._slots:
            slot.folder.mkdir()
        self._condition = threading.Condition()
        self._available = deque(self._slots)
        self._closed = False

    @staticmethod
    def _discard(slot):
        process = slot.process
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.close()
            slot.process = None
        if slot.stderr is not None:
            slot.stderr.close()
            slot.stderr = None
        for name in ("request.json", "response.json", "ready.json"):
            retry_file(lambda: (slot.folder/name).unlink(missing_ok=True))

    def _check(self, cancel, deadline):
        if self._closed:
            raise WorkerCancelled("worker pool is closed")
        if cancel is not None and cancel():
            raise WorkerCancelled("worker job cancelled before commit")
        if time.monotonic() >= deadline:
            raise TimeoutError("persistent worker job exceeded its wall timeout")

    def _read(self, slot, path, cancel, deadline):
        while True:
            self._check(cancel, deadline)
            if path.exists():
                if path.stat().st_size > 128*1024*1024:
                    raise WorkerFailure("worker response exceeds128MiB")
                return json.loads(retry_file(lambda:path.read_text(encoding="utf-8")))
            if slot.process.poll() is not None:
                error_path = slot.folder/"stderr.log"
                tail = error_path.read_bytes()[-4096:].decode("utf-8", errors="replace") if error_path.exists() else ""
                raise WorkerFailure(f"worker exited with code{slot.process.returncode}: {tail}")
            time.sleep(0.015)

    def _start(self, slot, cancel, deadline):
        if slot.process is not None and slot.process.poll() is None:
            return
        self._discard(slot)
        slot.generation += 1
        slot.stderr = (slot.folder/"stderr.log").open("wb")
        options = {"cwd": self.cwd, "env": self.env, "stdin": subprocess.DEVNULL,
                   "stdout": subprocess.DEVNULL, "stderr": slot.stderr}
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        from .process_lifetime import launch_owned
        slot.process = launch_owned([self.python, "-B", "-m", "kryptos.app_worker",
                                         "--persistent", str(slot.folder)], **options)
        ready = self._read(slot, slot.folder/"ready.json", cancel, deadline)
        if ready.get("source_sha256") != source_fingerprint():
            raise WorkerFailure("worker sources changed during startup")

    def execute(self, job, cancel=None, timeout=60):
        if not isinstance(job, dict):
            raise ValueError("worker job must be an object")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        encoded = json.loads(json.dumps(job, allow_nan=False))
        deadline = time.monotonic()+timeout
        slot = None
        try:
            with self._condition:
                while not self._available:
                    self._check(cancel, deadline)
                    self._condition.wait(min(0.05, max(0.001, deadline-time.monotonic())))
                self._check(cancel, deadline)
                slot = self._available.popleft()
            self._start(slot, cancel, deadline)
            self._check(cancel, deadline)
            request_id = uuid.uuid4().hex
            identity = source_fingerprint()
            response_path = slot.folder/"response.json"
            retry_file(lambda:response_path.unlink(missing_ok=True))
            atomic_message(slot.folder/"request.json", {"id": request_id, "job": encoded, "source_sha256": identity})
            response = self._read(slot, response_path, cancel, deadline)
            self._check(cancel, deadline)
            if response.get("id") != request_id:
                raise WorkerFailure("worker response identifier mismatch")
            if response.get("source_sha256") != identity or source_fingerprint() != identity:
                raise WorkerFailure("worker sources changed while executing; result discarded")
            retry_file(lambda:response_path.unlink(missing_ok=True))
            if not response.get("ok"):
                raise WorkerFailure(response.get("error", "worker returned an unspecified failure"))
            from .parallel_search import _decode
            return _decode(response["result"])
        except BaseException:
            if slot is not None:
                self._discard(slot)
            raise
        finally:
            if slot is not None:
                with self._condition:
                    if self._closed:
                        self._discard(slot)
                    self._available.append(slot)
                    self._condition.notify_all()

    def close(self):
        # Active calls own their cleanup. Killing their child wakes the read loop.
        with self._condition:
            self._closed = True
            idle = set(self._available)
            for slot in self._slots:
                if slot in idle:
                    self._discard(slot)
                elif slot.process is not None and slot.process.poll() is None:
                    slot.process.terminate()
            self._condition.notify_all()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
