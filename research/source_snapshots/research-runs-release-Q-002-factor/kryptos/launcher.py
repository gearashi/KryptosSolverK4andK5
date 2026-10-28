"""Local server discovery and browser opening; never discover through a proxy."""
import errno
import hashlib
from http.client import HTTPException
import json
import os
import subprocess
import tempfile
from pathlib import Path
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler
import webbrowser

SERVICE = "kryptos-local-dashboard"
DESCRIPTOR = "dashboard-server.json"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None


def state_identity(directory):
    return hashlib.sha256(os.path.normcase(str(Path(directory).resolve())).encode()).hexdigest()


def local_url(value):
    try:
        p = urlsplit(value)
        return (p.scheme == "http" and p.hostname == "127.0.0.1" and
                p.username is None and p.password is None and p.port is not None and
                1 <= p.port <= 65535 and p.path == "/" and not p.query and not p.fragment)
    except (TypeError, ValueError, AttributeError):
        return False


def health(url, timeout=1):
    if not local_url(url):
        return None
    try:
        with build_opener(ProxyHandler({}),NoRedirect()).open(url + "api/health", timeout=timeout) as r:
            if r.status != 200:
                return None
            raw = r.read(4097)
            if len(raw) > 4096:
                return None
            value = json.loads(raw)
            return value if isinstance(value, dict) and value.get("service") == SERVICE else None
    except (OSError, ValueError, HTTPException):
        return None


def find_existing(directory):
    """A stale file or unrelated HTTP server cannot authorize reusing a server."""
    try:
        path = Path(directory) / DESCRIPTOR
        if path.stat().st_size > 4096:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not local_url(value.get("url")):
            return None
        live = health(value["url"])
        if (live and live.get("instance") == value.get("instance") and
                isinstance(live.get("instance"), str) and len(live["instance"]) >= 32 and
                live.get("state_identity") == state_identity(directory)):
            return dict(live, url=value["url"])
    except (OSError, ValueError):
        pass
    return None


def port_unavailable(error):
    return (isinstance(error, OSError) and
            (error.errno in {errno.EADDRINUSE, errno.EACCES} or
             getattr(error, "winerror", None) in {10048, 10013}))


def wait_ready(url, instance, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        live = health(url, timeout=min(1, max(.05, deadline - time.monotonic())))
        if live and live.get("instance") == instance:
            return True
        time.sleep(.05)
    return False


def open_browser(url, report=print):
    if not local_url(url):
        raise ValueError("Only the validated loopback dashboard URL may be opened")
    try:
        if webbrowser.open(url, new=2):
            return True
    except Exception as error:
        report(f"Browser could not be opened automatically: {error}")
    report(f"The server is still running. Open this address in your browser: {url}")
    return False


def bounded_gpu_probe(python,environment,directory,timeout=30):
    """A stuck driver/compiler cannot prevent startup indefinitely."""
    from .process_lifetime import launch_owned
    code="import json; from kryptos.accelerated import probe_backend; print(json.dumps(probe_backend(),allow_nan=False))"
    with tempfile.TemporaryDirectory(prefix="gpu-probe-",dir=directory) as folder:
        output=Path(folder)/"probe.json"
        errors=Path(folder)/"stderr.txt"
        with output.open("w",encoding="utf-8") as stdout, errors.open("w",encoding="utf-8") as stderr:
            child=launch_owned([str(python),"-B","-c",code],cwd=Path(__file__).resolve().parents[1],env=environment,stdout=stdout,stderr=stderr)
            try:
                try:
                    status=child.wait(timeout=timeout)
                except subprocess.TimeoutExpired as error:
                    raise RuntimeError(f"CUDA probe exceeded {timeout} seconds; CPU dashboard remains available. Use --skip-gpu-probe to bypass probing.") from error
            finally:
                child.close()
        if status:
            raise RuntimeError("CUDA probe failed: "+errors.read_text(encoding="utf-8",errors="replace")[-2000:])
        if output.stat().st_size>1024*1024:raise RuntimeError("CUDA probe response exceeds1MiB")
        value=json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(value,dict):raise RuntimeError("CUDA probe returned an invalid response")
        return value
