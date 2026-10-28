import errno
from http.client import IncompleteRead, BadStatusLine
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

from kryptos import launcher
from kryptos.app import make_server
from kryptos.process_lifetime import launch_owned

ROOT = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def test_malformed_health_response_and_redirect_cannot_break_discovery(self):
        for error in (IncompleteRead(b"partial"),BadStatusLine("invalid response")):
            client=MagicMock()
            client.open.side_effect=error
            with patch.object(launcher,"build_opener",return_value=client):
                self.assertIsNone(launcher.health("http://127.0.0.1:8767/"))
        self.assertIsNone(launcher.NoRedirect().redirect_request(None,None,302,"found",{},"https://example.invalid/"))

    def test_timed_out_gpu_probe_closes_owned_child(self):
        child=MagicMock()
        child.wait.side_effect=subprocess.TimeoutExpired("probe",.01)
        with tempfile.TemporaryDirectory() as folder,patch("kryptos.process_lifetime.launch_owned",return_value=child):
            with self.assertRaisesRegex(RuntimeError,"CPU dashboard remains available"):
                launcher.bounded_gpu_probe(sys.executable,os.environ.copy(),folder,timeout=.01)
        child.close.assert_called_once()
    def test_urls_cannot_escape_loopback_or_include_credentials(self):
        for value in (None, {}, "https://127.0.0.1:1/", "http://localhost:2/",
                      "http://127.0.0.1.evil:2/", "http://user@127.0.0.1:2/",
                      "http://127.0.0.1:2/else", "http://127.0.0.1:2/#bad",
                      "http://127.0.0.1:0/", "http://127.0.0.1:65536/"):
            self.assertFalse(launcher.local_url(value), value)
        self.assertTrue(launcher.local_url("http://127.0.0.1:8767/"))

    def test_browser_failure_reports_url_without_raising(self):
        for outcome in (False, RuntimeError("no browser association")):
            with patch.object(launcher.webbrowser, "open", side_effect=[outcome]):
                messages=[]
                self.assertFalse(launcher.open_browser("http://127.0.0.1:8767/", messages.append))
                self.assertIn("still running", messages[-1])

    def test_discovery_checks_instance_and_saved_workspace(self):
        with tempfile.TemporaryDirectory(prefix="kryptos-launch-") as folder:
            server=make_server(folder,0,probe=False)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                url=f"http://127.0.0.1:{server.server_port}/"
                descriptor=Path(folder)/launcher.DESCRIPTOR
                value={"url":url,"instance":server.instance}
                descriptor.write_text(json.dumps(value),encoding="utf-8")
                self.assertEqual(launcher.find_existing(folder)["url"],url)
                self.assertTrue(launcher.wait_ready(url,server.instance,1))
                self.assertFalse(launcher.wait_ready(url,"wrong",.05))
                value["instance"]="wrong"
                descriptor.write_text(json.dumps(value),encoding="utf-8")
                self.assertIsNone(launcher.find_existing(folder))
                descriptor.write_text('[]',encoding="utf-8")
                self.assertIsNone(launcher.find_existing(folder))
            finally:
                server.shutdown();thread.join(3)
                server.campaigns.close();server.manager.close();server.server_close()

    def test_port_fallback_only_for_port_errors(self):
        self.assertTrue(launcher.port_unavailable(OSError(errno.EADDRINUSE,"busy")))
        self.assertTrue(launcher.port_unavailable(PermissionError(errno.EACCES,"reserved")))
        self.assertFalse(launcher.port_unavailable(OSError(errno.ENOENT,"missing")))
        self.assertFalse(launcher.port_unavailable(RuntimeError("state owned")))

    def test_actual_launch_falls_back_and_second_launch_reuses_server(self):
        with tempfile.TemporaryDirectory(prefix="kryptos-launch-") as folder, socket.socket() as occupied:
            occupied.bind(("127.0.0.1",0));occupied.listen()
            port=occupied.getsockname()[1]
            args=[sys.executable,"-B","-m","kryptos.app","--port",str(port),
                  "--state-dir",str(Path(folder)/"state"),"--no-browser","--skip-gpu-probe"]
            with (Path(folder)/"output.txt").open("w",encoding="utf-8") as log:
                process=launch_owned(args,cwd=ROOT,stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+15
                    existing=None
                    while time.monotonic()<deadline and process.poll() is None:
                        existing=launcher.find_existing(Path(folder)/"state")
                        if existing:break
                        time.sleep(.05)
                    self.assertIsNotNone(existing,(Path(folder)/"output.txt").read_text())
                    self.assertNotEqual(existing["url"],f"http://127.0.0.1:{port}/")
                    reused=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=10)
                    self.assertEqual(reused.returncode,0,reused.stderr)
                    self.assertIn("Reopened the existing server",reused.stdout)
                    self.assertIsNone(process.poll())
                finally:
                    process.close()

    @unittest.skipUnless(os.name=="nt","Windows batch setup contract")
    def test_batch_wrappers_setup_and_launch_from_spaced_path(self):
        with tempfile.TemporaryDirectory(prefix="Kryptos setup with spaces ") as folder:
            directory=Path(folder)
            for name in ("Setup.cmd","Setup.ps1","OpenDashboard.cmd","OpenDashboard.ps1"):
                shutil.copyfile(ROOT/name,directory/name)
            env=dict(os.environ,PYTHONPATH=str(ROOT),PYTHONUTF8="1")
            # Invoke the .cmd from a different working directory, with paths that require quoting.
            command=f'"{directory / "Setup.cmd"}" -Python "{sys.executable}"'
            result=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=ROOT,
                                  env=env,capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn("CPU application ready",result.stdout)
            args=["cmd.exe","/d","/c","OpenDashboard.cmd","-Port","0","-NoBrowser","-SkipGpuProbe",
                  "-StateDir",str(directory/"saved state")]
            with (directory/"output.txt").open("w",encoding="utf-8") as log:
                process=launch_owned(args,cwd=directory,env=env,stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+20
                    existing=None
                    while time.monotonic()<deadline and process.poll() is None:
                        existing=launcher.find_existing(directory/"saved state")
                        if existing:break
                        time.sleep(.05)
                    self.assertIsNotNone(existing,(directory/"output.txt").read_text())
                    command=f'"{directory / "OpenDashboard.cmd"}" -NoBrowser -SkipGpuProbe -StateDir "{directory / "saved state"}"'
                    reopened=subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
                    self.assertEqual(reopened.returncode,0,reopened.stdout+reopened.stderr)
                    self.assertIn("Reopened",reopened.stdout)
                finally:
                    process.close()


if __name__=="__main__":
    unittest.main()
