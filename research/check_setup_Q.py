"""Bounded end-to-end checks of the shipped Windows batch entry points.

Never operates on a pre-existing server. Fresh output directory is mandatory;
the only launched descendants are owned by Windows kill-on-close Job Objects.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.process_lifetime import launch_owned

PACKAGES = ("cupy-cuda12x", "nvidia-cuda-runtime-cu12", "nvidia-cuda-nvrtc-cu12", "z3-solver")


def packages():
    return {"distribution_count": sum(1 for _ in importlib.metadata.distributions()),
            "selected_versions": {name: importlib.metadata.version(name) for name in PACKAGES}}


def get_json(url):
    with build_opener(ProxyHandler({})).open(url, timeout=2) as response:
        return json.loads(response.read())


def port_open(port):
    with socket.socket() as connection:
        connection.settimeout(.3)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def run_command(command, name, output, env, timeout):
    start = time.monotonic()
    with (output / (name + ".stdout.txt")).open("x", encoding="utf-8") as stdout, (output / (name + ".stderr.txt")).open("x", encoding="utf-8") as stderr:
        child = launch_owned(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
        try:
            code = child.wait(timeout=timeout)
        finally:
            child.close()
    result = {"command": command, "exit_code": code, "elapsed_seconds": time.monotonic() - start}
    if code:
        raise RuntimeError(f"{name} exited {code}; inspect preserved logs")
    return result


def check(output):
    output.mkdir(parents=True, exist_ok=False)
    state = output / "isolated-state"
    probe_tmp = output / "probe-tmp"
    probe_tmp.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1",
               PIP_CONFIG_FILE=os.devnull, PIP_INDEX_URL="https://pypi.org/simple",
               PIP_EXTRA_INDEX_URL="", PIP_NO_INPUT="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               TEMP=str(probe_tmp), TMP=str(probe_tmp), CUPY_CACHE_DIR=str(output / "probe-cache"))
    removed = [key for key in env if key.upper().startswith("CUDA_PATH") or key.upper() == "CUDA_HOME"]
    for key in removed:
        env.pop(key)
    env.pop("PIP_NO_INDEX", None)
    report = {"schema": "kryptos.windows-entrypoint-check.v1", "passed": False,
              "python": sys.version, "cpu_search_started": False, "cuda_path_present_in_child": "CUDA_PATH" in env,
              "removed_cuda_variable_names": removed, "before_packages": packages(),
              "existing_8767_port_open_before": port_open(8767), "production_edits": False,
              "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ("Setup.cmd", "Setup.ps1", "OpenDashboard.cmd", "OpenDashboard.ps1",
                                       "requirements-gpu.txt", "requirements-sat.txt", "kryptos/app.py",
                                       "kryptos/launcher.py", "kryptos/cuda_environment.py", "research/check_setup_Q.py")}}
    port = None
    try:
        cmd = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        report["setup"] = run_command([cmd, "/d", "/c", "Setup.cmd", "-Gpu", "-Sat"], "setup", output, env, 150)
        report["after_packages"] = packages()
        report["packages_unchanged"] = report["before_packages"] == report["after_packages"]
        setup_stdout = (output / "setup.stdout.txt").read_text(encoding="utf-8", errors="replace")
        report["already_satisfied_lines"] = setup_stdout.count("Requirement already satisfied:")
        report["setup_cpu_import_ready"] = "CPU application ready on Python" in setup_stdout
        report["setup_smt_import_ready"] = "Optional SMT backend ready: Z3" in setup_stdout
        command = [cmd, "/d", "/c", "OpenDashboard.cmd", "-Port", "0", "-NoBrowser", "-StateDir", str(state)]
        with (output / "launcher.stdout.txt").open("x", encoding="utf-8") as stdout, (output / "launcher.stderr.txt").open("x", encoding="utf-8") as stderr:
            child = launch_owned(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
            start = time.monotonic()
            try:
                descriptor = None
                ready = False
                deadline = start + 50
                while time.monotonic() < deadline and child.poll() is None:
                    try:
                        descriptor = json.loads((state / "dashboard-server.json").read_text())
                        health = get_json(descriptor["url"] + "api/health")
                        if health.get("instance") == descriptor["instance"]:
                            ready = True
                            break
                    except (OSError, ValueError):
                        descriptor = None
                    time.sleep(.1)
                if descriptor is None or not ready:
                    raise RuntimeError("Batch launcher failed HTTP readiness within 50 seconds")
                url = descriptor["url"]
                port = int(url.split(":")[-1].rstrip("/"))
                info = get_json(url + "api/info")
                status = get_json(url + "api/status")
                cuda = info["capabilities"]["cuda"]
                report["launcher"] = {"command": command, "http_ready": True, "url": url,
                                      "elapsed_seconds": time.monotonic() - start,
                                      "version": info["version"], "service": health.get("service"),
                                      "instance_matches_descriptor": health.get("instance") == descriptor["instance"],
                                      "cuda": cuda, "idle": status.get("run") is None,
                                      "no_campaign": status.get("campaign") is None}
                assert info["version"] == "0.6.0", "Unexpected version"
                assert health["service"] == "kryptos-local-dashboard", "Unexpected HTTP service"
                assert cuda.get("ready") and cuda.get("available") and cuda.get("compiled_kernel_verified"), "Compiled CUDA not ready"
                assert status.get("run") is None, "Server started a search"
            finally:
                child.close()
        deadline = time.monotonic() + 5
        while port is not None and port_open(port) and time.monotonic() < deadline:
            time.sleep(.1)
        report["owned_port_closed"] = port is not None and not port_open(port)
        assert report["owned_port_closed"], "Owned server port remained open"
        # Probe separately so its stderr is preserved: normal successful startup
        # intentionally removes the internal temporary probe logs.
        probe = "import json; from kryptos.accelerated import probe_backend; print(json.dumps(probe_backend(), allow_nan=False))"
        report["direct_gpu_probe"] = run_command([sys.executable, "-B", "-c", probe], "direct-gpu-probe", output, env, 35)
        direct = json.loads((output / "direct-gpu-probe.stdout.txt").read_text())
        assert direct["cuda"].get("ready") and direct["cuda"].get("compiled_kernel_verified"), "Direct compiled GPU probe failed"
        report["direct_gpu_probe"]["cuda"] = direct["cuda"]
        log_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in output.glob("*.txt"))
        report["cuda_path_detection_warning"] = "CUDA path could not be detected" in log_text
        assert not report["cuda_path_detection_warning"], "CUDA path warning found"
        assert report["setup_cpu_import_ready"] and report["setup_smt_import_ready"]
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["existing_8767_port_open_after"] = port_open(8767)
        report["sources_unchanged"] = all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in report["sources"].items())
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    result = check(parser.parse_args().output.resolve())
    print(json.dumps({"passed": result["passed"], "version": result["launcher"]["version"],
                      "compiled_cuda_ready": result["launcher"]["cuda"]["compiled_kernel_verified"],
                      "owned_port_closed": result["owned_port_closed"]}))
