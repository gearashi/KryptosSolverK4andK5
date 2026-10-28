"""Validate a fresh Git archive, never the developer's working state.

Requires installed Python/Node/Playwright/Chromium. Installs nothing. CUDA is
explicitly opt-in; CPU CI evidence must never be presented as GPU validation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from kryptos.process_lifetime import launch_owned


def run(args, cwd, log, env, timeout=600):
    with log.open("x", encoding="utf-8") as stream:
        process = launch_owned(args, cwd=cwd, env=env, stdout=stream, stderr=stream)
        try:
            code=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stream.write(f"\nValidation command exceeded {timeout} seconds; owned descendants terminated.\n")
            raise RuntimeError(f"Validation timed out; inspect {log.name}") from error
        finally:
            process.close()
    if code:
        raise RuntimeError(f"Validation failed ({code}); inspect {log.name}")


def browser_check(args,package,output,env,script,name):
    server_log = output / (name+"-server.txt")
    with server_log.open("x", encoding="utf-8") as stream:
        command = [sys.executable, "-B", "-m", "kryptos.app", "--port", "0", "--no-browser", "--state-dir", str(output / (name+"-isolated-state"))]
        cpu_only=name in {"workspace-browser","search-P-browser","methods-Q-browser"}
        if args.cuda == "off" or cpu_only: command.append("--skip-gpu-probe")
        server = launch_owned(command, cwd=package, env=env, stdout=stream, stderr=stream)
        try:
            url = None
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and server.poll() is None:
                found = re.search(r"http://127\.0\.0\.1:\d+/", server_log.read_text(encoding="utf-8"))
                if found: url = found.group(); break
                time.sleep(.1)
            if url is None: raise RuntimeError("Isolated packaged server did not become ready")
            command = [args.node, script, "--url", url, "--out", str(output / name), "--suite", "all", "--cuda", "off" if cpu_only else args.cuda]
            if args.playwright_module: command += ["--playwright-module", args.playwright_module]
            if args.browser_executable: command += ["--browser-executable", args.browser_executable]
            run(command, package, output / (name+"-console.txt"), env, timeout=420)
        finally:
            server.close()


def validate(args):
    root = Path(__file__).resolve().parents[1]
    output = Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(["git", "rev-parse", args.ref + "^{commit}"], cwd=root, text=True,timeout=30).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Expected a full Git commit")
    archive = output / "KryptosSolverK4AndK5.zip"
    run(["git", "archive", "--format=zip", "--output=" + str(archive), commit], root, output/"archive-log.txt",os.environ.copy(),timeout=60)
    package = output / "package"
    package.mkdir()
    with zipfile.ZipFile(archive) as z:
        # Git paths are still checked before extraction.
        for name in z.namelist():
            if not (package / name).resolve().is_relative_to(package):
                raise ValueError("Archive path escapes package")
        z.extractall(package)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", KRYPTOS_TEST_CUDA="1" if args.cuda == "required" else "0")
    record = {"schema": "kryptos.package-validation.v1", "commit": commit,
              "package_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
              "platform": sys.platform, "python": sys.version, "cuda_policy": args.cuda,
              "checks": [], "passed": False}
    try:
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"], package, output / "python-tests.txt", env)
        record["checks"].append("packaged Python suite")
        run([args.node, "tests/browser_validation.test.cjs"], package, output / "node-tests.txt", env)
        record["checks"].append("packaged Node runner checks")
        browser_check(args,package,output,env,"research/browser_validation.cjs","browser")
        record["checks"].append("packaged browser workflows")
        browser = json.loads((output / "browser/browser-report.json").read_text())
        record["browser_passed"] = browser["passed"]
        record["hardware"] = browser.get("capabilities", {})
        browser_check(args,package,output,env,"research/browser_workspace.cjs","workspace-browser")
        record["checks"].append("packaged workspace recovery workflows")
        record["workspace_browser_passed"]=json.loads((output/"workspace-browser/report.json").read_text())["passed"]
        browser_check(args,package,output,env,"research/browser_search_P.cjs","search-P-browser")
        record["checks"].append("packaged optional search and shared scan workflows")
        record["search_P_browser_passed"]=json.loads((output/"search-P-browser/report.json").read_text())["passed"]
        browser_check(args,package,output,env,"research/browser_methods_Q.cjs","methods-Q-browser")
        record["checks"].append("packaged research methods and expanded hardware controls")
        record["methods_Q_browser_passed"]=json.loads((output/"methods-Q-browser/report.json").read_text())["passed"]
        record["passed"] = True
    finally:
        (output / "validation.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        (output / "SHA256SUMS").write_text(record["package_sha256"] + "  " + archive.name + "\n", encoding="utf-8")
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, help="Fresh evidence directory")
    p.add_argument("--ref", default="HEAD")
    p.add_argument("--cuda", choices=["off", "required"], default="off")
    p.add_argument("--node", default="node")
    p.add_argument("--playwright-module")
    p.add_argument("--browser-executable")
    args = p.parse_args()
    print(json.dumps(validate(args), indent=2))


if __name__ == "__main__":
    main()
