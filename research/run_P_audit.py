"""Prepare or run one immutable phase-P audit with complete process ownership.

The three kinds retain separate contracts, input snapshots and output folders.
Preparation does not execute scientific code. Reusing a prepared label is allowed
only when every input, contract, interpreter and audit helper still matches.
Run only after the coordinating task announces the production source freeze.
"""
import argparse
from copy import deepcopy
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.process_lifetime import launch_owned

SCRIPTS = {kind: f"research/{kind}_P.py" for kind in ("joint", "factor", "campaign")}



def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def project_file(name):
    relative = Path(name)
    candidate = ROOT / relative
    if relative.is_absolute() or ".." in relative.parts or not candidate.is_file():
        raise ValueError(f"Input must be an existing project-relative file: {name}")
    if not candidate.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError(f"Input escapes the project: {name}")
    return candidate


def input_paths(kind):
    paths = {p.relative_to(ROOT).as_posix() for p in (ROOT / "kryptos").glob("*.py")}
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").glob("*.py"))
    paths.update(("research/run_P_audit.py", SCRIPTS[kind],
                  f"research/{kind}_P_protocol.json", f"research/{kind}_P_notes.md",
                  "research/phase_P_plan.json",
                  "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"))
    for name in paths:
        project_file(name)
    return sorted(paths)


def contract_for(kind, paths):
    protocol = json.loads(project_file(f"research/{kind}_P_protocol.json").read_text(encoding="utf-8"))
    bounds = deepcopy(protocol.get("limits", protocol.get("bounds", {})))
    bounds["outer_seconds"] = {"joint": 240, "factor": 60, "campaign": 120}[kind]
    return {
        "claim_id": "KRYPTOS-P-" + kind.upper() + "-WORK",
        "mathematics": {
            "assertion_tested": protocol.get("assertion_tested", protocol.get("claim")),
            "coefficient_domain": "Exact integer product scores; modular cipher equations over Z/26.",
            "conventions": "Declared finite authored controls and exhaustive oracles; lexical ties and canonical recipes. Saved work, new work and validation overhead are distinct. No reserved O benchmark is reused for tuning.",
            "inputs": paths, "bounds": bounds,
            "non_claims": ["No authenticated Kryptos plaintext or universal search reduction.",
                           "Search decisions and complete evaluations are separate from propagation, bounds, replay and cache work.",
                           "Mechanism controls are not held-out cryptanalytic recovery evidence."],
            "frozen_protocol": protocol},
        "execution_artifacts": paths,
        "software": [{"name": "Python", "version": sys.version.split()[0]}],
        "randomness": {"used": kind != "campaign", "generator": "Python random.Random" if kind != "campaign" else "none",
                       "seed": str(protocol.get("seed", protocol.get("random_authored_controls", {}).get("seed", "none")))}
    }


def prepare(kind, label, skill):
    output = Path("research/runs") / label / kind
    if (ROOT / output).exists():
        raise FileExistsError("Audit output exists; preserve it and choose a fresh label")
    paths = input_paths(kind)
    originals = {name: project_file(name).read_bytes() for name in paths}
    hashes = {name: digest(data) for name, data in originals.items()}
    contract_bytes = encoded(contract_for(kind, paths))
    contract_path = ROOT / "research" / f"{label}-{kind}-contract.json"
    snapshot = ROOT / "research/source_snapshots" / f"{label}-{kind}"
    tools = {name: digest((skill / "scripts" / name).read_bytes())
             for name in ("run_experiment.py", "validate_manifest.py")}
    record = {"schema": "kryptos.P-audit-preparation.v1", "kind": kind, "label": label,
              "output_directory": output.as_posix(), "inputs": hashes,
              "contract_sha256": digest(contract_bytes), "audit_helper_sha256": tools,
              "interpreter": str(Path(sys.executable).resolve()),
              "python_version": sys.version, "benchmark_started": False}
    prep = snapshot / "_audit/preparation.json"
    if snapshot.exists() or contract_path.exists():
        if not prep.is_file() or not contract_path.is_file():
            raise ValueError("Partial preparation exists; preserve it and choose a fresh label")
        if json.loads(prep.read_text(encoding="utf-8")) != record or contract_path.read_bytes() != contract_bytes:
            raise ValueError("Prepared source, tool, interpreter or contract changed; use a fresh label")
    else:
        snapshot.mkdir(parents=True)
        for name, data in originals.items():
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(data)
        (snapshot / "_audit").mkdir()
        with (snapshot / "_audit/contract.json").open("xb") as stream:
            stream.write(contract_bytes)
        with contract_path.open("xb") as stream:
            stream.write(contract_bytes)
        with prep.open("xb") as stream:
            stream.write(encoded(record))
    verify_snapshot(snapshot, hashes, contract_bytes)
    return output, contract_path, snapshot, record


def verify_snapshot(snapshot, hashes, contract_bytes):
    for name, expected in hashes.items():
        if digest(project_file(name).read_bytes()) != expected or digest((snapshot / name).read_bytes()) != expected:
            raise ValueError(f"Current input or immutable snapshot changed: {name}")
    if (snapshot / "_audit/contract.json").read_bytes() != contract_bytes:
        raise ValueError("Immutable contract snapshot changed")


def owned_run(argv, env, timeout):
    with tempfile.TemporaryFile(mode="w+b", dir=ROOT / "runtime/cache/tmp") as log:
        process = launch_owned(argv, cwd=ROOT, env=env, stdout=log, stderr=log)
        try:
            code = process.wait(timeout=timeout)
        finally:
            process.close()  # Own runner and descendants, including Windows venv redirectors.
            log.seek(0)
            data = log.read(65537)
            print(data[:65536].decode("utf-8", errors="replace"), end="", flush=True)
            if len(data) > 65536:
                print("\nWrapper console truncated; canonical child logs remain in the audit directory.")
    return code


def execute(kind, skill, output, contract_path, snapshot, record):
    contract_bytes = contract_path.read_bytes()
    contract = json.loads(contract_bytes)
    outer = contract["mathematics"]["bounds"]["outer_seconds"]
    env = os.environ.copy()
    for name, suffix in (("TEMP", "tmp"), ("TMP", "tmp"), ("CUPY_CACHE_DIR", "cupy")):
        cache = ROOT / "runtime/cache" / suffix
        cache.mkdir(parents=True, exist_ok=True)
        env[name] = str(cache)
    result = output / "campaign/results.json" if kind == "campaign" else output / "result.json"
    argv = [sys.executable, str(skill / "scripts/run_experiment.py"), "--root", str(ROOT),
            "--contract", str(contract_path), "--output", output.as_posix(), "--result", result.as_posix(),
            "--timeout", str(outer), "--max-output-bytes", "1048576", "--max-threads", "1"]
    for name in record["inputs"]:
        argv += ["--input", name]
    child_output = output / "campaign" if kind == "campaign" else result
    argv += ["--", sys.executable, "-B", SCRIPTS[kind], "--output", child_output.as_posix()]
    code = owned_run(argv, env, outer + 20)
    manifest_path = ROOT / output / "manifest.json"
    # Even failed computations can have valid evidence; validate before returning failure.
    if not manifest_path.is_file():
        raise RuntimeError("Runner left no manifest; preserve this incomplete audit directory")
    validated = owned_run([sys.executable, str(skill / "scripts/validate_manifest.py"),
                           str(manifest_path), "--root", str(ROOT)], env, 30)
    if validated:
        raise subprocess.CalledProcessError(validated, "validate_manifest.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    observed = {row["path"]: row["sha256"] for row in manifest["input_artifacts"]}
    if observed != record["inputs"] or any(row["sha256_after"] != row["sha256"] for row in manifest["input_artifacts"]):
        raise ValueError("Manifest input observations differ from the prepared source snapshot")
    verify_snapshot(snapshot, record["inputs"], contract_bytes)
    files = [manifest_path, ROOT / output / "stdout.txt", ROOT / output / "stderr.txt"]
    if (ROOT / result).is_file():
        files.append(ROOT / result)
    closure = {"schema": "kryptos.P-audit-closure.v1", "manifest_status": manifest["run"]["status"],
               "source_snapshot": snapshot.relative_to(ROOT).as_posix(),
               "input_count": len(observed), "current_and_snapshot_hashes_match": True,
               "execution_files": {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in files}}
    with (ROOT / output / "snapshot-verification.json").open("xb") as stream:
        stream.write(encoded(closure))
    print(json.dumps(closure, indent=2))
    if code:
        raise subprocess.CalledProcessError(code, argv)
    checked = json.loads((ROOT / result).read_text(encoding="utf-8"))
    if checked.get("passed") is False or checked.get("status") == "failed":
        raise ValueError("Execution completed but finite assertion did not pass; preserve all evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-skill", type=Path, required=True)
    parser.add_argument("--kind", choices=tuple(SCRIPTS), required=True)
    parser.add_argument("--label", default="release-P-001")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", args.label):
        parser.error("Use an alphanumeric/hyphen label")
    skill = args.audit_skill.resolve()
    for name in ("run_experiment.py", "validate_manifest.py"):
        if not (skill / "scripts" / name).is_file():
            parser.error("Installed computation-audit runner/validator unavailable")
    output, contract, snapshot, record = prepare(args.kind, args.label, skill)
    if args.prepare_only:
        print(json.dumps({"contract": str(contract), "snapshot": str(snapshot),
                          "input_count": len(record["inputs"]), "benchmark_started": False}, indent=2))
        return
    execute(args.kind, skill, output, contract, snapshot, record)


if __name__ == "__main__":
    main()
