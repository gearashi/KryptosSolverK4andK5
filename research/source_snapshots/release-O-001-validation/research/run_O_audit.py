"""Prepare or run one immutable phase-O audit with complete process ownership.

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

SCRIPTS = {"search": "research/search_O.py", "validation": "research/validation_O.py",
           "scan": "research/scan_work_O.py"}


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
    paths.update(("research/run_O_audit.py", SCRIPTS[kind], "tests/test_process_lifetime.py"))
    if kind == "search":
        paths.update(("research/search_O_acceptance.md", "tests/test_search_O.py",
                      "tests/test_joint_ranked.py", "tests/test_guided_search.py",
                      "tests/test_factor_decomposition.py", "tests/test_search_enhancements.py"))
    elif kind == "scan":
        paths.update(("tests/test_scan_work.py", "tests/test_accelerated.py",
                      "tests/test_cuda_environment.py",
                      "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"))
    else:
        paths.update(("research/O-validation-contract.json", "research/fixtures_O.json",
                      "research/protocol_O.json", "research/grid_paths_O_protocol.json",
                      "research/sculpture_layout.json", "examples/validate-campaign-null.json",
                      "tests/test_validation_O.py", "tests/test_grid_paths.py",
                      "tests/test_validation_protocols.py", "tests/test_hypotheses.py"))
        request = json.loads(project_file("examples/validate-campaign-null.json").read_text(encoding="utf-8"))
        paths.update(request["model_paths"])
    for name in paths:
        project_file(name)
    return sorted(paths)


def contract_for(kind, paths):
    if kind == "validation":
        # Refresh source closure/software only. The frozen scientific bounds,
        # fixtures, mask, bank, threshold and seeds are not changed here.
        contract = deepcopy(json.loads(project_file("research/O-validation-contract.json").read_text(encoding="utf-8")))
    else:
        common = {"coefficient_domain": "Exact nonnegative integer product scores; modular letters over Z/26.",
                  "non_claims": ["No Kryptos decipherment or authenticity probability.",
                                 "Finite mechanistic controls, not representative cryptanalytic performance.",
                                 "Added bound, verification and calibration work is not free; no universal improvement."]}
        if kind == "search":
            common.update(
                assertion_tested="Verify coordinated seeds by complete products; compare finite mini-bucket bounds with independently enumerated residual maxima; compare ranked joint search and sliced continuation with independent permutation/key enumeration. Report favorable and unfavorable work counts.",
                conventions="Integer score and lexical ties; incomplete atomic tasks retained on resume; unique completed search assignments are separate from repeated retained-candidate verification.",
                bounds={"guided_dimensions": [2, 6], "guided_restarts": 1, "guided_sweeps": 3,
                        "guided_max_evaluations": 100, "random_graphs": 36, "residuals_per_graph": 8,
                        "oracle_bucket_caps": [9, 27], "oracle_bound_checks": 576,
                        "cycle_bucket_caps": [1, 4, 8], "joint_width": 3,
                        "joint_periods": [1, 2], "joint_top": [3, 1],
                        "joint_max_states": 1000000, "joint_seconds_per_call": 10,
                        "maximum_checkpoint_slices": 100, "slice_max_evaluations": 5,
                        "slice_max_states": 350, "slice_max_orders": 1,
                        "slice_max_segmentations": 1, "outer_seconds": 60})
            randomness = {"used": True, "generator": "Python random.Random", "seed": "60132; guided default seed=0"}
        else:
            common.update(
                assertion_tested="Compare incremental CPU rankings with literal integer-product enumeration on fixed carry/mask/zero controls; compare CUDA compacted intervals with the independent CPU interval oracle and certified retained ranks with CPU ranks; verify bounded measured-backend calibration and cache reuse on actual CUDA hardware.",
                conventions="Nonstandard alphabet ties; 72 CPU pages with 990 oracle visits; sparse/dense factor-work comparisons; uint64 interval edge cases; three explicit CPU/CUDA pages. GPU certification can rescore overlapping candidates, including all ties.",
                bounds={"cpu_oracle_pages": 72, "oracle_candidate_visits": 990,
                        "sparse_dense_cases": 2, "candidates_per_work_comparison": 26,
                        "cuda_interval_oracle_cases": 13, "paired_cpu_cuda_offsets": [0, 256, 512],
                        "candidates_per_page": 128, "retained_per_backend": 5,
                        "auto_measured_pages": 2, "calibration_candidates_per_backend": 32,
                        "outer_seconds": 90})
            randomness = {"used": True, "generator": "Python random.Random", "seed": 97025}
        contract = {"claim_id": "KRYPTOS-O-" + kind.upper() + "-WORK", "mathematics": common,
                    "randomness": randomness}
    contract["mathematics"]["inputs"] = paths
    contract["execution_artifacts"] = paths
    contract["software"] = [{"name": "Python", "version": sys.version.split()[0]}]
    if kind == "scan":
        for package in ("cupy-cuda12x", "numpy", "nvidia-cuda-runtime-cu12", "nvidia-cuda-nvrtc-cu12"):
            try:
                found = version(package)
            except PackageNotFoundError:
                continue  # Actual CUDA is mandatory in the script; absence cannot silently pass.
            contract["software"].append({"name": package, "version": found})
    return contract


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
    record = {"schema": "kryptos.O-audit-preparation.v1", "kind": kind, "label": label,
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
    result = output / "result.json"
    argv = [sys.executable, str(skill / "scripts/run_experiment.py"), "--root", str(ROOT),
            "--contract", str(contract_path), "--output", output.as_posix(), "--result", result.as_posix(),
            "--timeout", str(outer), "--max-output-bytes", "1048576", "--max-threads", "1"]
    for name in record["inputs"]:
        argv += ["--input", name]
    argv += ["--", sys.executable, "-B", SCRIPTS[kind], "--output", result.as_posix()]
    if kind == "scan":
        argv.append("--cuda")
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
    closure = {"schema": "kryptos.O-audit-closure.v1", "manifest_status": manifest["run"]["status"],
               "source_snapshot": snapshot.relative_to(ROOT).as_posix(),
               "input_count": len(observed), "current_and_snapshot_hashes_match": True,
               "execution_files": {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in files}}
    with (ROOT / output / "snapshot-verification.json").open("xb") as stream:
        stream.write(encoded(closure))
    print(json.dumps(closure, indent=2))
    if code:
        raise subprocess.CalledProcessError(code, argv)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-skill", type=Path, required=True)
    parser.add_argument("--kind", choices=tuple(SCRIPTS), required=True)
    parser.add_argument("--label", default="release-O-001")
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
