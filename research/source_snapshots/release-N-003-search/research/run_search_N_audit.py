"""Own the bounded checkpoint-N search audit and preserve portable evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "research"))
from kryptos.process_lifetime import launch_owned
from search_N import input_paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-skill", type=Path, required=True)
    parser.add_argument("--label", default="release-N-001")
    args = parser.parse_args()
    if not args.label.replace("-", "").isalnum():
        raise ValueError("Use an alphanumeric/hyphen label")
    output = Path("research/runs") / args.label / "search"
    if (ROOT / output).exists():
        raise FileExistsError("Use a fresh audit output")
    inputs = input_paths()
    snapshots = ROOT / "research/source_snapshots" / (args.label + "-search")
    snapshots.mkdir(parents=True)
    before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    for name in inputs:
        target = snapshots / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != before[name]:
            raise RuntimeError("Input changed while snapshotting")
    contract = {"claim_id": "KRYPTOS-N-GUIDED-DECOMPOSITION-JOINT", "mathematics": {
        "assertion_tested": "Frozen equal-evaluation guided/contiguous comparisons verify scores and replay; residual elimination matches exhaustive score and lexical optimum; independent joint-order/key enumeration matches top-k and counts.",
        "coefficient_domain": "Z/26letters,F2/F13affine coordinates,nonnegative integer product objectives",
        "conventions": "Original-coordinate lexical optimizer ties; joint distinct-plaintext lexical ties; explicit fixed crib masks. Guided outcome comparisons are descriptive, not required to favor guidance.",
        "inputs": inputs, "bounds": {"guided_comparisons": 8, "max_guided_evaluations_each": 192,
            "residual_cases": 60, "max_residual_oracle_completions_each": 48,
            "joint_cases": 24, "joint_independent_completions": 97344,
            "outer_seconds": 60, "owned_watchdog_seconds": 75},
        "non_claims": ["No K4/K5 search or authenticity", "No universal performance or recovery-rate claim", "A capped computation is not a negative cryptanalytic result"]},
        "execution_artifacts": inputs, "software": [{"name": "Python", "version": sys.version.split()[0]}],
        "randomness": {"used": True, "generator": "Python random.Random", "seed": "guided17,41;graph483"}}
    contract_path = ROOT / "research" / (args.label + "-search-contract.json")
    with contract_path.open("x", encoding="utf-8") as stream:
        json.dump(contract, stream, indent=2, allow_nan=False)
    result = output / "result.json"
    command = [sys.executable, str(args.audit_skill / "scripts/run_experiment.py"), "--root", str(ROOT),
        "--contract", str(contract_path), "--output", output.as_posix(), "--result", result.as_posix(),
        "--timeout", "60", "--max-output-bytes", "1048576", "--max-threads", "1"]
    for name in inputs:
        command += ["--input", name]
    command += ["--", sys.executable, "-B", "research/search_N.py", "--output", result.as_posix()]
    owned = launch_owned(command, cwd=ROOT, stdout=1, stderr=2)
    try:
        status = owned.wait(timeout=75)
    finally:
        owned.close()
    if status:
        raise subprocess.CalledProcessError(status, command)
    subprocess.run([sys.executable, str(args.audit_skill / "scripts/validate_manifest.py"),
                    str(ROOT / output / "manifest.json"), "--root", str(ROOT)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
