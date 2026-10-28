"""Run the fixed Q71-90 experiment using the installed audit manifest runner."""
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ["research/phase_Q_models_contract.json", "research/audit_Q_models.py",
          "research/run_Q_models_audit.py", "kryptos/geometry_constraints.py",
          "kryptos/language_constraints.py", "kryptos/model_lab.py",
          "kryptos/explanations.py", "kryptos/ciphers.py"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True, help="Installed mathbox computation-audit run_experiment.py")
    parser.add_argument("--output", required=True, help="New project-relative run directory")
    args = parser.parse_args()
    output = (ROOT/args.output).resolve()
    output.relative_to(ROOT)
    if output.exists():
        raise SystemExit("refusing to reuse an earlier run directory")
    detailed = json.loads((ROOT/INPUTS[0]).read_text(encoding="utf-8"))
    contract = {"claim_id": "Q71_90_FINITE_MODELS", "mathematics": {
        "assertion_tested": detailed["assertion_tested"], "coefficient_domain": "exact integers and finite modular arithmetic",
        "conventions": detailed["domain"], "inputs": detailed["geometry_cases"]+detailed["language_cases"]+detailed["codebook_cases"]+detailed["other_cases"],
        "bounds": detailed["bounds"], "non_claims": detailed["non_claims"]},
        "execution_artifacts": INPUTS, "software": [{"name": "Python", "version": platform.python_version()}],
        "randomness": {"used": False, "generator": "", "seed": None}}
    runtime = ROOT/"runtime"; runtime.mkdir(exist_ok=True)
    contract_path = runtime/(output.name+"-models-contract.json")
    if contract_path.exists():
        raise SystemExit("refusing to overwrite an earlier generated contract")
    contract_path.write_text(json.dumps(contract, indent=2)+"\n", encoding="utf-8")
    command = [sys.executable, str(Path(args.runner).resolve()), "--root", str(ROOT), "--contract", str(contract_path),
               "--output", args.output, "--result", args.output.replace("\\", "/")+"/result.json", "--timeout", "60", "--max-output-bytes", "1048576"]
    for item in INPUTS:
        command += ["--input", item]
    command += ["--", sys.executable, "-B", "research/audit_Q_models.py", "--output", args.output.replace("\\", "/")+"/result.json"]
    completed = subprocess.run(command, cwd=ROOT, check=False)
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
