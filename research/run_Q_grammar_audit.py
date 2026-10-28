"""Record the frozen Q62/64/65 work controls using the installed audit runner."""
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ["research/phase_Q_grammar_contract.json", "research/audit_Q_grammar.py",
          "research/run_Q_grammar_audit.py", "kryptos/recipe_grammar.py",
          "kryptos/recipe_algebra.py", "kryptos/family_identity.py",
          "kryptos/constraint_algebra.py", "kryptos/constraint_lab.py",
          "kryptos/general_layers.py", "kryptos/scheduled_layers.py", "kryptos/ciphers.py"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    relative = output.relative_to(ROOT).as_posix()
    if output.exists():
        raise SystemExit("refusing to reuse an earlier run directory")
    frozen = json.loads((ROOT / INPUTS[0]).read_text(encoding="utf-8"))
    contract = {
        "claim_id": "Q62_64_65_FIXED_WORK_CONTROLS",
        "mathematics": {
            "assertion_tested": "The frozen six-slot binary grammar represents 64 syntax paths using 12 symbolic edges; shared-key CEGIS accepts exactly recipes 0 and 2 using either one or three initial examples; shorter-first priority reaches the same first valid recipe after one instead of three candidates.",
            "coefficient_domain": "exact integers and F2/F13 equations lifted to Z/26Z",
            "conventions": "Independent unrestricted substitution keys within each recipe; one shared unknown key vector across all explicitly supplied examples; primary and secondary work counters reported separately.",
            "inputs": [frozen["frozen_controls"], "A separate three-recipe first-witness priority control fixed in audit_Q_grammar.py"],
            "bounds": {"grammar_slots": 6, "choices_per_slot": 2, "text_lengths": [3, 4], "cegis_bank_size": 4, "priority_bank_size": 3, "examples": 3, "initial_examples": [1, 3]},
            "non_claims": frozen["limits"] + ["Only authored controls are measured; no universal work improvement or Kryptos authentication", "Grammar canonicalization arithmetic and hashing are not fully instrumented", "CEGIS can trade fewer equation rows for more proposed keys and literal replay checks", "First-witness runs intentionally leave the remaining bank unexplored"]
        },
        "execution_artifacts": INPUTS,
        "software": [{"name": "Python", "version": platform.python_version()}],
        "randomness": {"used": False, "generator": "", "seed": None}
    }
    runtime = ROOT / "runtime"
    runtime.mkdir(exist_ok=True)
    contract_path = runtime / (output.name + "-grammar-contract.json")
    with contract_path.open("x", encoding="utf-8") as stream:
        json.dump(contract, stream, indent=2)
        stream.write("\n")
    command = [sys.executable, str(Path(args.runner).resolve()), "--root", str(ROOT),
               "--contract", str(contract_path), "--output", relative,
               "--result", relative + "/result.json", "--timeout", "60",
               "--max-output-bytes", "1048576", "--max-threads", "1"]
    for path in INPUTS:
        command.extend(["--input", path])
    command.extend(["--", sys.executable, "-B", "research/audit_Q_grammar.py",
                    "--output", relative + "/result.json"])
    raise SystemExit(subprocess.run(command, cwd=ROOT, check=False).returncode)


if __name__ == "__main__":
    main()
