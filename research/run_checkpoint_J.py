"""Run a declared checkpoint-J contract through the installed audit runner."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path("C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/3.2.0/skills/computation-audit/scripts/run_experiment.py")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--contract",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--script",required=True)
    p.add_argument("--timeout",type=int,default=60)
    p.add_argument("--extra-result",action="append",default=[])
    p.add_argument("--directory-result",help="New subdirectory below the run directory for scripts producing several files")
    a = p.parse_args()
    contract = json.loads((ROOT / a.contract).read_text(encoding="utf-8"))
    script_output = a.output.rstrip("/") + "/" + a.directory_result if a.directory_result else a.output.rstrip("/") + "/results.json"
    result = script_output + "/results.json" if a.directory_result else script_output
    args = [sys.executable,str(RUNNER),"--root",str(ROOT),"--contract",a.contract,
            "--output",a.output,"--result",result,"--timeout",str(a.timeout),
            "--max-output-bytes","262144","--max-threads","1"]
    for path in sorted(set(contract["execution_artifacts"])):
        args.extend(["--input",path])
    for path in a.extra_result:
        args.extend(["--result",path])
    args += ["--",sys.executable,"-B",a.script,"--output",script_output]
    return subprocess.run(args,cwd=ROOT,check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
