"""Run a frozen K contract with explicit result files and optional script flags."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
RUNNER=Path("C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/3.2.0/skills/computation-audit/scripts/run_experiment.py")


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--contract",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--script",required=True)
    p.add_argument("--timeout",type=int,default=60)
    p.add_argument("--extra-result",action="append",default=[])
    p.add_argument("--script-arg",action="append",default=[])
    a=p.parse_args()
    contract=json.loads((ROOT/a.contract).read_text(encoding="utf-8"))
    result=a.output.rstrip("/")+"/results.json"
    command=[sys.executable,str(RUNNER),"--root",str(ROOT),"--contract",a.contract,"--output",a.output,
             "--result",result,"--timeout",str(a.timeout),"--max-output-bytes","262144","--max-threads","1"]
    for path in sorted(set(contract["execution_artifacts"])):
        command.extend(["--input",path])
    for path in a.extra_result:
        command.extend(["--result",path])
    command.extend(["--",sys.executable,"-B",a.script,"--output",result,*a.script_arg])
    return subprocess.run(command,cwd=ROOT,check=False).returncode


if __name__=="__main__":
    raise SystemExit(main())
