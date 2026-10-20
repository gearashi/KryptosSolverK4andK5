"""Validate the frozen K evidence and preserve links to the historical J revision."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
VALIDATOR=Path("C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/3.2.0/skills/computation-audit/scripts/validate_manifest.py")
RUNS=("joint-K-001","scheduled-K-001","alphabet-K-001","hard-controls-K-001","runtime-K-001","runtime-audit-K-001","unit-K-001","cli-K-001")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


records=[]
for name in RUNS:
    path="research/runs/"+name+"/manifest.json"
    process=subprocess.run([sys.executable,str(VALIDATOR),path,"--root",str(ROOT)],cwd=ROOT,capture_output=True,text=True,check=False)
    value=json.loads((ROOT/path).read_text())
    passed=process.returncode==0 and value["run"]["status"]=="completed"
    records.append({"manifest":path,"sha256":digest(ROOT/path),"valid_current_evidence":passed,
                    "validator_output":process.stdout.strip(),"stderr":process.stderr.strip()})
    assert passed,records[-1]
historical=[]
old_manifest=json.loads((ROOT/"research/runs/unit-J-001/manifest.json").read_text())
for item in old_manifest["input_artifacts"]:
    if digest(ROOT/item["path"])==item["sha256"]:
        continue
    assert item["path"]=="kryptos/__main__.py",item
    snapshot=ROOT/"research/source_snapshots/checkpoint-J/__main__.py"
    assert digest(snapshot)==item["sha256"]
    historical.append({"original":item["path"],"snapshot":snapshot.relative_to(ROOT).as_posix(),"sha256":item["sha256"]})
supplementary=[]
for name in ("research/manual-checks/alphabet-independent-K/audit.py","research/manual-checks/alphabet-independent-K/result.json",
             "research/manual-checks/joint-independent-K/recorded_result.json"):
    supplementary.append({"path":name,"sha256":digest(ROOT/name)})
data_hash=digest(ROOT/"kryptos/data.py")
assert data_hash=="2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2"
result={"checkpoint":"K4-20261013-K","successful_manifests":records,"all_current_records_valid":True,
        "canonical_data_sha256":data_hash,"historical_J_modified_inputs_preserved":historical,
        "supplementary_peer_audits":supplementary,
        "supplementary_limit":"Joint peer audit retains the earlier inline execution report; its literal script was not retained. Reproducible joint canonical and unit controls remain available.",
        "non_claim":"Execution, hashes and finite checks are verified. No authenticated decipherment follows."}
with (ROOT/"research/checkpoint-K-validation.json").open("x",encoding="utf-8") as stream:
    json.dump(result,stream,indent=2)
print(json.dumps({"successful_manifests_validated":len(records),"historical_snapshots_checked":len(historical),"supplementary_files":len(supplementary)}))
