"""Check freshness of all successful checkpoint-J canonical evidence records."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = Path("C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/3.2.0/skills/computation-audit/scripts/validate_manifest.py")
RUNS = ("geometry-J-001","columnar-J-001","alphabet-J-001","general-J-002","evaluation-J-001","unit-J-001","cli-J-001")
records = []
for name in RUNS:
    path = "research/runs/" + name + "/manifest.json"
    process = subprocess.run([sys.executable,str(VALIDATOR),path,"--root",str(ROOT)],cwd=ROOT,capture_output=True,text=True,check=False)
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    passed = process.returncode == 0 and value["run"]["status"] == "completed"
    records.append({"manifest":path,"sha256":hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                    "valid_current_evidence":passed,"validator_output":process.stdout.strip(),"stderr":process.stderr.strip()})
    if not passed:
        raise AssertionError(records[-1])
old = json.loads((ROOT / "research/runs/general-J-001/manifest.json").read_text())
preserved = []
for entry in old["input_artifacts"]:
    source = ROOT / "research/source_snapshots/general-J-001" / entry["path"]
    if source.exists():
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        assert digest == entry["sha256"]
        preserved.append({"original":entry["path"],"snapshot":source.relative_to(ROOT).as_posix(),"sha256":digest})
value = {"checkpoint":"K4-20261013-J","successful_manifests":records,
         "all_current_records_valid":True,"canonical_data_sha256":hashlib.sha256((ROOT / "kryptos/data.py").read_bytes()).hexdigest(),
         "historical_failed_attempt":{"manifest":"research/runs/general-J-001/manifest.json",
             "reason":"Benchmark called nonexistent CharacterNgramModel.from_dict before the mathematical experiment. Fixed to the validated from_json loader and reran in general-J-002.",
             "modified_inputs_preserved":preserved},
         "non_claim":"Execution, hashes and checks are verified; no authentication of a decipherment follows."}
with (ROOT / "research/checkpoint-J-validation.json").open("x",encoding="utf-8") as f:
    json.dump(value,f,indent=2)
print(json.dumps({"successful_manifests_validated":len(records),"historical_snapshots_checked":len(preserved)}))
