"""Run new public commands, independently replay outputs and resume a CLI frontier."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.explanations import replay_recipe
from kryptos.replay_expanded import replay_expanded

CASES=(("joint-ragged","joint","examples/joint-ragged.json"),
       ("scheduled-shared","scheduled","examples/scheduled-shared.json"),
       ("mixed-shared","mixed","examples/mixed-shared.json"),
       ("alphabet-plus","alphabet-plus","examples/alphabet-cycle.json"),
       ("optimize-lazy","optimize-plus","examples/optimize-lazy.json"),
       ("batch-lazy","batch","examples/batch-lazy.json"))


def execute(command,request,destination):
    args=[sys.executable,"-B","-m","kryptos",command,"--request",str(request),"--output",str(destination)]
    process=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=25,check=False)
    assert process.returncode==0,process.stderr
    return json.loads(destination.read_text(encoding="utf-8"))


def verify(candidate,ciphertext):
    assert candidate["plaintext"] is not None
    recipe=candidate["encryption_recipe"]
    replay=replay_expanded if recipe["schema"]=="kryptos.expanded-recipe.v1" else replay_recipe
    assert replay(candidate["plaintext"],recipe)["ciphertext"]==ciphertext
    assert candidate["evidence"]["literal_reencryption_matches"]


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    records=[]
    for name,command,request in CASES:
        destination=a.output.parent/(name+".json")
        result=execute(command,request,destination)
        raw=json.loads((ROOT/request).read_text())
        candidates=[]
        if command=="batch":
            for job in result["jobs"]:
                candidate=job["optimization"]["candidate"]
                ciphertext=next(r["request"]["ciphertext"] for r in raw["jobs"] if r["id"]==job["id"])
                verify(candidate,ciphertext)
                candidates.append(candidate)
        else:
            candidates=[result["optimization"]["candidate"]] if "optimization" in result else result.get("candidates",[])
            assert candidates
            for candidate in candidates:
                verify(candidate,raw["ciphertext"])
        if command=="scheduled":
            assert result["distinct_plaintext_count"]==1 and candidates[0]["plaintext"]=="ABCDE"
        if command=="joint":
            assert result["complete"] and all(c["plaintext"]=="ABCDEFGHIJ" for c in candidates)
        if command=="mixed":
            assert result["complete"] and all(c["plaintext"]=="ABCD" for c in candidates)
        assert result["authenticated_solution"] is False
        records.append({"name":name,"command":command,"request":request,"output":destination.as_posix(),
                        "sha256":hashlib.sha256(destination.read_bytes()).hexdigest(),"replayed_candidates":len(candidates),"passed":True})
    request=json.loads((ROOT/"examples/optimize-lazy.json").read_text())
    first=a.output.parent/"frontier-initial.json"
    request.update(max_nodes=0,checkpoint_path=str(first.resolve()))
    request_path=a.output.parent/"stop-request.json"
    request_path.write_text(json.dumps(request))
    stopped=execute("optimize-plus",request_path,a.output.parent/"stopped.json")
    request.update(max_nodes=10000,resume_path=str(first.resolve()),checkpoint_path=str((a.output.parent/"frontier-final.json").resolve()))
    request_path=a.output.parent/"resume-request.json"
    request_path.write_text(json.dumps(request))
    resumed=execute("optimize-plus",request_path,a.output.parent/"resumed.json")
    assert resumed["optimization"]["search"]["resumed"] and resumed["optimization"]["search"]["complete"]
    verify(resumed["optimization"]["candidate"],request["ciphertext"])
    result={"cases":records,"all_passed":True,"commands":len(records)+2,
            "replayed_candidates":sum(r["replayed_candidates"] for r in records)+1,"checkpoint_roundtrip_passed":True,
            "initial_stop_reason":stopped["optimization"]["search"]["stop_reason"]}
    with a.output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)
    print(json.dumps({k:v for k,v in result.items() if k!="cases"}))


if __name__=="__main__":
    main()
