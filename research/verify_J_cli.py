"""Exercise all new CLI commands and independently replay saved candidates."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.explanations import replay_recipe

CASES = (("columns-ragged","columns","examples/columns-ragged.json"),
         ("general-five-stages","general","examples/general-five-stages.json"),
         ("alphabet-cycle","alphabet","examples/alphabet-cycle.json"),
         ("optimize-small","optimize","examples/optimize-small.json"),
         ("layout-k4","layout",None),("columns-k4","columns",None))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    a = parser.parse_args()
    records = []
    for name, command, request in CASES:
        destination = a.output.parent / (name + ".json")
        args = [sys.executable,"-B","-m","kryptos",command,"--output",str(destination)]
        if request:
            args += ["--request",request]
        process = subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=15,check=False)
        assert process.returncode == 0, process.stderr
        result = json.loads(destination.read_text(encoding="utf-8"))
        candidates = result.get("candidates",[])
        if "optimization" in result:
            candidates = [result["optimization"]["candidate"]]
        for candidate in candidates:
            expected = result["explanation"]["input"]["ciphertext"]
            assert replay_recipe(candidate["plaintext"],candidate["encryption_recipe"])["ciphertext"] == expected
        if name == "columns-ragged":
            assert result["total_column_orders"] == 1 and candidates[0]["plaintext"] == "ABCDEFGHIJ"
        elif name == "general-five-stages":
            assert result["distinct_plaintext_count"] == 2 and result["evaluated"] == 2
        elif name == "alphabet-cycle":
            assert result["complete"] and result["total_alphabet_key_assignments"] == 12
        elif name == "optimize-small":
            assert result["optimization"]["search"]["optimal"]
        elif name == "layout-k4":
            assert len(result["cells"]) == 97 and result["cells"][0]["column"] == 27
        else:
            assert result["total_column_orders"] == 0 and result["default_geometry"]
        assert result["authenticated_solution"] is False
        records.append({"name":name,"command":args,"output":destination.relative_to(ROOT).as_posix() if destination.is_absolute() else destination.as_posix(),
                        "sha256":hashlib.sha256(destination.read_bytes()).hexdigest(),"replayed_candidates":len(candidates),"passed":True})
    with a.output.open("x",encoding="utf-8") as f:
        json.dump({"cases":records,"all_passed":True,"commands":len(records),"replayed_candidates":sum(r["replayed_candidates"] for r in records)},f,indent=2)
    print(json.dumps({"commands":len(records),"all_passed":True}))


if __name__ == "__main__":
    main()
