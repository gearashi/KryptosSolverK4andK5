"""Run explicit bounded release controls through the external provenance runner."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-skill",type=Path,required=True)
    parser.add_argument("--label",default="release-L-001")
    args=parser.parse_args()
    if not args.label.replace("-","").isalnum():
        raise ValueError("Use an alphanumeric label")
    base=Path("research/runs")/args.label
    if (ROOT/base).exists():
        raise FileExistsError("Use a fresh label")
    package=sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/"kryptos").glob("*.py"))
    cache=ROOT/"runtime/cache"
    for name,part in (("TEMP","tmp"),("TMP","tmp"),("CUPY_CACHE_DIR","cupy")):
        (cache/part).mkdir(parents=True,exist_ok=True)
        os.environ[name]=str(cache/part)
    for name,script,extra,bounds in (
        ("accelerated","research/accelerated_benchmarks.py",["--cuda"],
         {"pages":3,"candidates_per_backend":6201,"retained_replay_and_objective_checks":60,"backends":["cpu","cuda"],"outer_seconds":90}),
        ("correlated","research/correlated_bound_benchmark.py",[],
         {"family_size":52,"all_partial_assignments":81,"integrated_implementations":2,"outer_seconds":30})):
        inputs=package+[script,"research/run_release_audits.py"]
        if name=="accelerated":
            inputs += ["tests/test_accelerated.py","research/models/multilingual-001/artifacts/pg1342-english-trigram.json"]
        else:
            inputs += ["research/source_snapshots/checkpoint-K-original/kryptos/"+s for s in ("search_runtime.py","language.py")]
        inputs=sorted(set(inputs))
        contract={"claim_id":"KRYPTOS-APP-L-"+name,"mathematics":{
            "assertion_tested":"Synthetic CPU/CUDA pages have independently verified retained integer objectives and literal reencryption" if name=="accelerated" else "Integrated correlated bounds equal exact local maxima for every partial assignment of the fixed family, with unchanged optimum",
            "coefficient_domain":"Z/26 letters via F2/F13; exact integer product scores; CUDA float64 shortlist only",
            "conventions":"1-based external cribs; zero-based internal indices; fixed model; CPU exact ranking, approximate CUDA shortlist unless all candidates rescored",
            "inputs":inputs,"bounds":bounds,
            "non_claims":["No K4/K5 decipherment or global exclusion","No general performance guarantee","Replay authenticates a specified recipe, not the sculpture's unknown method"]},
            "execution_artifacts":inputs,"software":[{"name":"Python","version":sys.version.split()[0]}],
            "randomness":{"used":False,"generator":"","seed":None}}
        contract_path=ROOT/"research"/(args.label+"-"+name+"-contract.json")
        with contract_path.open("x",encoding="utf-8") as handle:
            json.dump(contract,handle,indent=2)
        output=base/name
        result=output/"result.json"
        command=[sys.executable,str(args.audit_skill/"scripts/run_experiment.py"),"--root",str(ROOT),"--contract",str(contract_path),
                 "--output",output.as_posix(),"--result",result.as_posix(),"--timeout",str(bounds["outer_seconds"]),"--max-output-bytes","1048576","--max-threads","1"]
        for path in inputs:
            command += ["--input",path]
        command += ["--",sys.executable,"-B",script,"--output",result.as_posix(),*extra]
        subprocess.run(command,cwd=ROOT,check=True)
        subprocess.run([sys.executable,str(args.audit_skill/"scripts/validate_manifest.py"),str(ROOT/output/"manifest.json"),"--root",str(ROOT)],cwd=ROOT,check=True)

if __name__=="__main__":
    main()
