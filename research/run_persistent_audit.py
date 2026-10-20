"""Run the finite persistent-worker/CUDA comparison with a provenance manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.process_lifetime import launch_owned


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-skill",type=Path,required=True)
    parser.add_argument("--label",default="release-M-001")
    args=parser.parse_args()
    if not args.label.replace("-","").isalnum():
        raise ValueError("Use an alphanumeric/hyphen label")
    output=Path("research/runs")/args.label/"persistent"
    if (ROOT/output).exists():
        raise FileExistsError("Use a fresh audit output")
    inputs=sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/"kryptos").glob("*.py"))
    inputs += ["research/persistent_benchmarks.py","research/run_persistent_audit.py",
               "tests/test_accelerated.py","tests/test_worker_pool.py","tests/test_process_lifetime.py",
               "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"]
    snapshots=ROOT/"research/source_snapshots"/(args.label+"-persistent")
    snapshots.mkdir(parents=True)
    original={path:hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in inputs}
    for name in inputs:
        destination=snapshots/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,destination)
        if hashlib.sha256(destination.read_bytes()).hexdigest()!=original[name]:
            raise RuntimeError("source changed while taking the audit snapshot")
    contract={"claim_id":"KRYPTOS-APP-M-PERSISTENT-CERTIFIED","mathematics":{
        "assertion_tested":"For20 explicit synthetic pages, retained exact integer rankings agree across CPU/CUDA and one-shot/persistent workers; every retained score/recipe is independently replayed; active cancellation, crash and timeout recycle owned processes",
        "coefficient_domain":"Z/26 letters via F2/F13; exact integer product scores; integer-only outward-rounded log2 intervals on CUDA, followed by exact CPU overlap comparison",
        "conventions":"Zero-based mixed-radix pages; identical frozen model/window mask; lexical plaintext then assignment-index ties; timing includes process startup/shutdown, caches not flushed",
        "inputs":inputs,"bounds":{"pages_per_mode_backend":20,"candidates_per_page":256,"modes":["one-shot","persistent"],
            "backends":["cpu","cuda"],"scored_candidates_total":20480,"retained_independent_checks":240,
            "cancel_timeout_controls":2,"crash_control":1,"outer_seconds":180,"worker_timeout_seconds":60},
        "non_claims":["No K4/K5 search or authenticated plaintext","No general performance guarantee","No ranking guarantee outside the declared pages","A failed run is not evidence for correctness"]},
        "execution_artifacts":inputs,"software":[{"name":"Python","version":sys.version.split()[0]}],
        "randomness":{"used":False,"generator":"","seed":None}}
    contract_path=ROOT/"research"/(args.label+"-persistent-contract.json")
    with contract_path.open("x",encoding="utf-8") as stream:
        json.dump(contract,stream,indent=2)
    for name,part in (("TEMP","tmp"),("TMP","tmp"),("CUPY_CACHE_DIR","cupy")):
        cache=ROOT/"runtime/cache"/part
        cache.mkdir(parents=True,exist_ok=True)
        os.environ[name]=str(cache)
    result=output/"result.json"
    command=[sys.executable,str(args.audit_skill/"scripts/run_experiment.py"),"--root",str(ROOT),"--contract",str(contract_path),
             "--output",output.as_posix(),"--result",result.as_posix(),"--timeout","180","--max-output-bytes","1048576","--max-threads","1"]
    for name in inputs:
        command += ["--input",name]
    command += ["--",sys.executable,"-B","research/persistent_benchmarks.py","--cuda","--output",result.as_posix()]
    # The external runner kills its direct child on Windows. Own its whole tree
    # so a virtualenv redirector cannot leave the benchmark alive after timeout.
    auditor=launch_owned(command,cwd=ROOT,stdout=1,stderr=2)
    try:
        status=auditor.wait(timeout=195)
    finally:
        auditor.close()
    if status:
        raise subprocess.CalledProcessError(status,command)
    subprocess.run([sys.executable,str(args.audit_skill/"scripts/validate_manifest.py"),str(ROOT/output/"manifest.json"),"--root",str(ROOT)],cwd=ROOT,check=True)


if __name__=="__main__":
    main()
