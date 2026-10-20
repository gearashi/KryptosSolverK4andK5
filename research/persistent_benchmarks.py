"""Twenty explicit synthetic pages: one-shot versus persistent end-to-end workers."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.accelerated import probe_backend
from kryptos.explanations import replay_recipe
from kryptos.language import CharacterNgramModel
from kryptos.parallel_search import _decode
from kryptos.process_lifetime import launch_owned
from kryptos.worker_pool import PersistentWorkerPool,WorkerCancelled,source_fingerprint


def projection(result):
    return [(c["plaintext"],c["score_exact"],c["assignment_index_decimal"]) for c in result["candidates"]]


def verify(result,model,ciphertext):
    p,q=float(model.alpha).as_integer_ratio()
    assert result["ranking_exact_within_page"] and result["ranking_mode"]=="certified"
    for candidate in result["candidates"]:
        word=candidate["plaintext"]
        objective=1
        for start in result["scoring"]["window_starts"]:
            objective*=model.counts.get(word[start:start+model.order],0)*q+p
        assert objective==int(candidate["score_exact"],16)
        assert replay_recipe(word,candidate["encryption_recipe"])["ciphertext"]==ciphertext


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--cuda",action="store_true")
    args=parser.parse_args()
    output=args.output.resolve()
    if output.exists():
        raise ValueError("a fresh result path is required")
    output.parent.mkdir(parents=True,exist_ok=True)
    artifacts=output.with_name(output.stem+"-files")
    artifacts.mkdir()
    sources_before=source_fingerprint()
    model_path=ROOT/"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
    model=CharacterNgramModel.from_json(model_path.read_text(encoding="utf-8-sig"))
    model_hash=hashlib.sha256(model_path.read_bytes()).hexdigest()
    readiness=probe_backend() if args.cuda else {"cpu":{"ready":True}}
    if args.cuda and not readiness["cuda"]["ready"]:
        raise RuntimeError("real CUDA is required for --cuda")
    text="ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL"
    request={"target":"custom","ciphertext":text,"cribs":[],"alphabet":"standard",
             "model_path":str(model_path),"stages":[{"operation":"substitution","period":3},
             {"operation":"gather","permutation":list(range(1,len(text)))+[0]}]}
    env=dict(os.environ)
    rows=[]
    retained_checks=0
    reference=None
    for backend in (("cpu","cuda") if args.cuda else ("cpu",)):
        jobs=[{"kind":"accelerated","request":request,"backend":backend,"offset":i*256,
               "batch_size":256,"top":3,"ranking_mode":"certified"} for i in range(20)]
        for mode in ("one-shot","persistent"):
            results=[]
            started=time.perf_counter()
            if mode=="one-shot":
                for index,job in enumerate(jobs):
                    job_path=artifacts/f"{backend}-{index}.job.json"
                    result_path=artifacts/f"{backend}-{index}.result.json"
                    job_path.write_text(json.dumps(job),encoding="utf-8")
                    error_path=artifacts/f"{backend}-{index}.stderr.txt"
                    with error_path.open("w",encoding="utf-8") as errors:
                        process=launch_owned([sys.executable,"-B","-m","kryptos.app_worker","--job",str(job_path),
                                              "--output",str(result_path)],cwd=ROOT,env=env,stderr=errors)
                        try:
                            process.wait(timeout=60)
                        finally:
                            process.close()
                    if process.returncode:
                        raise RuntimeError(error_path.read_text(encoding="utf-8")[-4096:])
                    results.append(_decode(json.loads(result_path.read_text(encoding="utf-8"))))
            else:
                with PersistentWorkerPool(1,folder=artifacts,env=env) as pool:
                    results=[pool.execute(job,timeout=60) for job in jobs]
            wall=time.perf_counter()-started
            for result in results:
                assert result["backend_used"]==backend and result["evaluated"]==256
                verify(result,model,text)
                retained_checks+=len(result["candidates"])
            current=[projection(result) for result in results]
            if reference is None:
                reference=current
            assert current==reference,"CPU/GPU or process-lifetime rankings differ"
            rows.append({"backend":backend,"mode":mode,"pages":20,"evaluated":5120,
                "wall_seconds":wall,"worker_reported_seconds":sum(r["elapsed_seconds"] for r in results),
                "exact_cpu_rescores":sum(r["cpu_exact_scored"] for r in results),
                "device_cache_hits":sum(bool(r.get("certification",{}).get("immutable_device_cache_hit")) for r in results),
                "retained":current,"first_candidate":results[0]["candidates"][0]})
    lifecycle={}
    with PersistentWorkerPool(1,folder=artifacts) as pool:
        before=pool.execute({"kind":"ping"})["pid"]
        started=time.monotonic()
        try:
            pool.execute({**jobs[0],"backend":"cpu","batch_size":4096},cancel=lambda:time.monotonic()-started>0.03)
            raise AssertionError("bounded long CPU job completed before cancellation control")
        except WorkerCancelled:
            pass
        cancelled=pool.execute({"kind":"ping"})["pid"]
        assert cancelled!=before
        pool._slots[0].process.kill()
        pool._slots[0].process.wait(timeout=5)
        restarted=pool.execute({"kind":"ping"})["pid"]
        assert restarted!=cancelled
        try:
            pool.execute({**jobs[0],"backend":"cpu","batch_size":4096},timeout=0.02)
            raise AssertionError("bounded CPU job unexpectedly completed before timeout")
        except TimeoutError:
            pass
        timeout_restart=pool.execute({"kind":"ping"})["pid"]
        assert timeout_restart!=restarted
        lifecycle={"active_cancel_killed_worker":True,"crash_restarted":True,"timeout_restarted":True,
                   "pids":[before,cancelled,restarted,timeout_restart]}
    assert sources_before==source_fingerprint(),"source changed during benchmark"
    assert model_hash==hashlib.sha256(model_path.read_bytes()).hexdigest()
    result={"schema":"kryptos.persistent-audit.v1","passed":True,"created_utc":datetime.now(timezone.utc).isoformat(),
            "scope":"20 fixed synthetic pages of256 candidates per mode/backend; no K4/K5 search; end-to-end includes process startup and shutdown. OS/file caches are not cleared; modes run in declared order.",
            "argv":sys.argv,"python":sys.version,"platform":platform.platform(),"readiness":readiness,
            "request":request,"source_sha256":sources_before,"model_sha256":model_hash,
            "benchmark_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "independent_retained_score_recipe_checks":retained_checks,"records":rows,"lifecycle":lifecycle}
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,allow_nan=False)
        stream.write("\n")
    print(json.dumps({"passed":True,"output":str(output),"checks":retained_checks,
        "timings":[{k:r[k] for k in ("backend","mode","wall_seconds","exact_cpu_rescores","device_cache_hits")} for r in rows]}))


if __name__=="__main__":
    main()
