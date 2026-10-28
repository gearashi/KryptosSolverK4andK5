"""Bounded hardware comparison on identical real K4 affine-family pages.

Run only after source freeze: python -B research/hardware_Q.py --out <new-dir>
Uses all visible logical CPU processors (up to32) and actual CUDA. No fallback.
Throughput is a resource recommendation, not a search-efficiency improvement.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.worker_pool import PersistentWorkerPool,source_fingerprint
from kryptos.resource_governor import hardware_worker_limit


def dump(path,value):
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+"\n",encoding="utf-8")


def ranked(rows):
    candidates={c["plaintext"]:c for row in rows for c in row["candidates"]}
    values=sorted(candidates.values(),key=lambda c:(-int(c["score_exact"],16),c["plaintext"],int(c["index_decimal"])))[:20]
    return [(c["score_exact"],c["plaintext"],c["index_decimal"]) for c in values]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    output=args.out.resolve()
    if not output.is_relative_to(ROOT):raise ValueError("output must be within this project")
    output.mkdir(parents=True,exist_ok=False)
    before=source_fingerprint()
    request={"target":"k4","alphabet":"kryptos","stages":[{"operation":"substitution","period":28}],
             "model_path":"research/runs/evaluation-J-001/artifacts/english-two-author-trigram.json"}
    model_hash=hashlib.sha256((ROOT/request["model_path"]).read_bytes()).hexdigest()
    contract={"created_utc":datetime.now(timezone.utc).isoformat(),"request":request,"model_sha256":model_hash,
              "assertion_tested":"Identical certified top20 for the first32768 distinct plaintexts across CPU worker counts/page sizes and actual CUDA; every retained candidate has literal replay.",
              "cpu_workers":sorted({1,min(4,hardware_worker_limit()),hardware_worker_limit()}),
              "cpu_page_sizes":[2048],"cuda_page_sizes":[512,2048,8192],"candidates_per_configuration":32768,
              "warmup":"One256-candidate page per worker, excluded from timed throughput but explicitly counted.",
              "non_claims":["Not a completed K4 family search or a decipherment","No search decision reduction from hardware speed","GPU utilization can be limited by certified CPU rescoring and tiny kernels"]}
    dump(output/"contract.json",contract)
    hardware={"python":sys.version,"platform":platform.platform(),"logical_processors":os.cpu_count(),
              "nvidia_smi":subprocess.run(["nvidia-smi","--query-gpu=name,memory.total,driver_version","--format=csv,noheader"],capture_output=True,text=True,timeout=10).stdout.strip()}
    env=dict(os.environ,PYTHONUTF8="1",PYTHONDONTWRITEBYTECODE="1")
    for key in list(env):
        if key.upper().startswith("CUDA_PATH"):del env[key]
    cache=ROOT/"runtime"/"hardware-Q-cache"
    cache.mkdir(parents=True,exist_ok=True)
    env.update(TEMP=str(cache),TMP=str(cache),CUPY_CACHE_DIR=str(cache/"cupy"))
    configs=[("cpu",w,2048) for w in contract["cpu_workers"]]+[("cuda",1,p) for p in contract["cuda_page_sizes"]]
    telemetry=[];stop=threading.Event()
    def monitor():
        while not stop.is_set():
            r=subprocess.run(["nvidia-smi","--query-gpu=utilization.gpu,temperature.gpu,memory.used,power.draw","--format=csv,noheader,nounits"],capture_output=True,text=True,timeout=10)
            telemetry.append({"monotonic":time.monotonic(),"gpu":r.stdout.strip()})
            stop.wait(.5)
    monitor_thread=threading.Thread(target=monitor,daemon=True);monitor_thread.start()
    records=[];reference=None
    try:
        for backend,workers,page in configs:
            pool=PersistentWorkerPool(workers,folder=cache,env=env,cwd=ROOT)
            def job(offset,size):return {"kind":"accelerated","backend":backend,"request":request,"offset":offset,"batch_size":size,"top":20,"ranking_mode":"certified"}
            try:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    warm=list(executor.map(lambda i:pool.execute(job(i*256,256),timeout=60),range(workers)))
                    start=time.perf_counter()
                    rows=list(executor.map(lambda offset:pool.execute(job(offset,page),timeout=60),range(0,32768,page)))
                    elapsed=time.perf_counter()-start
                assert all(r["backend_used"]==backend and r["ranking_exact_within_page"] for r in rows+warm)
                assert sum(r["evaluated"] for r in rows)==32768
                assert all(c["evidence"]["literal_reencryption_matches"] for r in rows for c in r["candidates"])
                answer=ranked(rows)
                if reference is None:reference=answer
                assert answer==reference,"CPU/CUDA global top20 mismatch"
                record={"backend":backend,"workers":workers,"batch_size":page,"seconds":elapsed,
                        "candidates":32768,"candidates_per_second":32768/elapsed,"warmup_candidates":sum(r["evaluated"] for r in warm),
                        "exact_cpu_comparisons":sum(r["cpu_exact_scored"] for r in rows),"ranking_matches_reference":True,
                        "worker_pids":[slot.process.pid for slot in pool._slots],
                        "page_seconds":[r["elapsed_seconds"] for r in rows],"top20":answer}
                records.append(record);dump(output/f"{backend}-{workers}-{page}.json",record)
                print(json.dumps({k:record[k] for k in ("backend","workers","batch_size","seconds","candidates_per_second")}),flush=True)
            finally:pool.close()
        assert source_fingerprint()==before,"Sources changed during benchmark"
        assert hashlib.sha256((ROOT/request["model_path"]).read_bytes()).hexdigest()==model_hash
        best=max(records,key=lambda r:r["candidates_per_second"])
        dump(output/"result.json",{"status":"completed","hardware":hardware,"configurations":records,
             "recommendation":{k:best[k] for k in ("backend","workers","batch_size")},"source_before":before,"source_after":source_fingerprint(),"contract":contract})
    except BaseException as error:
        dump(output/"failure.json",{"status":"failed","error":str(error),"completed_configurations":records,"source_before":before,"source_after":source_fingerprint()})
        raise
    finally:
        stop.set();monitor_thread.join(12);dump(output/"telemetry.json",telemetry)


if __name__=="__main__":main()
