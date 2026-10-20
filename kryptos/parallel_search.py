"""Deterministic CPU batches of independent lazy-product searches.

Each worker owns a complete job and its own optional checkpoint. Results are
returned in job-id order; no cross-process floating reduction or shared journal.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from .search_runtime import optimize_lazy,_validate


ALLOWED_OPTIONS={"max_nodes","time_limit_seconds","max_frontier","max_cache_entries",
                 "local_exact_limit","ordering","resume_path","checkpoint_path","factor_group_size","group_exact_limit",
                 "decomposition","decomposition_max_entries","decomposition_max_operations"}


def _one(job):
    result=optimize_lazy(job["problem"],**job.get("options",{}))
    return {"id":job["id"],"worker_pid":os.getpid(),"result":result}


def _decode(value):
    if isinstance(value,dict):
        if set(value)=={"encoding","value"} and value["encoding"]=="exact_integer_hex":
            return int(value["value"],16)
        return {k:_decode(v) for k,v in value.items()}
    if isinstance(value,list):
        return [_decode(v) for v in value]
    return value


def _process_job(item):
    job_path,result_path=item
    flags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
    process=subprocess.run([sys.executable,"-B","-m","kryptos.parallel_search","--job",str(job_path),"--result",str(result_path)],
        cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,creationflags=flags,check=False)
    if process.returncode:
        raise RuntimeError("batch worker failed: "+process.stderr[-4000:])
    return _decode(json.loads(result_path.read_text(encoding="utf-8")))


def optimize_batch(jobs,*,workers=1):
    if type(workers) is not int or not 1<=workers<=4:
        raise ValueError("workers must be in1..4")
    if not isinstance(jobs,list) or not 1<=len(jobs)<=32:
        raise ValueError("batch needs1..32 jobs")
    ids=set()
    outputs=set()
    inputs=set()
    normalized=[]
    for job in jobs:
        if not isinstance(job,dict) or set(job)-{"id","problem","options"} or not {"id","problem"}<=set(job):
            raise ValueError("job requires id and problem")
        if not isinstance(job["id"],str) or not job["id"] or len(job["id"])>128 or job["id"] in ids:
            raise ValueError("job IDs must be unique nonempty strings up to128characters")
        ids.add(job["id"])
        _validate(job["problem"])
        options=job.get("options",{})
        if not isinstance(options,dict) or set(options)-ALLOWED_OPTIONS:
            raise ValueError("invalid batch search options")
        options=dict(options)
        seconds=options.get("time_limit_seconds",10)
        if isinstance(seconds,bool) or not isinstance(seconds,(int,float)) or not 0<seconds<=30:
            raise ValueError("each batch job needs a cooperative time limit in(0,30]")
        for field,container in (("checkpoint_path",outputs),("resume_path",inputs)):
            if options.get(field) is not None:
                options[field]=str(Path(options[field]).resolve())
                path=options[field].casefold()
                if field=="checkpoint_path" and path in outputs:
                    raise ValueError("workers cannot share a checkpoint output")
                container.add(path)
        normalized.append({**job,"options":options})
    if outputs&inputs:
        raise ValueError("batch outputs cannot overwrite any resume input")
    ordered=sorted(normalized,key=lambda j:j["id"])
    if workers==1:
        records=[_one(job) for job in ordered]
    else:
        # Explicit subprocesses avoid Windows named-pipe ACL failures in
        # restricted environments. Threads only dispatch; scoring uses CPUs
        # in separate hidden Python processes with private immutable inputs.
        folder=Path(__file__).resolve().parents[1]/"research"/(".batch-"+uuid.uuid4().hex)
        folder.mkdir()
        try:
            work=[]
            for number,job in enumerate(ordered):
                job_path=folder/(str(number)+"-job.json")
                result_path=folder/(str(number)+"-result.json")
                with job_path.open("x",encoding="utf-8") as stream:
                    json.dump(job,stream,allow_nan=False)
                work.append((job_path,result_path))
            with ThreadPoolExecutor(max_workers=min(workers,len(jobs))) as executor:
                records=list(executor.map(_process_job,work))
        finally:
            for path in folder.iterdir():
                path.unlink()
            folder.rmdir()
    return {"jobs":records,"workers_requested":workers,"job_count":len(records),
            "all_searches_complete":all(row["result"]["complete"] for row in records),
            "all_objectives_proved_optimal":all(row["result"]["optimal"] for row in records),
            "ordering":"ascending job ID; per-job original-coordinate lexical tie break",
            "interpretation":"Independent jobs, not counts of disjoint cipher families. Time-limited progress can vary with hardware; complete answers and ties must agree."}


if __name__=="__main__":
    import argparse
    from .advanced_cli import json_safe_integers
    parser=argparse.ArgumentParser()
    parser.add_argument("--job",required=True,type=Path)
    parser.add_argument("--result",required=True,type=Path)
    args=parser.parse_args()
    if args.job.stat().st_size>64*1024*1024:
        parser.error("job exceeds64MiB")
    job=json.loads(args.job.read_text(encoding="utf-8"))
    # Reuse public validation, including checkpoint ownership rules.
    result=optimize_batch([job],workers=1)["jobs"][0]
    with args.result.open("x",encoding="utf-8") as stream:
        json.dump(json_safe_integers(result),stream,allow_nan=False)
