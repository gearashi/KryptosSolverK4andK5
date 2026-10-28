"""Private finite one-shot or persistent file-protocol worker."""
import argparse
import json
import os
from pathlib import Path
import time


def execute(job):
    if job["kind"]=="accelerated":
        from .accelerated import scan_batch
        return scan_batch(job["request"],backend=job["backend"],offset=int(job["offset"]),
                          batch_size=job["batch_size"],top=job["top"],
                          ranking_mode=job.get("ranking_mode","certified"))
    if job["kind"]=="family-identity":
        from .family_identity import describe_family
        return describe_family(job["request"])
    if job["kind"]=="alias-candidates":
        from .family_identity import replay_aliases
        return replay_aliases(job["request"],job["candidates"])
    if job["kind"]=="ping":
        return {"pid":os.getpid(),"protocol":"kryptos.private-worker.v1"}
    command=job["command"]
    from .research_methods import COMMANDS,execute as run_research_method
    if command in COMMANDS:
        return run_research_method(command,job["request"])
    if command in ("validate-holdout","validate-controls","validate-ablations"):
        from .validation_protocols import run_validation
        return run_validation(command,job["request"])
    from .advanced_cli import run_advanced
    from .__main__ import _target,run_recovery,run_layers,run_grid,run_residues
    from .next_cli import run_next
    if command=='joint-ranked':
        from .joint_ranked import run_joint_ranked
        return run_joint_ranked(job['request'],_target)
    first={"recover":run_recovery,"layers":run_layers,"grid":run_grid,"residues":run_residues}
    if command in first:
        return first[command](job["request"])
    if command in {"joint","scheduled","mixed","alphabet-plus","optimize-plus"}:
        return run_next(command,job["request"],_target)
    return run_advanced(command,job["request"],_target)


def persistent(folder):
    from .worker_pool import atomic_message,source_fingerprint,retry_file
    startup_sources=source_fingerprint()
    from .advanced_cli import json_safe_integers
    if startup_sources!=source_fingerprint():
        raise RuntimeError("sources changed during worker import")
    atomic_message(folder/"ready.json",{"pid":os.getpid(),"source_sha256":startup_sources})
    last_activity=time.monotonic()
    while True:
        request_path=folder/"request.json"
        if not request_path.exists():
            if time.monotonic()-last_activity>300:
                return  # Release an abandoned idle CUDA context eventually.
            time.sleep(0.015)
            continue
        envelope=json.loads(retry_file(lambda:request_path.read_text(encoding="utf-8")))
        retry_file(request_path.unlink)
        response={"id":envelope.get("id"),"source_sha256":startup_sources}
        stale=False
        try:
            if envelope.get("source_sha256")!=startup_sources or source_fingerprint()!=startup_sources:
                raise RuntimeError("persistent worker sources changed; restart required")
            result=execute(envelope["job"])
            if source_fingerprint()!=startup_sources:
                raise RuntimeError("sources changed during execution; result discarded")
            response.update(ok=True,result=json_safe_integers(result))
        except Exception as exc:
            response.update(ok=False,error=f"{type(exc).__name__}: {exc}")
            stale=source_fingerprint()!=startup_sources
        atomic_message(folder/"response.json",response)
        if stale:
            return
        last_activity=time.monotonic()


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--job",type=Path)
    p.add_argument("--output",type=Path)
    p.add_argument("--persistent",type=Path)
    args=p.parse_args()
    if args.persistent:
        if args.job or args.output:
            p.error("persistent and one-shot arguments are mutually exclusive")
        persistent(args.persistent.resolve())
    else:
        if not args.job or not args.output:
            p.error("one-shot mode requires --job and --output")
        from .advanced_cli import json_safe_integers
        job=json.loads(args.job.read_text(encoding="utf-8"))
        result=execute(job)
        with args.output.open("x",encoding="utf-8") as stream:
            json.dump(json_safe_integers(result),stream,allow_nan=False)
