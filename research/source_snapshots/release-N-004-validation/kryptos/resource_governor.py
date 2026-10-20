"""Deterministic, bounded page-boundary resource policy; no utilization promise."""
import math

MAX_EVENTS=1000

def validate_resources(values, backend="cpu"):
    if not isinstance(values,dict) or set(values)-{"workers","idle_ms","target_page_seconds","adaptive"}:
        raise ValueError("Unknown resource control")
    out=dict(values)
    for name,lo,hi in (("workers",1,4),("idle_ms",0,5000)):
        if name in out and (type(out[name]) is not int or not lo<=out[name]<=hi):
            raise ValueError(f"{name} must be an integer in {lo}..{hi}")
    if "adaptive" in out and type(out["adaptive"]) is not bool:
        raise ValueError("adaptive must be a boolean")
    if "target_page_seconds" in out:
        value=out["target_page_seconds"]
        if type(value) not in (float,int) or not math.isfinite(value) or not .1<=value<=10:
            raise ValueError("target_page_seconds must be in0.1..10")
    if backend in ("cuda","auto") and out.get("workers",1)!=1:
        raise ValueError("CUDA/auto uses one worker context")
    return out

def next_batch_size(current,seconds,target):
    """Aim at a duration; bounded factor2 steps and25% hysteresis avoid thrash."""
    if not math.isfinite(seconds) or seconds<=0:
        return current
    proposed=round(current*target/seconds)
    proposed=max(max(1,current//2),min(8192,current*2,proposed))
    return proposed if abs(proposed-current)>=max(1,current*.25) else current
