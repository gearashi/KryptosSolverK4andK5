"""Bounded, paged CPU/CUDA scanning of exact general/scheduled affine families.

CPU selection uses integer products. Certified CUDA uses integer interval sums
and CPU exact comparison of every candidate that might cross the cutoff.
Approximate float64 shortlisting remains an explicit opt-in mode.
"""
from functools import lru_cache
from copy import deepcopy
import hashlib
import heapq
import json
import math
from pathlib import Path
import platform
import time

from .cuda_environment import load_cupy, prepare_cuda_environment

SCHEMA = "kryptos.accelerated-scan.v1"
ROOT = Path(__file__).resolve().parents[1]
MAX_BATCH = 65536
MAX_LETTER_OPERATIONS = 50_000_000
MAX_WINDOWS = 5_000_000
MAX_SCORE_BITS = 4_000_000


class _ReverseLex(str):
    def __lt__(self, other):
        return str.__gt__(self, other)

    def __gt__(self, other):
        return str.__lt__(self, other)


def _integer(value, name, low, high=None):
    if type(value) is not int or value < low or (high is not None and value > high):
        raise ValueError(f"{name} must be an integer >= {low}" + (f" and <= {high}" if high is not None else ""))
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _digits(index, domains):
    values = [0] * len(domains)
    for i in range(len(domains)-1, -1, -1):
        index, values[i] = divmod(index, domains[i])
    if index:
        raise ValueError("index lies beyond the affine family")
    return values


@lru_cache(maxsize=2)
def _prepare(serialized, model_sha, source_sha):
    from .__main__ import _target
    from .next_cli import _optimization_job
    job = _optimization_job(json.loads(serialized), _target)
    if job["model_sha256"] != model_sha:
        raise ValueError("scoring model changed while preparing scan; retry with a stable file")
    if job["solution"] is not None and job["solution"].feasible:
        job["accelerated_affine"] = job["solution"].affine_plaintext()
        job["accelerated_scoring"] = _scoring(job,job["accelerated_affine"])
        job["cuda_static"] = {}
    return job


def _scoring(job, affine):
    model, alphabet = job["model"], affine["alphabet"]
    mask = set(job.get("score_mask",job["known"]))
    starts = [i for i in range(len(affine["base"])-model.order+1)
              if all(j not in mask for j in range(i, i+model.order))]
    indices = {c: i for i, c in enumerate(alphabet)}
    codes = {}
    for gram, count in model.counts.items():
        code = 0
        for c in gram:
            code = code * 26 + indices[c]
        codes[code] = count
    p, q = float(model.alpha).as_integer_ratio()
    return starts, codes, p, q


def _objective(letters, starts, order, codes, p, q):
    result = 1
    for start in starts:
        code = 0
        for pos in range(start, start+order):
            code = code * 26 + letters[pos]
        result *= codes.get(code, 0) * q + p
    return result


def _cpu_rank(affine, offset, count, keep, scoring, order):
    """Odometer updates touch only nonzero entries of changed coordinates."""
    domains, columns = affine["domains"], affine["columns"]
    values = _digits(offset, domains)
    letters = [(base + sum(col[i]*v for col, v in zip(columns, values))) % 26
               for i, base in enumerate(affine["base"])]
    sparse = [[(i, x) for i, x in enumerate(col) if x] for col in columns]
    starts, codes, p, q = scoring
    heap = []
    changed_entries = 0
    for local in range(count):
        score = _objective(letters, starts, order, codes, p, q)
        word = _ReverseLex("".join(affine["alphabet"][x] for x in letters))
        entry = (score, word, -(offset+local))
        if len(heap) < keep:
            heapq.heappush(heap, entry)
        elif entry > heap[0]:
            heapq.heapreplace(heap, entry)
        if local+1 == count:
            break
        for slot in range(len(values)-1, -1, -1):
            old = values[slot]
            values[slot] = (old+1) % domains[slot]
            delta = values[slot]-old
            for pos, coefficient in sparse[slot]:
                letters[pos] = (letters[pos]+coefficient*delta) % 26
                changed_entries += 1
            if values[slot]:
                break
    return [(score, -negative) for score, word, negative in sorted(heap, key=lambda x: (-x[0], str(x[1]), -x[2]))], changed_entries


CUDA_SOURCE = r'''
extern "C" __global__ void coordinates(const unsigned char* origin,
    const unsigned char* domains, unsigned char* values, int d, int batch) {
    int row = blockDim.x * blockIdx.x + threadIdx.x;
    if (row >= batch) return;
    unsigned int carry = row;
    for (int k=d-1; k>=0; --k) {
        carry += origin[k];
        values[row*d+k] = carry % domains[k];
        carry /= domains[k];
    }
}
extern "C" __global__ void letters(const unsigned char* base,
    const unsigned char* columns, const unsigned char* values,
    unsigned char* output, int n, int d, int batch) {
    int pos = blockDim.x * blockIdx.x + threadIdx.x;
    if (pos >= n*batch) return;
    int row = pos/n, i = pos%n, value = base[i];
    for (int k=0; k<d; ++k) value += columns[k*n+i]*values[row*d+k];
    output[pos] = value%26;
}
extern "C" __global__ void score(const unsigned char* text, const int* starts,
    const unsigned long long* codes, const double* logs, double unseen,
    double* scores, int n, int batch, int windows, int order, int observed) {
    int row = blockDim.x * blockIdx.x + threadIdx.x;
    if (row >= batch) return;
    double total = 0;
    for (int w=0; w<windows; ++w) {
        unsigned long long code = 0;
        for (int j=0; j<order; ++j) code = code*26+text[row*n+starts[w]+j];
        int low=0, high=observed;
        while (low<high) { int mid=low+(high-low)/2;
            if (codes[mid]<code) low=mid+1; else high=mid; }
        total += low<observed && codes[low]==code ? logs[low] : unseen;
    }
    scores[row] = total;
}
extern "C" __global__ void readiness(int* out) { out[0] = 7*6; }
extern "C" __global__ void interval_score(const unsigned char* text, const int* starts,
    const unsigned long long* codes, const unsigned long long* low_table,
    const unsigned long long* high_table, unsigned long long unseen_low,
    unsigned long long unseen_high, unsigned long long* lower,
    unsigned long long* upper, int n, int batch, int windows, int order, int observed) {
    int row = blockDim.x * blockIdx.x + threadIdx.x;
    if (row >= batch) return;
    unsigned long long low_total=0, high_total=0;
    for (int w=0; w<windows; ++w) {
        unsigned long long code=0;
        for (int j=0; j<order; ++j) code=code*26+text[row*n+starts[w]+j];
        int low=0, high=observed;
        while (low<high) { int mid=low+(high-low)/2;
            if (codes[mid]<code) low=mid+1; else high=mid; }
        bool found=low<observed && codes[low]==code;
        low_total += found ? low_table[low] : unseen_low;
        high_total += found ? high_table[low] : unseen_high;
    }
    lower[row]=low_total;
    upper[row]=high_total;
}
'''


@lru_cache(maxsize=4)
def _kernels(device_id):
    cp = load_cupy()
    module = cp.RawModule(code=CUDA_SOURCE, options=("--std=c++11",))
    return {name: module.get_function(name) for name in ("coordinates", "letters", "score", "interval_score", "readiness")}


def probe_backend():
    """Run a one-thread compiled kernel; importing CuPy alone is insufficient."""
    result = {"cpu": {"ready": True, "python": platform.python_version()},
              "cuda": {"ready": False, "devices": []}}
    try:
        result["cuda"]["environment"] = prepare_cuda_environment()
        cp = load_cupy()
        result["cuda"]["cupy_version"] = cp.__version__
        result["cuda"]["driver_version"] = cp.cuda.runtime.driverGetVersion()
        result["cuda"]["runtime_version"] = cp.cuda.runtime.runtimeGetVersion()
        for number in range(cp.cuda.runtime.getDeviceCount()):
            properties = cp.cuda.runtime.getDeviceProperties(number)
            name = properties["name"]
            result["cuda"]["devices"].append({"id": number, "name": name.decode() if isinstance(name, bytes) else name,
                "compute_capability": [properties["major"], properties["minor"]],
                "total_memory_bytes": properties["totalGlobalMem"]})
        if not result["cuda"]["devices"]:
            raise RuntimeError("no CUDA device")
        output = cp.zeros(1, dtype=cp.int32)
        _kernels(cp.cuda.Device().id)["readiness"]((1,), (1,), (output,))
        if output.get().tolist() != [42]:
            raise RuntimeError("compiled CUDA readiness kernel returned an incorrect result")
        result["cuda"].update(ready=True, compiled_kernel_verified=True, current_device=cp.cuda.Device().id)
    except Exception as exc:
        result["cuda"].update(error_type=type(exc).__name__, error=str(exc), compiled_kernel_verified=False)
    return result


def _cuda_tables(affine,job,scoring,ranking_mode):
    """Per-family/device immutable arrays survive pages in persistent workers."""
    cp = load_cupy()
    from .certified_scores import log2_interval
    device=cp.cuda.Device().id
    key=(device,ranking_mode)
    if key in job["cuda_static"]:
        return job["cuda_static"][key],True
    starts,codes,p,q=scoring
    model = job["model"]
    index = {c: i for i, c in enumerate(affine["alphabet"])}
    encoded_logs = {}
    for gram, value in model._log_probabilities.items():
        code = 0
        for c in gram:
            code = code*26+index[c]
        encoded_logs[code] = value
    observed = sorted(codes)
    arrays = [cp.asarray(value, dtype=dtype) for value, dtype in (
        (affine["domains"], cp.uint8),
        (affine["base"], cp.uint8), (affine["columns"], cp.uint8),
        (starts, cp.int32), (observed, cp.uint64), ([encoded_logs[c] for c in observed], cp.float64))]
    tables={"arrays":arrays,"observed":len(observed)}
    if ranking_mode=="certified":
        bounds=[log2_interval(codes[code]*q+p) for code in observed]
        unseen=log2_interval(p)
        maximum=max([unseen[1]]+[bound[1] for bound in bounds])
        if maximum*len(starts)>2**64-1:
            raise ValueError("certified GPU interval sum would exceed uint64")
        tables.update(low=cp.asarray([a for a,b in bounds],dtype=cp.uint64),
                      high=cp.asarray([b for a,b in bounds],dtype=cp.uint64),unseen=unseen)
    job["cuda_static"][key]=tables
    return tables,False


def _cuda_rank(affine, job, offset, count, keep, scoring,ranking_mode="certified"):
    cp = load_cupy()
    import numpy as np
    from .certified_scores import FRACTIONAL_BITS,overlapping_indices
    n,d=len(affine["base"]),len(affine["domains"])
    starts,codes,_,_=scoring
    model=job["model"]
    tables,cache_hit=_cuda_tables(affine,job,scoring,ranking_mode)
    domains,base,columns,windows,gram_codes,logs=tables["arrays"]
    origin=cp.asarray(_digits(offset,affine["domains"]),dtype=cp.uint8)
    values = cp.empty((count, d), dtype=cp.uint8)
    text = cp.empty((count, n), dtype=cp.uint8)
    kernels = _kernels(cp.cuda.Device().id)
    args = lambda *xs: tuple(np.int32(x) for x in xs)
    kernels["coordinates"](((count+127)//128,), (128,), (origin, domains, values, *args(d, count)))
    kernels["letters"](((count*n+127)//128,), (128,), (base, columns, values, text, *args(n, d, count)))
    certification={"mode":ranking_mode,"immutable_device_cache_hit":cache_hit}
    if ranking_mode=="certified":
        lower=cp.empty(count,dtype=cp.uint64)
        upper=cp.empty(count,dtype=cp.uint64)
        kernels["interval_score"](((count+127)//128,),(128,),(text,windows,gram_codes,tables["low"],tables["high"],
            np.uint64(tables["unseen"][0]),np.uint64(tables["unseen"][1]),lower,upper,
            *args(n,count,len(starts),model.order,tables["observed"])))
        lower_values,upper_values=lower.get().tolist(),upper.get().tolist()
        selected,threshold=overlapping_indices(lower_values,upper_values,keep)
        pool=len(selected)
        certification.update(method="integer outward-rounded log2 intervals plus exact CPU overlap comparison",
            fractional_bits=FRACTIONAL_BITS,threshold_lower_hex=hex(threshold),interval_candidates=pool,
            eliminated_candidates=count-pool,max_interval_width_hex=hex(max(b-a for a,b in zip(lower_values,upper_values))))
    else:
        scores=cp.empty(count,dtype=cp.float64)
        kernels["score"](((count+127)//128,), (128,), (text, windows, gram_codes, logs,
            np.float64(model._unknown_log_probability), scores, *args(n, count, len(starts), model.order,tables["observed"])))
        raw_scores = scores.get().tolist()
        if any(not math.isfinite(x) for x in raw_scores):
            raise RuntimeError("CUDA returned nonfinite ranking scores")
        pool = min(count, max(64, keep*4))
        selected = heapq.nsmallest(pool, range(count), key=lambda i: (-raw_scores[i], i))
    actual_letters = text[cp.asarray(selected, dtype=cp.int32)].get().tolist()
    exact = []
    for local, gpu_letters in zip(selected, actual_letters):
        point = _digits(offset+local, affine["domains"])
        expected = [(x+sum(col[i]*v for col, v in zip(affine["columns"], point))) % 26
                    for i, x in enumerate(affine["base"])]
        if gpu_letters != expected:
            raise RuntimeError("CUDA candidate letters failed independent CPU affine verification")
        exact.append((_objective(expected, starts, model.order, *scoring[1:]), offset+local,
                      "".join(affine["alphabet"][x] for x in expected)))
    exact.sort(key=lambda item: (-item[0], item[2], item[1]))
    certification["exact_scored_candidates"]=pool
    return [(score, index) for score, index, word in exact[:keep]], pool,certification


def scan_batch(request, backend="cpu", offset=0, batch_size=1024, top=10,ranking_mode="certified"):
    """Scan [offset,next_offset), not the entire family; resume using next_offset.

    Explicit CUDA failure raises RuntimeError; ``auto`` alone permits CPU fallback.
    Every result carries decimal-string offsets/counts for lossless browser use.
    ``complete`` means this page reaches the family end, not earlier-page coverage.
    """
    started = time.perf_counter()
    if backend not in ("cpu", "cuda", "auto"):
        raise ValueError("backend must be cpu, cuda or auto")
    if ranking_mode not in ("certified","approximate"):
        raise ValueError("ranking_mode must be certified or approximate")
    _integer(offset, "offset", 0)
    _integer(batch_size, "batch_size", 1, MAX_BATCH)
    _integer(top, "top", 1, 100)
    from .next_cli import BASE, LINEAR_LIMITS, SEARCH_LIMITS, _check, _verify
    from .advanced_cli import _candidate
    _check(request, BASE | LINEAR_LIMITS | SEARCH_LIMITS | {"stages", "alphabet", "cells", "layer_model", "model_path","score_mask"})
    path = request.get("model_path")
    if not isinstance(path, str):
        raise ValueError("an explicit frozen model_path is required")
    path = Path(path).resolve()
    if path.stat().st_size > 32*1024*1024:
        raise ValueError("model exceeds32MiB")
    model_sha = _hash(path.read_bytes())
    source_hashes = {p.name: _hash(p.read_bytes()) for p in sorted((ROOT/"kryptos").glob("*.py"))}
    normalized = dict(request, model_path=str(path))
    job = _prepare(_canonical(normalized), model_sha, _hash(_canonical(source_hashes).encode()))
    result = {"schema": SCHEMA, "target": job["target"], "candidates": [], "offset": offset,
        "offset_decimal": str(offset), "evaluated": 0, "backend_requested": backend, "backend_used": None,
        "ranking_mode":ranking_mode,
        "authenticated_solution": False, "model_file_sha256": model_sha, "model_id": job["model"].model_id,
        "phase_provenance": deepcopy(job["phase_provenance"]), "source_sha256": source_hashes,
        "request_sha256": _hash(_canonical(request).encode()), "supplied_request": request,
        "bounds": {"batch_size": batch_size, "top": top, "max_letter_operations": MAX_LETTER_OPERATIONS,
                   "max_window_evaluations": MAX_WINDOWS, "max_score_bits": MAX_SCORE_BITS},
        "paging_convention": "F2 coordinates then F13; rightmost coordinate fastest. complete means page reaches family end; no earlier coverage is implied.",
        "score_interpretation": "Frozen joint ngram ranking excludes every window touching the explicit score mask, which includes all supplied crib positions. Scores and re-encryption never authenticate plaintext."}
    if job["algebra_budget"] is not None:
        result.update(feasible=None, total=None, total_decimal=None, complete=False, next_offset=offset,
                      next_offset_decimal=str(offset), stop_reason="algebra_budget", algebra=deepcopy(job["algebra_budget"]))
        return result
    solution = job["solution"]
    total = solution.distinct_plaintext_count
    if offset > total:
        raise ValueError("offset exceeds the distinct plaintext family")
    count = min(batch_size, total-offset)
    result.update(feasible=solution.feasible, total=total, total_decimal=str(total),
        next_offset=offset+count, next_offset_decimal=str(offset+count), complete=offset+count==total,
        family=solution.summary(), ignored_optimizer_fields=sorted(set(request) & SEARCH_LIMITS))
    if not solution.feasible or not count:
        result.update(stop_reason="exact_contradiction" if not solution.feasible else "end_of_family", elapsed_seconds=time.perf_counter()-started)
        return result
    affine = job["accelerated_affine"]
    scoring = job["accelerated_scoring"]
    starts, codes, p, q = scoring
    operations = count*len(affine["base"])*(len(affine["domains"])+1)
    if operations > MAX_LETTER_OPERATIONS or count*len(starts) > MAX_WINDOWS:
        raise ValueError("batch exceeds the work cap; request a smaller batch_size")
    if len(starts)*(max(codes.values())*q+p).bit_length() > MAX_SCORE_BITS:
        raise ValueError("frozen model/text exceeds exact score bit cap")
    score_mask=job.get("score_mask",job["known"])
    result["scoring"] = {"windows": len(starts), "excluded_positions": sorted(score_mask),
        "window_starts": starts, "score_available": bool(starts), "exact_objective": "product(count*q+p)",
        "p_hex": hex(p), "q_hex": hex(q), "denominator_common_within_model_mask_family": True}
    used = backend
    if backend == "auto":
        readiness = probe_backend()
        used = "cuda" if readiness["cuda"]["ready"] else "cpu"
        if used == "cpu":
            result["fallback_reason"] = readiness["cuda"].get("error", "CUDA unavailable")
    if used == "cuda":
        try:
            ranked, rescored,certification = _cuda_rank(affine, job, offset, count, min(top, count), scoring,ranking_mode)
            result["certification"]=certification
        except Exception as exc:
            if backend != "auto":
                raise RuntimeError(f"CUDA scan failed: {exc}") from exc
            used = "cpu"
            result["fallback_reason"] = f"CUDA scan failed: {exc}"
    if used == "cpu":
        ranked, changed = _cpu_rank(affine, offset, count, min(top, count), scoring, job["model"].order)
        rescored = count
        result["work"] = {"incremental_letter_updates": changed}
    result.update(backend_used=used, evaluated=count, stop_reason="page_complete", cpu_exact_scored=rescored,
        ranking_exact_within_page=used=="cpu" or ranking_mode=="certified" or rescored==count,
        ranking_method="exact integer product" if used=="cpu" else ("CUDA certified interval filtering followed by CPU exact comparison" if ranking_mode=="certified" else "CUDA float64 shortlist followed by CPU exact rescoring"),
        ranking_scope="this page only; merge separately across pages with the same request/model/source hashes")
    for objective, index in ranked:
        values = _digits(index, affine["domains"])
        candidate = solution.candidate(values[:solution.dimensions_mod2], values[solution.dimensions_mod2:])
        if job["layer_model"] == "general":
            candidate = _candidate(candidate, job["stages"], solution.alphabet, job["text"], job["known"])
        candidate = _verify(candidate, job["text"], job["known"])
        from .score_sensitivity import report as sensitivity_report
        candidate["score_sensitivity"] = sensitivity_report(solution,job["model"],candidate["plaintext"],job["known"])
        display_score = job["model"].score(candidate["plaintext"], score_mask).to_dict()
        candidate.update(index=index, index_decimal=str(index), assignment_index_decimal=str(index),
            exact_objective_hex=hex(objective), score_exact=hex(objective), score=display_score["mean_log_probability"],
            display_model_score=display_score,
            technique="Exact crib-constrained affine family; deterministic mixed-radix page; frozen crib-masked ngram ranking; CPU literal recipe replay.",
            classification="ranked_model_consistency_witness")
        result["candidates"].append(candidate)
    result["elapsed_seconds"] = time.perf_counter()-started
    return result
