"""Small independent read-only audit of lazy bounds, frontiers and CPU batches.

Creates a fresh result and nearby checkpoint evidence; does not edit sources.
Run: python research/search_runtime_audit_K.py --output NEW_PATH.json
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import platform
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kryptos import search_runtime
from kryptos.parallel_search import optimize_batch


def literal(problem, point):
    """Independent integer objective; no bound/evaluator/score helper calls."""
    answer = 1
    for factor in problem["factors"]:
        coordinates = [point[i] for i in factor["scope"]]
        if factor["kind"] == "table":
            offset = 0
            for i, value in zip(factor["scope"], coordinates):
                offset = offset * problem["domains"][i] + value
            value = factor["values"][offset]
        else:
            model = problem["model"]
            letters = []
            for j, base in enumerate(factor["base"]):
                residue = base
                for column, coordinate in zip(factor["columns"], coordinates):
                    residue += column[j] * coordinate
                letters.append(model["alphabet"][residue % 26])
            value = model["counts"].get("".join(letters), 0) * model["q"] + model["p"]
        answer *= value ** factor.get("power", 1)
    return answer


def run(output):
    files = ["kryptos/search_runtime.py", "kryptos/parallel_search.py", "kryptos/language.py",
             "kryptos/advanced_cli.py", "kryptos/explanations.py", "kryptos/ciphers.py",
             "research/search_runtime_audit_K.py"]
    hashes = lambda: {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in files}
    before = hashes()
    started = time.perf_counter()
    evidence = output.parent / (output.stem + "-checkpoints")
    evidence.mkdir(parents=True, exist_ok=False)
    tie = {"schema": search_runtime.SCHEMA, "domains": [2, 2, 2], "factors": [
        {"kind": "table", "scope": [0, 2], "values": [1, 7, 7, 1]},
        {"kind": "table", "scope": [1, 2], "values": [7, 1, 1, 7]}]}
    model = {"alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "counts": {"AD": 100, "ND": 18, "AB": 11, "NA": 5, "AZ": 7, "NB": 4, "CB": 30, "CA": 9},
             "p": 3, "q": 2, "order": 2, "id": "independent-hand-correlated"}
    correlated = {"schema": search_runtime.SCHEMA, "domains": [2, 3, 2], "model": model,
                  "factors": [{"kind": "ngram", "scope": [0, 1], "base": [0, 25], "columns": [[13, 13], [2, 2]], "power": 2},
                              {"kind": "ngram", "scope": [1, 2], "base": [0, 0], "columns": [[0, 1], [2, 1]]}]}
    problems = [tie, correlated]
    partial_checks = local_checks = searches = 0
    truths = []
    for problem in problems:
        points = list(product(*(range(d) for d in problem["domains"])))
        scores = {p: literal(problem, p) for p in points}
        truth = min(points, key=lambda p: (-scores[p], p))
        truths.append((scores[truth], truth))
        evaluator = search_runtime._Evaluator(problem, 0, 1)
        for partial in product(*(range(-1, d) for d in problem["domains"])):
            compatible = [p for p in points if all(a < 0 or a == v for a, v in zip(partial, p))]
            upper = evaluator.upper(partial)
            assert upper >= max(scores[p] for p in compatible)
            if -1 not in partial:
                assert upper == scores[partial]
            for number, factor in enumerate(problem["factors"]):
                single = {**problem, "factors": [factor]}
                local = evaluator.local_upper(number, partial) ** factor.get("power", 1)
                assert local >= max(literal(single, p) for p in compatible)
                if -1 not in partial:
                    assert local == literal(single, partial)
                local_checks += 1
            partial_checks += 1
        for ordering in ("natural", "impact"):
            for nodes in (0, 1, 2, 5, 1000):
                result = search_runtime.optimize_lazy(problem, ordering=ordering, max_nodes=nodes,
                                                     local_exact_limit=1, max_cache_entries=0)
                assert result["lower_bound"] <= scores[truth] <= result["upper_bound"]
                if result["complete"]:
                    assert (result["score"], tuple(result["assignment"])) == (scores[truth], truth)
                    assert result["tie_break_proven"]
                searches += 1
    assert truths[0] == (49, (0, 1, 1))
    first = evidence / "frontier-cap.json"
    stopped = search_runtime.optimize_lazy(tie, max_frontier=1, checkpoint_path=first)
    assert stopped["stop_reason"] == "frontier_limit" and stopped["frontier_nodes"] == 1
    previous = first
    resumes = 0
    for step in range(20):
        destination = evidence / f"resume-{step}.json"
        result = search_runtime.optimize_lazy(tie, max_nodes=1, max_frontier=100,
                                             resume_path=previous, checkpoint_path=destination)
        assert result["lower_bound"] <= 49 <= result["upper_bound"]
        previous = destination
        resumes += 1
        if result["complete"]:
            break
    assert result["complete"] and (result["score"], tuple(result["assignment"])) == truths[0]
    identity = search_runtime._identity
    def changed_identity(*args):
        value = identity(*args)
        value["sources"]["search_runtime.py"] = "0" * 64
        return value
    rejected_changed_source = False
    with patch("kryptos.search_runtime._identity", side_effect=changed_identity):
        try:
            search_runtime.optimize_lazy(tie, resume_path=first)
        except ValueError:
            rejected_changed_source = True
    assert rejected_changed_source
    # Public path semantics should be identical from a non-project cwd.
    caller = evidence / "alternate-cwd"
    caller.mkdir()
    cwd = Path.cwd()
    try:
        os.chdir(caller)
        serial_job = {"id": "path", "problem": tie, "options": {"checkpoint_path": "serial.json", "max_nodes": 1}}
        parallel_job = {"id": "path", "problem": tie, "options": {"checkpoint_path": "parallel.json", "max_nodes": 1}}
        serial = optimize_batch([serial_job], workers=1)
        parallel = optimize_batch([parallel_job], workers=2)
        assert (caller / "serial.json").exists() and (caller / "parallel.json").exists()
        assert serial_job["options"]["checkpoint_path"] == "serial.json"
        assert parallel_job["options"]["checkpoint_path"] == "parallel.json"
        # A relative resume must also resolve in the caller's directory.
        job = {"id": "resume", "problem": tie, "options": {"resume_path": "parallel.json", "max_nodes": 1000}}
        resumed = optimize_batch([job], workers=2)["jobs"][0]["result"]
        assert resumed["complete"] and (resumed["score"], tuple(resumed["assignment"])) == truths[0]
    finally:
        os.chdir(cwd)
    jobs = [{"id": str(i), "problem": problem, "options": {"local_exact_limit": 1, "max_nodes": 1000, "time_limit_seconds": 5}}
            for i, problem in enumerate(problems)]
    serial, parallel = optimize_batch(jobs, workers=1), optimize_batch(jobs, workers=2)
    for number, (left, right) in enumerate(zip(serial["jobs"], parallel["jobs"])):
        for key in ("assignment", "score", "lower_bound", "upper_bound", "complete", "tie_break_proven", "nodes"):
            assert left["result"][key] == right["result"][key], key
        assert (right["result"]["score"], tuple(right["result"]["assignment"])) == truths[number]
    after = hashes()
    assert before == after
    return {"schema": "kryptos.search-runtime-audit.K.v1", "utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(), "elapsed_seconds": time.perf_counter() - started,
            "source_sha256_before": before, "source_sha256_after": after,
            "scope": "Two tiny independently evaluated finite product objectives; no K4 scan or source modification.",
            "results": {"passed": True, "partial_bound_checks": partial_checks, "local_factor_bound_checks": local_checks,
                        "capped_searches": searches,
                        "one_node_resumes": resumes, "source_change_rejected": rejected_changed_source,
                        "serial_parallel_exact_jobs": len(problems), "relative_checkpoint_and_resume_paths_agree": True,
                        "caller_jobs_not_mutated": True,
                        "tie_control": {"optimal_score": 49, "original_coordinate_lexical_assignment": [0, 1, 1]}},
            "limits": ["An admissible lazy bound can be loose; these controls do not measure large-instance efficiency.",
                       "Checkpoint hashes detect accidental changes; they are not an external authentication or independent coverage proof.",
                       "CPU job time limits are cooperative unless the caller additionally imposes an outer process timeout."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("choose a fresh output")
    result = run(output)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result["results"], sort_keys=True))


if __name__ == "__main__":
    main()
