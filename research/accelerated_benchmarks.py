"""Small CPU/CUDA audit; writes a fresh result, never searches K4."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.accelerated import probe_backend, scan_batch
from kryptos.explanations import replay_recipe
from kryptos.language import CharacterNgramModel
from kryptos.replay_expanded import replay_expanded


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cuda", action="store_true", help="require actual CUDA, otherwise CPU only")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("output must be a fresh path")
    model_path = ROOT/"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
    sources = sorted((ROOT/"kryptos").glob("*.py")) + [Path(__file__).resolve(), ROOT/"tests/test_accelerated.py", model_path]
    before = {str(path.relative_to(ROOT)): digest(path) for path in sources}
    model = CharacterNgramModel.from_json(model_path.read_text(encoding="utf-8-sig"))
    readiness = probe_backend() if args.cuda else {"cpu": {"ready": True}}
    if args.cuda and not readiness["cuda"]["ready"]:
        raise RuntimeError(f"CUDA required but unavailable: {readiness}")
    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL"
    common = {"target": "custom", "ciphertext": text, "cribs": [], "alphabet": "standard", "model_path": str(model_path)}
    general = {**common, "stages": [{"operation": "substitution", "period": 3},
                {"operation": "gather", "permutation": list(range(1, len(text)))+[0]}]}
    scheduled = {**common, "layer_model": "scheduled", "cribs": [{"start": 1, "text": "A"}],
        "stages": [{"operation": "substitution", "key_id": "same", "key_length": 4}]*2}
    cases = [("full-small-page", general, 3, 57), ("general-throughput", general, 123, 4096),
             ("scheduled-nonunit-throughput", scheduled, 33, 2048)]
    records, checks = [], 0
    for name, request, offset, size in cases:
        results = {}
        for backend in (("cpu", "cuda") if args.cuda else ("cpu",)):
            result = scan_batch(request, backend=backend, offset=offset, batch_size=size, top=10)
            assert result["backend_used"] == backend and result["evaluated"] == size
            p, q = float(model.alpha).as_integer_ratio()
            known = {i: c for crib in request["cribs"] for i, c in enumerate(crib["text"], crib["start"]-1)}
            for candidate in result["candidates"]:
                word = candidate["plaintext"]
                objective = 1
                for pos in range(len(word)-model.order+1):
                    if all(i not in known for i in range(pos, pos+model.order)):
                        objective *= model.counts.get(word[pos:pos+model.order], 0)*q+p
                assert objective == int(candidate["score_exact"], 16)
                recipe = candidate["encryption_recipe"]
                replay = (replay_expanded if recipe["schema"] == "kryptos.expanded-recipe.v1" else replay_recipe)(word, recipe)
                assert replay["ciphertext"] == text and all(word[i] == c for i, c in known.items())
                checks += 1
            results[backend] = result
        if args.cuda and name == "full-small-page":
            projection = lambda result: [(c["plaintext"], c["score_exact"], c["index"]) for c in result["candidates"]]
            assert projection(results["cpu"]) == projection(results["cuda"])
        records.append({"case": name, "results": results, "retained_text_overlap":
            len(set(c["plaintext"] for c in results["cpu"]["candidates"]) &
                set(c["plaintext"] for c in results["cuda"]["candidates"])) if args.cuda else None})
    after = {str(path.relative_to(ROOT)): digest(path) for path in sources}
    assert before == after, "input changed during audit"
    packages = {}
    for name in ("cupy-cuda12x", "nvidia-cuda-runtime-cu12", "nvidia-cuda-nvrtc-cu12", "numpy", "cuda-pathfinder"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    result = {"schema": "kryptos.accelerated-audit.v1", "passed": True, "python": sys.version,
        "platform": platform.platform(), "argv": sys.argv, "packages": packages, "readiness": readiness,
        "cache_environment": {key: os.environ.get(key) for key in ("TEMP", "TMP", "CUPY_CACHE_DIR")},
        "scope": "Three explicit pages of synthetic general/scheduled families, 6201 candidates per backend; no K4/K5 search or authenticity claim.",
        "independent_retained_objective_and_recipe_checks": checks,
        "source_hashes_before": before, "source_hashes_after": after, "records": records}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"passed": True, "output": str(output), "checks": checks,
        "timings": [{"case": row["case"], **{backend: value["elapsed_seconds"] for backend, value in row["results"].items()},
                     "retained_text_overlap": row["retained_text_overlap"]} for row in records]}))


if __name__ == "__main__":
    main()
