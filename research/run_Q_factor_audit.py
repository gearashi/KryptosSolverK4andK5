"""Canonical phase-Q factor audit with immutable sources and owned children."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.process_lifetime import launch_owned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True)
    parser.add_argument("--output", required=True, help="Fresh project-relative audit directory")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--shared-workers", type=int, default=8)
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    relative = output.relative_to(ROOT).as_posix()
    if output.exists():
        raise FileExistsError("Preserve earlier audit output; choose a fresh directory")
    if not 1 <= args.workers <= 64 or not 1 <= args.shared_workers <= 64:
        raise ValueError("workers must be in 1..64")
    inputs = sorted([p.relative_to(ROOT).as_posix() for p in (ROOT / "kryptos").glob("*.py")]
                    + ["research/factor_Q.py", "research/phase_Q_factors.json", "research/run_Q_factor_audit.py"])
    originals = {name: (ROOT/name).read_bytes() for name in inputs}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()}
    details = json.loads((ROOT/"research/phase_Q_factors.json").read_text(encoding="utf-8"))
    contract = dict(claim_id="Q31_61_FINITE_FACTOR_WORK", mathematics=dict(
        assertion_tested="All 561 exact integrated comparisons on 33 frozen controls match literal exhaustive score and lexical optimum, plus declared guidance, bounds, cache, top-k, route-bank and shared-incumbent controls.",
        coefficient_domain=details["coefficient_domain"], conventions=details["conventions"],
        inputs=["research/factor_Q.py: cases(), VARIANTS and mechanisms(); 7 structural,24 seeded,2 affine cipher controls"],
        bounds=dict(cases=33, integrated_variants=17, max_nodes_per_variant=100000,
            max_factor_operations=2000000, max_table_entries=100000,
            process_workers=args.workers, shared_incumbent_workers=args.shared_workers,
            outer_seconds=300, per_variant_seconds=30), non_claims=details["non_claims"]),
        execution_artifacts=inputs, software=[dict(name="Python", version=platform.python_version())],
        randomness=dict(used=True, generator="random.Random", seed=31061))
    label = relative.replace("/", "-")
    contract_path = ROOT / "research" / (label + "-contract.json")
    snapshot = ROOT / "research/source_snapshots" / label
    if contract_path.exists() or snapshot.exists():
        raise FileExistsError("Preserve earlier contract/snapshot; choose a fresh output label")
    snapshot.mkdir(parents=True)
    for name, data in originals.items():
        destination = snapshot/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
    contract_path.write_text(json.dumps(contract, indent=2)+"\n", encoding="utf-8")
    (snapshot/"_input_hashes.json").write_text(json.dumps(hashes, indent=2)+"\n", encoding="utf-8")
    command = [sys.executable, str(Path(args.runner).resolve()), "--root", str(ROOT),
        "--contract", str(contract_path), "--output", relative, "--result", relative+"/result.json",
        "--timeout", "300", "--max-output-bytes", "1048576"]
    for name in inputs:
        command += ["--input", name]
    command += ["--", sys.executable, "-B", "research/factor_Q.py", "--output", relative+"/result.json",
                "--workers", str(args.workers), "--shared-workers", str(args.shared_workers)]
    (ROOT/"runtime").mkdir(exist_ok=True)
    with tempfile.TemporaryFile(mode="w+b", dir=ROOT/"runtime") as log:
        process = launch_owned(command, cwd=ROOT, stdout=log, stderr=log)
        try:
            code = process.wait(timeout=330)
        finally:
            process.close()
            log.seek(0)
            print(log.read(65536).decode("utf-8", errors="replace"), end="")
    for name, digest in hashes.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise ValueError("Audit input changed; preserve the record and rerun: " + name)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
