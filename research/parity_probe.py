"""Check a Reddit-suggested position-parity hypothesis without adopting it globally."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.position_residues import check_position_residues


def analyze():
    start = time.perf_counter()
    paths = ["research/parity_probe.py", "kryptos/position_residues.py", "kryptos/ciphers.py", "kryptos/data.py",
             "research/runs/complete-predictions-001/results.json"]
    hashes = lambda: {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    before = hashes()
    known = {row["start"] - 1 + i: c for row in K4_CRIBS for i, c in enumerate(row["text"])}
    parity = check_position_residues(K4_CIPHERTEXT, known)
    assert parity["feasible"]
    assert parity["classes"] == [list("ACKLNT"), list("BEHIORS")]
    # Independent pairwise equality check; not the same dictionary algorithm.
    pairs = [{"positions_one_based": [i + 1, j + 1], "letter": known[i],
              "agrees": (ord(K4_CIPHERTEXT[i]) - ord(K4_CIPHERTEXT[j]) + i - j) % 2 == 0}
             for i in known for j in known if i < j and known[i] == known[j]]
    assert len(pairs) == 13 and all(row["agrees"] for row in pairs)
    steps = [{"step_mod26": step, **check_position_residues(K4_CIPHERTEXT, known,
                modulus=26, step=step, alphabet=alphabet)}
             for alphabet in ("standard", "kryptos") for step in range(26)]
    saved = json.loads((ROOT / paths[-1]).read_text())
    candidates = []
    for row in saved["ranked_plaintexts"]:
        plaintext = row["plaintext"]
        assert len(plaintext) == 97 and all(plaintext[i] == c for i, c in known.items())
        candidates.append({"plaintext": plaintext, "sha256": hashlib.sha256(plaintext.encode()).hexdigest(),
            "parity_check": check_position_residues(K4_CIPHERTEXT, dict(enumerate(plaintext)))})
    assert len(candidates) == 46
    after = hashes()
    assert before == after
    return {"input_hashes_before": before, "input_hashes_after": after, "inputs_unchanged": True,
        "hypothesis_source": "https://www.kryptosbot.com/crib-parity/",
        "parity": parity, "repeated_letter_pairs": pairs,
        "independent_repeat_equalities": len(known) - len(set(known.values())),
        "constant_step_subclass": {"models": 52, "fits": sum(row["feasible"] for row in steps), "records": steps},
        "saved_candidate_filter": {"tested": 46, "fits": sum(row["parity_check"]["feasible"] for row in candidates), "records": candidates},
        "runtime_seconds": time.perf_counter() - start,
        "non_claims": [
            "A pattern selected after inspecting the clues has no valid significance estimate here.",
            "Parity is a necessary constraint for an unknown bijective alphabet plus alternating-parity keystream. It does not imply a constant numeric step.",
            "Constant-step failures reject only that stricter subclass.",
            "Existing candidates are tagged against this optional hypothesis, not discarded globally.",
            "Other alignments, alphabets, transpositions, and K5 are untested by this probe."
        ]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; choose a new file")
    result = analyze()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    print(json.dumps({"constant_step_fits": result["constant_step_subclass"]["fits"],
                      "candidate_parity_fits": result["saved_candidate_filter"]["fits"],
                      "runtime_seconds": result["runtime_seconds"]}))
