"""Tiny exact K4 exclusions, independent of the search engine.

Run from the project root: python research/independent_checks.py
Reads only literal K4 constants in kryptos/data.py, never importing the package.
All indices reported to readers are 1-based. No floating-point cipher arithmetic,
stochastic search, candidate ranking, or full application test is performed.
"""
from __future__ import annotations

import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
from itertools import combinations
import json
from pathlib import Path
import platform
import string
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
INPUT_PATHS = ["kryptos/data.py", "research/independent_checks.py"]
RESULT_PATH = "research/independent_checks.json"
MANIFEST_PATH = "research/independent_checks.manifest.json"
BASE_ID = "K4-20261012-A"


def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def load_literals():
    constants = {}
    tree = ast.parse((ROOT / "kryptos/data.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"K4_CIPHERTEXT", "K4_CRIBS"}:
                    constants[target.id] = ast.literal_eval(node.value)
    return constants["K4_CIPHERTEXT"], constants["K4_CRIBS"]


def mapping_check(observations, period, require_bijection):
    """Orthogonal implementation: construct phase dictionaries, not gap divisors."""
    forward, reverse = {}, {}
    for row in observations:
        phase = (row["position"] - 1) % period
        ck, pk = (phase, row["ciphertext"]), (phase, row["plaintext"])
        if ck in forward and forward[ck] != row["plaintext"]:
            return False
        if require_bijection and pk in reverse and reverse[pk] != row["ciphertext"]:
            return False
        forward[ck], reverse[pk] = row["plaintext"], row["ciphertext"]
    return True


def complete_bijections(ciphertext, observations, period):
    """A consistent phasewise partial injection always extends to a permutation.

    Construct such an extension to check sufficiency. The resulting text is
    deliberately arbitrary and is not a cryptanalytic candidate.
    """
    phases = [dict() for _ in range(period)]
    for row in observations:
        phases[(row["position"] - 1) % period][row["ciphertext"]] = row["plaintext"]
    for mapping in phases:
        unused_c = sorted(set(string.ascii_uppercase) - mapping.keys())
        unused_p = sorted(set(string.ascii_uppercase) - set(mapping.values()))
        assert len(unused_c) == len(unused_p)
        mapping.update(zip(unused_c, unused_p))
        assert set(mapping) == set(mapping.values()) == set(string.ascii_uppercase)
    plaintext = "".join(phases[i % period][char] for i, char in enumerate(ciphertext))
    assert all(plaintext[row["position"] - 1] == row["plaintext"] for row in observations)
    return phases


def main():
    started = datetime.now(timezone.utc).isoformat()
    timer = time.perf_counter()
    input_hashes = {path: digest(path) for path in INPUT_PATHS}
    ciphertext, cribs = load_literals()
    assert len(ciphertext) == 97 and set(ciphertext) <= set(string.ascii_uppercase)
    observations = [
        {"position": crib["start"] + offset,
         "ciphertext": ciphertext[crib["start"] + offset - 1], "plaintext": letter}
        for crib in cribs for offset, letter in enumerate(crib["text"])
    ]
    assert len(observations) == len({row["position"] for row in observations}) == 24
    counts = Counter(ciphertext)
    needed = Counter(row["plaintext"] for row in observations)
    deficits = [
        {"letter": letter, "ciphertext_count": counts[letter], "crib_count": needed[letter],
         "ciphertext_positions": [i + 1 for i, c in enumerate(ciphertext) if c == letter],
         "crib_positions": [row["position"] for row in observations if row["plaintext"] == letter]}
        for letter in sorted(needed) if needed[letter] > counts[letter]
    ]
    conflicts = []
    for a, b in combinations(observations, 2):
        same_c, same_p = a["ciphertext"] == b["ciphertext"], a["plaintext"] == b["plaintext"]
        if same_c != same_p:
            conflicts.append({"first": a, "second": b, "gap": b["position"] - a["position"],
                              "kind": "same_ciphertext_different_plaintext" if same_c
                              else "same_plaintext_different_ciphertext"})
    conflicts.sort(key=lambda x: (x["gap"], x["first"]["position"]))
    period_results = []
    for period in range(1, 98):
        witnesses = [pair for pair in conflicts if pair["gap"] % period == 0]
        bijective_compatible = not witnesses
        function_compatible = not any(pair["kind"] == "same_ciphertext_different_plaintext" for pair in witnesses)
        assert bijective_compatible == mapping_check(observations, period, True)
        assert function_compatible == mapping_check(observations, period, False)
        if bijective_compatible:
            complete_bijections(ciphertext, observations, period)
        period_results.append({"period": period, "bijective_compatible": bijective_compatible,
                               "deterministic_decryption_compatible": function_compatible,
                               "minimal_two_observation_witness": witnesses[0] if witnesses else None})
    excluded = [row["period"] for row in period_results if not row["bijective_compatible"]]
    # Pin independently computed JavaScript results, rather than merely testing
    # internal consistency of the Python implementation.
    assert excluded == [1, 2, 3, 4, 5, 6, 7, 9, 10, 14, 15, 17, 21, 25, 34, 42, 43, 45, 50]
    assert deficits == [{"letter": "E", "ciphertext_count": 2, "crib_count": 3,
                         "ciphertext_positions": [45, 93], "crib_positions": [22, 31, 65]}]
    assert conflicts[0]["first"]["position"] == 26 and conflicts[0]["second"]["position"] == 27
    # Hand-checkable benchmarks for both notions of substitution.
    assert mapping_check([{"position": 1, "ciphertext": "A", "plaintext": "B"}], 1, True)
    assert not mapping_check([{"position": 1, "ciphertext": "A", "plaintext": "B"},
                              {"position": 2, "ciphertext": "A", "plaintext": "C"}], 1, False)
    reverse_only = [{"position": 1, "ciphertext": "A", "plaintext": "B"},
                    {"position": 2, "ciphertext": "C", "plaintext": "B"}]
    assert mapping_check(reverse_only, 1, False) and not mapping_check(reverse_only, 1, True)
    non_claims = [
        "No decryption or discovery of K4 or K5 is claimed.",
        "Not excluded means only compatibility with these 24 letters, not plausibility or authenticity.",
        "Direct periodic substitution assumes the observed ciphertext and final-plaintext positions align; inserting a transposition invalidates that alignment assumption.",
        "The E inventory argument covers only letter-preserving permutations without added/deleted letters or symbol substitutions.",
        "No test excludes composed substitution/transposition, variable-state ciphers, fractionation, or other alphabets/encodings.",
        "Source authenticity and crib accuracy are inherited from the pinned data; no external source authentication was performed in this check.",
        "These elementary exclusions are not claimed to be novel."
    ]
    result = {
        "base_id": BASE_ID, "input_ciphertext": ciphertext,
        "ciphertext_sha256": hashlib.sha256(ciphertext.encode("ascii")).hexdigest(),
        "cribs": cribs, "observations": observations,
        "pure_transposition": {"excluded": bool(deficits), "deficits": deficits,
             "minimality": "Three required E observations exceed the two available E symbols; every proper subset of those E observations fits the E inventory."},
        "direct_monoalphabetic": {"excluded": True, "minimal_witness": conflicts[0],
             "reason": "The identical cipher symbol Q at positions 26 and 27 would have to decrypt both to N and to O."},
        "periodic_bijective_substitution": {
            "definition": "P_i=f_((i-1) mod p)(C_i), where each f is an arbitrary permutation of A-Z and indices align without transposition.",
            "excluded_positive_periods": excluded,
            "all_others_compatible_with_cribs": True,
            "forbidden_pair_gaps": sorted({pair["gap"] for pair in conflicts}),
            "uniform_reduction": "A phase map is a partial bijection exactly when equality of cipher symbols agrees with equality of plaintext symbols for every same-phase pair. Conflicting positions share a phase exactly when p divides their gap. Each nonconflicting finite partial bijection extends to an alphabet permutation. All forbidden gaps are at most 50, so no positive p greater than 50 is excluded by these cribs.",
            "directly_tested_periods": [1, 97], "period_results": period_results},
        "periodic_deterministic_decryption_not_required_injective": {
            "excluded_positive_periods": [row["period"] for row in period_results if not row["deterministic_decryption_compatible"]],
            "note": "This weaker interpretation allows distinct ciphertext letters to map to the same plaintext letter. It still excludes a single deterministic monoalphabetic decoder."},
        "non_claims": non_claims,
    }
    (ROOT / RESULT_PATH).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    assert json.loads((ROOT / RESULT_PATH).read_text(encoding="utf-8")) == result
    assert input_hashes == {path: digest(path) for path in INPUT_PATHS}, "Inputs changed during the run"
    manifest = {
        "schema_version": 2, "claim_id": BASE_ID + "/independent-elementary-exclusions",
        "repository": {"commit": "unavailable: workspace is not a Git repository", "dirty": True},
        "command": [sys.executable, "research/independent_checks.py"],
        "environment": {"software": [{"name": "Python", "version": platform.python_version()}],
                        "hardware": platform.machine(), "platform": platform.platform()},
        "mathematics": {
            "assertion_tested": "Exact inventory and pair consistency exclusions for fixed K4 ciphertext and 24 crib letters.",
            "coefficient_domain": "Exact integers, finite A-Z symbol equality, and integer divisibility",
            "conventions": "K4-20261012-A; 1-based visible positions; phase=(position-1) mod period; positive integer periods; aligned positions.",
            "inputs": INPUT_PATHS, "bounds": {"ciphertext_letters": 97, "crib_letters": 24, "direct_periods": [1, 97], "unordered_pairs": 276},
            "non_claims": non_claims},
        "randomness": {"used": False, "generator": "none", "seed": None},
        "run": {"started_at": started, "runtime_seconds": time.perf_counter() - timer, "exit_status": 0,
                "status": "completed", "resource_limits": {"memory_bytes": None, "cpu_seconds": None, "max_cores": None, "max_threads": None},
                "resource_note": "Tiny finite single-threaded stdlib calculation; no OS resource caps requested or applied."},
        "input_artifacts": [{"path": path, "sha256": checksum, "sha256_after": digest(path)} for path, checksum in input_hashes.items()],
        "execution_artifacts": INPUT_PATHS, "declared_results": [RESULT_PATH],
        "outputs": [{"path": RESULT_PATH, "sha256": digest(RESULT_PATH), "kind": "result"}],
        "checks": ["Input lengths and unique crib indices", "Pair-divisor results agree with separate phase-map implementation for every period 1..97",
                   "Consistent phase maps extended to full A-Z permutations and all cribs verified",
                   "Matches separately computed JavaScript exclusions", "Hand-checkable mapping benchmarks", "JSON round-trip", "Input hashes stable during run"],
        "result": "Implementation and finite assertions verified in the stated range; pair-divisor reduction explains the complete positive-period exclusion set under the stated model.",
        "residual_risks": ["Ciphertext and crib authenticity inherited from data.py", "No independent external audit of script; simple witnesses are supplied for manual checking", "Unversioned workspace; source/data hashes pin inputs", "Manifest is generated by the check script itself, not an external process supervisor"]}
    (ROOT / MANIFEST_PATH).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"base_id": BASE_ID, "pure_transposition_deficit": deficits,
                      "monoalphabetic_witness_positions": [26, 27], "excluded_bijective_periods": excluded,
                      "result": RESULT_PATH, "manifest": MANIFEST_PATH}, indent=2))


if __name__ == "__main__":
    main()
