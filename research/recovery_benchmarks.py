"""Small reproducible recovery benchmarks; expected keys never enter the API.

K1/K2 transcription: https://www.elonka.com/kryptos/transcript.html
Published plaintexts and expected keys, Gillogly's first-person 1999 message:
https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html
Corrected K2 input and ending:
https://www.elonka.com/kryptos/CorrectedK2Announcement.html
Re-read 2026-10-12. Preserve IQLUSION, UNDERGRUUND and as-inscribed IDBYROWS.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.ciphers import decrypt, encrypt
from kryptos.recovery import recover_periodic_keys, recover_transposition_routes
from research.k3_reference import K3_CIPHERTEXT, K3_PLAINTEXT, route_indices, validate as validate_k3

K1_CIPHERTEXT = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
)
K1_PLAINTEXT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_CIPHERTEXT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K2_PLAINTEXT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
    "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
    "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
)


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cribs(plaintext, prefix=15, suffix=8):
    return [{"start": 1, "text": plaintext[:prefix]},
            {"start": len(plaintext) - suffix + 1, "text": plaintext[-suffix:]}]


def _key_benchmark(name, ciphertext, plaintext, expected_key):
    # These oracle checks authenticate the fixtures; no oracle enters recovery.
    assert encrypt(plaintext, expected_key, alphabet="kryptos") == ciphertext
    assert decrypt(ciphertext, expected_key, alphabet="kryptos") == plaintext
    cribs = _cribs(plaintext)
    result = recover_periodic_keys(ciphertext, cribs, periods=range(1, 25), alphabet="kryptos",
                                   max_models=24, max_crib_checks=1000)
    actual = [row for row in result["candidates"] if row["canonical_key"] == expected_key]
    assert result["complete"] and actual and actual[0]["plaintext"] == plaintext
    withheld = len(plaintext) - sum(len(crib["text"]) for crib in cribs)
    return {"name": name, "letters": len(plaintext), "cribs": cribs,
            "withheld_plaintext_letters": withheld, "key_and_period_passed_to_recovery": False,
            "period_family": [1, 24], "recovered_expected_key": True,
            "recovered_expected_full_plaintext": True, "candidate_count": len(result["candidates"]),
            "complete_key_candidates": sum(row["key_complete"] for row in result["candidates"]),
            "incomplete_key_candidates": sum(not row["key_complete"] for row in result["candidates"]),
            "search_complete": result["complete"],
            "candidates": result["candidates"], "work": result["work"], "limits": result["limits"]}


def _route_benchmark():
    assert validate_k3()["plaintext_matches"]
    widths = [width for width in range(2, 29) if len(K3_CIPHERTEXT) % width == 0]
    routes = []
    for first in widths:
        for second in widths:
            # Build each candidate decryption gather, then invert for the API's
            # encryption-gather convention. The correct widths are not singled out.
            decrypt_gather = tuple(range(336))
            for width in (first, second):
                decrypt_gather = tuple(decrypt_gather[i] for i in route_indices(336, width))
            encrypt_gather = [0] * 336
            for output, source in enumerate(decrypt_gather):
                encrypt_gather[source] = output
            routes.append({"name": f"decrypt-widths-{first}-{second}", "permutation": encrypt_gather})
    cribs = _cribs(K3_PLAINTEXT)
    result = recover_transposition_routes(K3_CIPHERTEXT, cribs, routes, max_models=200, max_crib_checks=5000)
    actual = [row for row in result["candidates"] if row["plaintext"] == K3_PLAINTEXT]
    assert result["complete"] and actual
    return {"name": "K3_route_family_recovery", "letters": 336, "cribs": cribs,
            "withheld_plaintext_letters": 336 - 23, "width_family": widths,
            "raw_width_pairs": len(routes), "expected_route_passed_as_answer": False,
            "recovered_expected_full_plaintext": True,
            "candidate_count": len(result["candidates"]), "candidates": result["candidates"],
            "search_complete": result["complete"],
            "work": result["work"], "limits": result["limits"],
            "scope": "Recovery within a declared two-stage column-route family, not an unrestricted historical K3 solve."}


def analyze():
    started, timer = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    names = ["kryptos/recovery.py", "kryptos/ciphers.py", "research/recovery_benchmarks.py", "research/k3_reference.py"]
    before = {name: _hash(ROOT / name) for name in names}
    assert len(K1_CIPHERTEXT) == len(K1_PLAINTEXT) == 63
    assert len(K2_CIPHERTEXT) == len(K2_PLAINTEXT) == 369
    corrected_ciphertext = K2_CIPHERTEXT[:361] + "S" + K2_CIPHERTEXT[361:]
    corrected_plaintext = K2_PLAINTEXT[:-8] + "XLAYERTWO"
    assert len(corrected_ciphertext) == len(corrected_plaintext) == 370
    benchmarks = [
        _key_benchmark("K1", K1_CIPHERTEXT, K1_PLAINTEXT, "PALIMPSEST"),
        _key_benchmark("K2_as_inscribed", K2_CIPHERTEXT, K2_PLAINTEXT, "ABSCISSA"),
        _key_benchmark("K2_corrected", corrected_ciphertext, corrected_plaintext, "ABSCISSA"),
        _route_benchmark(),
    ]
    after = {name: _hash(ROOT / name) for name in names}
    assert before == after
    return {
        "started_at": started, "runtime_seconds": time.perf_counter() - timer,
        "environment": {"python": sys.version, "platform": platform.platform(), "workers": 1},
        "input_artifacts": [{"path": name, "sha256": before[name], "sha256_after": after[name]} for name in names],
        "input_hashes_unchanged": True, "benchmarks": benchmarks,
        "sources": ["https://www.elonka.com/kryptos/transcript.html",
                    "https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html",
                    "https://www.elonka.com/kryptos/CorrectedK2Announcement.html"],
        "non_claims": [
            "Benchmarks withhold keys/routes from the recovery API, not from the author of this known-answer experiment.",
            "Fixed alphabets, cipher convention, route family, and correct crib positions are supplied assumptions.",
            "Recovered fits do not demonstrate the actual K4/K5 method or unrestricted discovery capability.",
            "No K4 search, language scoring, full app test, GPU workload, or parallel processing occurred.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze()
    if args.output:
        output = args.output.resolve()
        if output in {(ROOT / item["path"]).resolve() for item in result["input_artifacts"]}:
            raise ValueError("output cannot overwrite an input")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"runtime_seconds": result["runtime_seconds"], "benchmarks": [
        {key: row[key] for key in ("name", "letters", "candidate_count", "withheld_plaintext_letters", "work")}
        for row in result["benchmarks"]]}, indent=2))


if __name__ == "__main__":
    main()
