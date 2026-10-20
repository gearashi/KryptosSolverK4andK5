"""Frozen bounded guidance/decomposition/joint-ranking audit for checkpoint N.

Guidance outcomes are descriptive, not a tuned recovery-rate acceptance gate.
No K4/K5 ciphertext is searched. Run only after the shared sources are frozen.
"""
import argparse
import hashlib
from itertools import islice, permutations, product
import json
import math
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.__main__ import _target
from kryptos.advanced_cli import json_safe_integers
from kryptos.factor_decomposition import exact_decomposition
from kryptos.guided_search import guided_seeds
from kryptos.joint_ranked import rank_joint_columnar
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.next_cli import _optimization_job, _optimization_result
from kryptos.search_runtime import SCHEMA, optimize_lazy

MODEL = "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KEYED = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
# Authored independent control prose, not downloaded or model-trained here.
TEXT = ("THEMESSAGELIESBENEATHTHESTONEWALLFOLLOWTHEPATHPASTTHETREESANDREADTHEMARKS"
        "INTHEORDERTHESHADOWSCROSSTHEGROUND")[:97]


def input_paths():
    paths = [p.relative_to(ROOT).as_posix() for p in (ROOT / "kryptos").glob("*.py")]
    paths += [p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").glob("*.py")]
    paths += ["research/search_N.py", "research/search_N_protocol.json", "research/run_search_N_audit.py", MODEL]
    return sorted(set(paths))


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in input_paths()}


def score_word(text, model, mask):
    """Independent literal-window objective, not the delta/factor evaluator."""
    numerator, denominator = model.alpha.as_integer_ratio()
    total = 1
    for start in range(len(text) - model.order + 1):
        if any(i in mask for i in range(start, start + model.order)):
            continue
        total *= model.counts.get(text[start:start + model.order], 0) * denominator + numerator
    return total


def encrypt_recipe(text, recipe):
    """Independent literal replay for generated old/expanded recipes."""
    alphabet = recipe.get("alphabet", STANDARD)
    for stage in recipe["stages"]:
        if stage["operation"] == "gather":
            text = "".join(text[i] for i in stage["permutation"])
            continue
        letters = stage.get("alphabet", alphabet)
        key = stage.get("key_pattern", stage.get("key"))
        phases = stage.get("phase_map")
        offset = stage.get("offset", 0)
        cipher = stage.get("cipher", "vigenere")
        output = []
        for i, c in enumerate(text):
            phase = (phases[i] if phases is not None else i) + offset
            a, b = letters.index(c), letters.index(key[phase % len(key)])
            output.append(letters[(b-a if cipher == "beaufort" else a-b if cipher == "variant" else a+b) % 26])
        text = "".join(output)
    return text


def guided_comparisons(protocol):
    assert len(TEXT) == 97
    records, replay_checks = [], 0
    for kind in ("general", "scheduled"):
        for alphabet in (STANDARD, KEYED):
            route = [(i + 17) % 97 for i in range(97)]
            phases = [i % 4 for i in range(97)] if kind == "general" else [(i // 5 + i % 3) % 4 for i in range(97)]
            hidden = [1, 4, 7, 9]
            intermediate = "".join(alphabet[(alphabet.index(c) + hidden[phases[i]]) % 26] for i, c in enumerate(TEXT))
            ciphertext = "".join(intermediate[i] for i in route)
            substitution = ({"operation": "substitution", "period": 4} if kind == "general" else
                {"operation": "substitution", "key_id": "hidden", "key_length": 4, "phase_map": phases})
            request = {"target": "custom", "ciphertext": ciphertext, "cribs": [{"start": 1, "text": TEXT[0]}],
                "alphabet": alphabet, "layer_model": kind,
                "stages": [substitution, {"operation": "gather", "permutation": route}],
                "model_path": str(ROOT / MODEL)}
            # The hidden generating key is deliberately absent from this call.
            job = _optimization_job(request, _target)
            assert job["solution"].feasible and job["problem"] is not None
            affine = job["solution"].affine_plaintext()
            dimensions = affine["domains"]
            for seed in protocol["guidance"]["seeds"]:
                began = time.monotonic()
                guided = guided_seeds(job["problem"], seed=seed, restarts=4, max_sweeps=2, top=4,
                    max_evaluations=192, max_factor_evaluations=200000, time_limit_seconds=10)
                guided_seconds = time.monotonic() - began
                count = guided["work"]["objective_evaluations"]
                assert count > 0
                began = time.monotonic()
                baseline = []
                for point in islice(product(*(range(d) for d in dimensions)), count):
                    plaintext = "".join(alphabet[(base + sum(v*col[i] for v, col in zip(point, affine["columns"]))) % 26]
                                        for i, base in enumerate(affine["base"]))
                    baseline.append((score_word(plaintext, job["model"], job["score_mask"]), point))
                assert len(baseline) == count
                baseline.sort(key=lambda row: (-row[0], row[1]))
                baseline_seconds = time.monotonic() - began
                actual_texts = {}
                for name, rows in (("guided", [(int(row["score_hex"], 16), tuple(row["assignment"])) for row in guided["candidates"]]),
                                   ("contiguous", baseline[:4])):
                    actual_texts[name] = []
                    for value, point in rows:
                        result = _optimization_result(job, {"assignment": list(point)})
                        candidate = result["candidate"]
                        assert score_word(candidate["plaintext"], job["model"], job["score_mask"]) == value
                        assert encrypt_recipe(candidate["plaintext"], candidate["encryption_recipe"]) == ciphertext
                        assert candidate["plaintext"][0] == TEXT[0]
                        actual_texts[name].append(candidate["plaintext"])
                        replay_checks += 1
                a = int(guided["candidates"][0]["score_hex"], 16)
                b = baseline[0][0]
                records.append({"id": f"{kind}-{'standard' if alphabet == STANDARD else 'kryptos'}-{seed}",
                    "request": request, "truth_plaintext": TEXT, "generating_numeric_key": hidden,
                    "domains": dimensions, "family_size": math.prod(dimensions), "guided": guided,
                    "equal_objective_evaluations": count, "contiguous_best_score_hex": hex(b),
                    "guided_best_score_hex": hex(a), "objective_comparison": "higher" if a > b else "lower" if a < b else "equal",
                    "guided_seconds": guided_seconds, "contiguous_seconds": baseline_seconds,
                    "retained_texts": actual_texts,
                    "truth_in_guided_retained": TEXT in actual_texts["guided"],
                    "truth_in_contiguous_retained": TEXT in actual_texts["contiguous"],
                    "truth_objective_hex": hex(score_word(TEXT, job["model"], job["score_mask"]))})
    return {"records": records, "independent_score_recipe_checks": replay_checks,
            "outcomes": {name: sum(r["objective_comparison"] == name for r in records) for name in ("higher", "equal", "lower")},
            "interpretation": "Equal numbers of objective evaluations, not equal unique points or time. Verification/preparation are separate. Outcomes are not tuned acceptance thresholds or proof of language authenticity."}


def direct_tables(problem, point):
    score = 1
    for f in problem["factors"]:
        row = 0
        for v in f["scope"]:
            row = row * problem["domains"][v] + point[v]
        score *= f["values"][row] ** f.get("power", 1)
    return score


def decomposition_controls():
    rng = random.Random(483)
    records, comparisons = [], 0
    for case in range(60):
        domains = [2, 3, 2, 2, 2]
        factors = []
        for number in range(5):
            scope = sorted(rng.sample(range(5), rng.randrange(4)))
            factors.append({"kind": "table", "scope": scope,
                "values": [rng.randrange(4) for _ in range(math.prod(domains[i] for i in scope))], "power": number % 3 + 1})
        problem = {"schema": SCHEMA, "domains": domains, "factors": factors}
        partial = [rng.randrange(d) if rng.random() < .3 else -1 for d in domains]
        oracle = [(direct_tables(problem, point), point) for point in
                  product(*(range(d) if v < 0 else (v,) for d, v in zip(domains, partial)))]
        comparisons += len(oracle)
        truth = min(oracle, key=lambda row: (-row[0], row[1]))
        actual = exact_decomposition(problem, partial, max_entries=20000, max_operations=200000, time_limit_seconds=5)
        assert actual["complete"] and (actual["score"], tuple(actual["assignment"])) == truth
        records.append({"case": case, "problem": problem, "partial": partial, "oracle_completions": len(oracle), "result": actual})
    chain = {"schema": SCHEMA, "domains": [2] * 14, "factors": [
        {"kind": "table", "scope": [i, i+1], "values": [1, 2, 2, 5]} for i in range(12) if i != 5]}
    direct = exact_decomposition(chain)
    assert direct["assignment"] == [1] * 13 + [0] and direct["score"] == 5**11
    enabled = optimize_lazy(chain, decomposition="auto", max_nodes=10000, time_limit_seconds=5)
    disabled = optimize_lazy(chain, decomposition="off", max_nodes=10000, time_limit_seconds=5)
    assert enabled["complete"] and disabled["complete"]
    assert enabled["assignment"] == disabled["assignment"] and enabled["score"] == disabled["score"]
    capped = exact_decomposition(chain, max_entries=1)
    assert not capped["complete"] and capped["assignment"] is None and capped["score"] is None
    return {"cases": records, "independent_oracle_completions": comparisons,
            "chain": {"problem": chain, "direct": direct, "enabled": enabled, "disabled": disabled, "capped": capped},
            "interpretation": "Exact arithmetic and lexical agreement in this bounded bank. Sparse-graph work reduction is workload-specific; dense residuals can fall back."}


def joint_controls():
    cells = [(3, -1), (0, 2), (0, -1), (5, 2), (2, 7)]
    ciphertext = "ZXAAA"
    model = train_ngram_model([CorpusDocument("ABCCBADAZAZXBBACBC", "audit-authored")], label="audit", order=2)
    records, checked = [], 0
    for alphabet, layer, cipher, reverse in product((STANDARD, "BACDEFGHIJKLMNOPQRSTUVWXYZ"), ("ST", "TS"),
                                                     ("vigenere", "beaufort", "variant"), (False, True)):
        labels = sorted({c for r, c in cells})
        columns = {c: sorted((i for i, rc in enumerate(cells) if rc[1] == c), key=lambda i: cells[i][0], reverse=reverse) for c in labels}
        expected, fits, order_fits = {}, 0, set()
        def decrypt(text, key):
            output = []
            for i, ch in enumerate(text):
                c, k = alphabet.index(ch), alphabet.index(key[i % 2])
                output.append(alphabet[(k-c if cipher == "beaufort" else c+k if cipher == "variant" else c-k) % 26])
            return "".join(output)
        for order in permutations(labels):
            route = sum((columns[c] for c in order), [])
            for chars in product(alphabet, repeat=2):
                checked += 1
                key = "".join(chars)
                middle = decrypt(ciphertext, key) if layer == "TS" else ciphertext
                plain = [""] * 5
                for pos, source in enumerate(route):
                    plain[source] = middle[pos]
                plain = "".join(plain)
                if layer == "ST":
                    plain = decrypt(plain, key)
                if plain[2] != "B":
                    continue
                fits += 1
                order_fits.add(order)
                objective = score_word(plain, model, {2})
                representative = (order, key)
                if plain not in expected or representative < expected[plain][1]:
                    expected[plain] = (objective, representative)
        result = rank_joint_columnar(ciphertext, [{"start": 3, "text": "B"}], model=model, period=2, cells=cells,
            order=layer, cipher=cipher, alphabet=alphabet, column_direction="bottom_to_top" if reverse else "top_to_bottom",
            top=7, max_states=200000, time_limit_seconds=10)
        assert result["complete"] and result["total_order_key_assignments"] == fits and result["total_column_orders"] == len(order_fits)
        wanted = sorted(expected, key=lambda word: (-expected[word][0], word))[:7]
        assert [c["plaintext"] for c in result["candidates"]] == wanted
        for got, plain in zip(result["candidates"], wanted):
            assert int(got["score_exact"], 16) == expected[plain][0]
            assert (tuple(got["column_order"]), got["key_pattern"]) == expected[plain][1]
            assert encrypt_recipe(plain, got["encryption_recipe"]) == ciphertext
        records.append({"alphabet": alphabet, "order": layer, "cipher": cipher, "reverse": reverse, "result": result})
    return {"records": records, "independent_order_key_completions": checked, "literal_candidate_replays": sum(len(r["result"]["candidates"]) for r in records)}


def run():
    before = hashes()
    protocol = json.loads((ROOT / "research/search_N_protocol.json").read_text())
    assert protocol["model_sha256"] == before[MODEL]
    started = time.monotonic()
    guidance = guided_comparisons(protocol)
    decomposition = decomposition_controls()
    joint = joint_controls()
    after = hashes()
    if before != after:
        raise RuntimeError("An audited source/input changed during the run")
    return {"schema": "kryptos.search-N-audit.v1", "passed": True, "protocol": protocol,
            "guidance": guidance, "decomposition": decomposition, "joint": joint,
            "input_sha256_before": before, "input_sha256_after": after,
            "runtime_seconds": time.monotonic() - started,
            "nonclaims": ["No K4/K5 ciphertext search, authenticity or universal performance claim.",
                          "Guided outcomes are retained even when a contiguous baseline is better.",
                          "Finite algorithm controls do not establish cryptanalytic success on unknown real messages."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.inputs:
        print(json.dumps(input_paths()))
    else:
        if args.output is None or args.output.exists():
            parser.error("provide a fresh --output path")
        result = run()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(json_safe_integers(result), stream, indent=2, allow_nan=False)
        print(json.dumps({"passed": result["passed"], "runtime_seconds": result["runtime_seconds"],
                          "guided_outcomes": result["guidance"]["outcomes"]}))
