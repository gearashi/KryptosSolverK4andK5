"""Independent finite recipe-grammar audit; literal oracle uses no compiler.

Frozen domain: eighteen length-two grammar paths; six plaintext probes and all
26^k key vectors for k<=2. CEGIS uses ten recipes, two alphabets, five generating
methods with valid/perturbed pairs, two priority orders and two initial-example
counts. Exhaustive literal keys decide acceptance; these are synthetic controls.
"""
from collections import Counter
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INPUTS = ["research/review_Q_grammar.py", "kryptos/recipe_grammar.py", "kryptos/recipe_algebra.py",
          "kryptos/family_identity.py", "kryptos/constraint_algebra.py", "kryptos/constraint_lab.py",
          "kryptos/general_layers.py", "kryptos/scheduled_layers.py", "kryptos/ciphers.py"]


def literal(values, stages, keys):
    values = list(values); offset = 0
    for stage in stages:
        if stage["operation"] == "gather":
            values = [values[i] for i in stage["permutation"]]
        else:
            n = stage["period"]; key = keys[offset:offset+n]; offset += n
            cipher = stage["cipher"]
            if cipher == "vigenere":
                values = [(value+key[i % n]) % 26 for i, value in enumerate(values)]
            elif cipher == "variant":
                values = [(value-key[i % n]) % 26 for i, value in enumerate(values)]
            else:
                values = [(key[i % n]-value) % 26 for i, value in enumerate(values)]
    return tuple(values)


def direct(text, stages, keys, alphabet):
    return "".join(alphabet[i] for i in literal([alphabet.index(c) for c in text], stages, keys))


def run():
    from kryptos.recipe_grammar import generate, expand_paths, synthesize
    from kryptos.recipe_algebra import compile_recipe, compiled_encrypt
    before = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    s = {"operation": "substitution", "period": 1, "cipher": "vigenere"}
    v = {**s, "cipher": "variant"}; b = {**s, "cipher": "beaufort"}; p = {**s, "period": 2}
    t = {"operation": "gather", "permutation": [1, 0]}; identity = {"operation": "gather", "permutation": [0, 1]}
    slots = [[s, v, t], [s, v, t], [identity, t]]
    grammar = generate({"length": 2, "slots": slots})
    serial = lambda value: json.dumps(value, sort_keys=True)
    syntax, image_checks, matrix_checks = [], 0, 0
    for leaf in grammar["leaves"]:
        recipes = expand_paths(grammar, leaf)
        assert len(recipes) == grammar["nodes"][leaf]["represented_paths"]
        syntax.extend(serial(stages) for stages in recipes)
        for text in [(0, 0), (0, 1), (1, 0), (13, 25), (25, 13), (25, 25)]:
            expected = None
            for stages in recipes:
                width = sum(stage.get("period", 0) for stage in stages if stage["operation"] == "substitution")
                image = {literal(text, stages, key) for key in itertools.product(range(26), repeat=width)}
                image_checks += 1
                if expected is None:
                    expected = image
                else:
                    assert image == expected
                compiled = compile_recipe(2, stages)
                for key in itertools.product([0, 1, 13, 25], repeat=width):
                    actual = compiled_encrypt("".join(chr(65+i) for i in text), list(key), compiled)
                    assert tuple(ord(c)-65 for c in actual) == literal(text, stages, key)
                    matrix_checks += 1
    assert Counter(syntax) == Counter(serial(list(stages)) for stages in itertools.product(*slots))
    assert sum(grammar["nodes"][i]["represented_paths"] for i in grammar["leaves"]) == 18
    boundary = generate({"length": 1, "slots": [[{"operation": "gather", "permutation": [0]}]*2]})
    assert len(expand_paths(boundary, boundary["leaves"][0])) == 2
    assert not generate({"length": 2, "slots": slots, "max_nodes": 1})["complete"]
    assert not generate({"length": 2, "slots": slots, "max_transitions": 1})["complete"]
    # Conservative classification does not claim all pointwise-equal relations merge.
    conservative = generate({"length": 1, "slots": [[s, b]]})
    assert len(conservative["leaves"]) == 2
    assert "distinct_transformation_families" not in conservative
    # Prevent reconstruction of a syntax path beyond the declared256-slot cap.
    try:
        generate({"length": 1, "slots": [[{**s, "period": 256}], [{**s, "period": 256}]]})
    except ValueError:
        pass
    else:
        raise AssertionError("grammar admitted unsupported total key-slot count")
    bank = [[identity], [t], [s], [v], [b], [p], [s, t], [t, s], [b, s], [s, t, s]]
    comparisons = replays = oracle_keys = 0
    cases = []
    for name, alphabet in [("standard", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ("kryptos", "KRYPTOSABCDEFGHIJLMNQUVWXZ")]:
        plains = [alphabet[0]+alphabet[1], alphabet[2]+alphabet[3], alphabet[13]+alphabet[25]]
        for generator, key in [([s], [1]), ([b], [13]), ([p], [2, 5]), ([s, t], [7]), ([t], [])]:
            valid = [direct(text, generator, key, alphabet) for text in plains]
            for perturb in (False, True):
                ciphers = list(valid)
                if perturb:
                    ciphers[-1] = alphabet[(alphabet.index(ciphers[-1][0])+1) % 26]+ciphers[-1][1]
                examples = [{"plaintext": text, "ciphertext": cipher, "source": "independent synthetic control"}
                            for text, cipher in zip(plains, ciphers)]
                expected = []
                for index, stages in enumerate(bank):
                    width = sum(stage.get("period", 0) for stage in stages if stage["operation"] == "substitution")
                    for key_values in itertools.product(range(26), repeat=width):
                        oracle_keys += 1
                        if all(direct(text, stages, key_values, alphabet) == cipher for text, cipher in zip(plains, ciphers)):
                            expected.append(index); break
                for priority, initial in [(False, 1), (True, 1), (False, 3), (True, 3)]:
                    result = synthesize({"recipes": bank, "examples": examples, "alphabet": name,
                                         "priority": priority, "initial_examples": initial})
                    assert result["complete"] and sorted(row["input_index"] for row in result["accepted"]) == expected
                    assert sorted(row["input_index"] for row in result["accepted"]+result["rejected"]) == list(range(len(bank)))
                    for row in result["accepted"]:
                        for text, cipher in zip(plains, ciphers):
                            assert direct(text, row["stages"], row["key_values"], alphabet) == cipher
                            replays += 1
                    comparisons += 1
                cases.append({"alphabet": name, "generating_stages": generator, "perturbed": perturb, "accepted_indices": expected})
    partial = synthesize({"recipes": bank, "examples": [{"plaintext": "AB", "ciphertext": "BC", "source": "synthetic"},
                        {"plaintext": "CD", "ciphertext": "DE", "source": "synthetic"}], "max_checks": 1})
    assert not partial["complete"] and partial["stop_reason"] == "max_checks"
    after = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    assert before == after, "reviewed inputs changed during run"
    return {"schema": "kryptos.independent-grammar-review.v1", "all_checks_passed": True,
            "verdict": "computationally verified only in the stated finite range",
            "python": platform.python_version(), "syntax_paths": len(syntax), "retained_classes": len(grammar["leaves"]),
            "literal_image_comparisons": image_checks, "literal_matrix_checks": matrix_checks,
            "cegis_bank_comparisons": comparisons, "literal_witness_pair_replays": replays,
            "exhaustive_oracle_key_vectors": oracle_keys, "cases": cases,
            "input_sha256_before": before, "input_sha256_after": after,
            "non_claims": ["No Kryptos method or plaintext authenticated", "Not exhaustive over all message lengths or recipes",
                           "Independent literal algorithms share the Python interpreter and may share conceptual errors"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--output", required=True)
    args = parser.parse_args(); output = Path(args.output)
    if output.exists():
        raise SystemExit("refusing to overwrite earlier evidence")
    result = run(); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("all_checks_passed", "syntax_paths", "literal_image_comparisons", "literal_matrix_checks", "cegis_bank_comparisons", "literal_witness_pair_replays", "exhaustive_oracle_key_vectors")}))
