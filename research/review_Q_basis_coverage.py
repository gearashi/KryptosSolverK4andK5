"""Independent finite basis/overlap review with literal set and score oracles.

The frozen controls cover F2/F13 paired plaintext/key images, selected-coordinate
identities, affine subset/intersection sets, and an overlapping real-cipher bank.
No production implementation is reused to compute the expected finite sets.
"""
from dataclasses import replace
import copy
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MODEL = "research/runs/evaluation-J-001/artifacts/english-two-author-trigram.json"
INPUTS = ["research/review_Q_basis_coverage.py", MODEL]+["kryptos/"+name for name in (
    "__main__.py", "advanced_cli.py", "ciphers.py", "constraint_algebra.py", "constraint_cover_proof.py",
    "constraint_coverage.py", "constraint_lab.py", "constraint_reuse.py", "correlated_bound.py", "data.py", "explanations.py",
    "family_identity.py", "general_layers.py", "grid.py", "language.py", "layer_plan.py", "next_cli.py",
    "position_residues.py", "recovery.py", "replay_expanded.py", "scheduled_layers.py", "scoring.py", "search_runtime.py")]


def field_pairs(field):
    result = set()
    for coordinates in itertools.product(range(field.modulus), repeat=len(field.plaintext_columns)):
        text = tuple((a+sum(c[i]*v for c, v in zip(field.plaintext_columns, coordinates))) % field.modulus
                     for i, a in enumerate(field.plaintext_base))
        keys = tuple((a+sum(c[i]*v for c, v in zip(field.key_lifts, coordinates))) % field.modulus
                     for i, a in enumerate(field.key_base))
        result.add((text, keys))
    return result


def points(family, prime):
    return {tuple((a+sum(c[i]*v for c, v in zip(family["basis"], coordinates))) % prime
                  for i, a in enumerate(family["base"]))
            for coordinates in itertools.product(range(prime), repeat=len(family["basis"]))}


def literal_encrypt(text, stages, keys):
    values = [ord(c)-65 for c in text]; offset = 0
    for stage in stages:
        if stage["operation"] == "gather":
            values = [values[i] for i in stage["permutation"]]
        else:
            n = stage["period"]; key = keys[offset:offset+n]; offset += n
            cipher = stage.get("cipher", "vigenere")
            values = [((key[i % n]-v) if cipher == "beaufort" else (v-key[i % n]) if cipher == "variant" else (v+key[i % n])) % 26
                      for i, v in enumerate(values)]
    return "".join(chr(65+i) for i in values)


def run():
    from kryptos.constraint_algebra import sparse_field, plaintext_coordinate_field, affine_relation, disjoint_finite_cover
    from kryptos.general_layers import FieldSolution, solve_layers
    from kryptos.constraint_coverage import run as cover
    from kryptos.constraint_cover_proof import create as create_proof
    from kryptos.constraint_lab import RelationSearch
    from kryptos.constraint_reuse import score_projection_groups
    before = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    paired_checks = coordinate_checks = actual_recipe_replays = intersection_checks = 0
    sparse_changes = 0
    for prime in (2, 13):
        constant = FieldSolution(prime, True, 0, (1,), 0, (1, 0), (), ())
        assert field_pairs(sparse_field(constant)[0]) == field_pairs(constant)
        assert field_pairs(plaintext_coordinate_field(constant)[0]) == field_pairs(constant)
        paired_checks += 2
        for base in ((0, 0, 0), (1, 1, 1), (prime-1, 2 % prime, 1)):
            for columns in (((1, 1, 0), (1, 1, 1)), ((1, 0, 1), (1, 1, 1))):
                field = FieldSolution(prime, True, 0, (1, 2 % prime), 2, base, columns, ((1, 0), (0, 1)))
                sparse, report = sparse_field(field)
                direct, positions = plaintext_coordinate_field(field)
                reference = field_pairs(field)
                assert field_pairs(sparse) == reference == field_pairs(direct)
                assert report["after"] <= report["before"]
                sparse_changes += len(report["changes"]); paired_checks += 2
                for values in itertools.product(range(prime), repeat=2):
                    for axis, position in enumerate(positions["positions"]):
                        actual = (direct.plaintext_base[position]+sum(c[position]*v for c, v in zip(direct.plaintext_columns, values))) % prime
                        assert actual == values[axis]
                        coordinate_checks += 1
    s = {"operation": "substitution", "period": 2, "cipher": "vigenere"}
    t = {"operation": "gather", "permutation": [2, 0, 3, 1]}
    recipes = [[s], [s, t, {**s, "period": 1}], [s, t, {**s, "cipher": "beaufort"}],
               [{**s, "cipher": "beaufort"}, t, {**s, "period": 1, "cipher": "variant"}]]
    for stages in recipes:
        width = sum(stage.get("period", 0) for stage in stages if stage["operation"] == "substitution")
        cipher = literal_encrypt("ABCD", stages, list(range(1, width+1)))
        original = solve_layers(cipher, {0: "A"}, stages, "standard")
        for transform in (sparse_field, plaintext_coordinate_field):
            a, _ = transform(original.field2); b, _ = transform(original.field13)
            assert field_pairs(a) == field_pairs(original.field2)
            assert field_pairs(b) == field_pairs(original.field13)
            paired_checks += 2
            changed = replace(original, field2=a, field13=b)
            # All CRT coordinate pairs here fit within26^3; literal replays use
            # a fixed prefix of at most32, while the full paired field sets above
            # independently verify the entire transformation images.
            for coordinates2, coordinates13 in itertools.islice(itertools.product(
                    itertools.product(range(2), repeat=changed.dimensions_mod2),
                    itertools.product(range(13), repeat=changed.dimensions_mod13)), 32):
                text = changed.plaintext(coordinates2, coordinates13)
                keystrings = changed.keys(coordinates2, coordinates13)
                keys = [ord(c)-65 for key in keystrings for c in key]
                assert literal_encrypt(text, stages, keys) == cipher and text[0] == "A"
                actual_recipe_replays += 1
    for prime in (2, 13):
        bases = [(0, 0), (1, 0), (0, 1), (prime-1, prime-1)]
        generators = [[], [(1, 0)], [(0, 1)], [(1, 1)], [(1, 0), (0, 1)], [(1, 1), (1, 1)]]
        families = [{"base": list(base), "basis": [list(c) for c in columns]} for base in bases for columns in generators]
        sets = [points(f, prime) for f in families]
        for i, left in enumerate(families):
            for j, right in enumerate(families):
                actual = affine_relation(left, right, prime)
                intersection = set() if actual["intersection"] is None else points(actual["intersection"], prime)
                assert intersection == sets[i] & sets[j]
                assert actual["left_subset_right"] == (sets[i] <= sets[j])
                assert actual["right_subset_left"] == (sets[j] <= sets[i])
                assert actual["intersection_size"] == len(intersection)
                intersection_checks += 1
        cover_families = [{**families[i], "prime": prime} for i in (1, 3, 4, 5)]
        actual = disjoint_finite_cover(cover_families)
        expected = [points(f, prime) for f in cover_families]
        owned = set()
        for index, block in enumerate(actual["blocks"]):
            local = {tuple(p) for p in block["points"]}
            assert local == expected[index]-owned
            owned |= local
        assert owned == set.union(*expected)
        for row in actual["aliases"]:
            assert row["families"] == [i for i, values in enumerate(expected) if tuple(row["point"]) in values]
    projected = score_projection_groups({"base": [0, 0], "columns": [[13, 0], [0, 14]], "domains": [2, 13]}, [0])
    assert projected["scoring_evaluations"] == 2 and projected["reconstruction_assignments"] == 26
    assert {tuple(v) for group in projected["groups"] for v in group["all_tie_coordinates"]} == set(itertools.product(range(2), range(13)))
    rejected_inputs = 0
    for bad in ([{"prime": -1, "base": [0], "basis": [[1]]}],
                [{"prime": 2, "base": [0], "basis": []}, {"prime": 13, "base": [0], "basis": []}]):
        try:
            disjoint_finite_cover(bad)
        except ValueError:
            rejected_inputs += 1
        else:
            raise AssertionError("invalid affine field metadata accepted")
    try:
        score_projection_groups({"base": [0], "columns": [[1]], "domains": [-1]}, [0])
    except ValueError:
        rejected_inputs += 1
    else:
        raise AssertionError("negative coordinate domain accepted")
    model_path = str(ROOT/MODEL)
    families = []
    expected_sets = []
    for cipher, period in [("BCD", 1), ("BCD", 2), ("ACE", 1)]:
        families.append({"cipher_request": {"target": "custom", "ciphertext": cipher, "cribs": [],
                         "alphabet": "standard", "stages": [{"operation": "substitution", "period": period}],
                         "model_path": model_path}})
        expected_sets.append({"".join(chr(65+(ord(c)-65-key[i % period]) % 26) for i, c in enumerate(cipher))
                              for key in itertools.product(range(26), repeat=period)})
    recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": "standard", "stages": [
        {"operation": "repeat_substitution", "cipher": "vigenere", "key_pattern": "B"}]}
    families.append({"ciphertext": "BCD", "cribs": [], "model_path": model_path,
                     "candidates": [{"plaintext": "ABC", "encryption_recipe": recipe,
                                     "score": 999999, "authenticated_solution": True}]})
    expected_sets.append({"ABC"})
    actual = cover({"families": families, "top": 10})
    model = json.loads((ROOT/MODEL).read_text(encoding="utf-8")); numerator, denominator = model["alpha"].as_integer_ratio()
    union = set.union(*expected_sets)
    objective = lambda text: model["counts"].get(text, 0)*denominator+numerator
    ranked = sorted(union, key=lambda text: (-objective(text), text))
    assert [c["plaintext"] for c in actual["candidates"]] == ranked[:10]
    for index, row in enumerate(actual["families"]):
        assert row["distinct_plaintexts"] == len(expected_sets[index])
        selected = sorted(expected_sets[index], key=lambda text: (-objective(text), text))[:10]
        assert [c["plaintext"] for c in row["candidates"]] == selected
        for candidate in row["candidates"]:
            assert int(candidate["exact_objective_hex"], 16) == objective(candidate["plaintext"])
            assert candidate["authenticated_solution"] is False
    assert "score" not in actual["families"][3]["candidates"][0]
    assert actual["work"]["complete_candidate_evaluations"] == len(union)
    assert actual["preparation"]["literal_replays"] == 3*sum(len(s) for s in expected_sets[:3])+1
    invalid = [dict(families[0]), {"cipher_request": {**families[1]["cipher_request"], "score_mask": [0]}}]
    try:
        cover({"families": invalid})
    except ValueError:
        pass
    else:
        raise AssertionError("coverage accepted mismatching score masks")
    proof_checks = tamper_rejections = 0
    for objective, rows in [("sum", [[0, 10], [1, 0]]), ("sum", [[0, -2], [1, -1]]),
                            ("product", [[0, 0], [1, 0]])]:
        for top in (1, 3):
            problem = {"domains": {"a": [0, 1], "b": [0, 1], "c": [0, 1]},
                       "factors": [{"scope": ["a"], "rows": rows}], "objective": objective, "top": top}
            values = {row[0]: row[1] for row in rows}
            expected = sorted([(values[a], (a, b, c)) for a, b, c in itertools.product(range(2), repeat=3)], key=lambda row: (-row[0], row[1]))[:top]
            for regions in ([{}], [{"a": 0}], [{"a": 0}, {"b": 0}]):
                artifacts = [create_proof({"problem": problem, "assumptions": assumptions})["coverage"] for assumptions in regions]
                checked = RelationSearch({**problem, "coverage": artifacts}).run()
                observed = [(row["score"], tuple(row["assignment"][name] for name in ("a", "b", "c"))) for row in checked["candidates"]]
                assert checked["complete"] and observed == expected
                proof_checks += 1
            artifact = create_proof({"problem": problem})["coverage"]
            changed_score = copy.deepcopy(artifact); changed_score["candidates"][0]["score"] += 100
            omitted = copy.deepcopy(artifact); omitted["tree"]["children"].pop()
            false_conflict = copy.deepcopy(artifact); false_conflict["tree"] = {"kind": "conflict"}
            false_bound = copy.deepcopy(artifact); false_bound["tree"] = {"kind": "bound"}
            for damaged in (changed_score, omitted, false_conflict, false_bound):
                try:
                    RelationSearch({**problem, "coverage": [damaged]})
                except ValueError:
                    tamper_rejections += 1
                else:
                    raise AssertionError("tampered subtree proof was accepted")
    impossible = {"domains": {"x": [0, 1]}, "relations": [{"scope": ["x"], "rows": []}], "top": 1}
    artifact = create_proof({"problem": impossible})["coverage"]
    checked = RelationSearch({**impossible, "coverage": [artifact]}).run()
    assert checked["complete"] and not checked["candidates"]
    proof_checks += 1
    after = {p: sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
    assert before == after, "production inputs changed during finite review"
    return {"schema": "kryptos.independent-basis-coverage-review.v1", "all_checks_passed": True,
            "verdict": "computationally verified only in the stated finite range", "python": platform.python_version(),
            "paired_plaintext_key_image_checks": paired_checks, "selected_coordinate_checks": coordinate_checks,
            "accepted_sparse_changes": sparse_changes, "literal_actual_recipe_replays": actual_recipe_replays,
            "subtree_proof_reuse_checks": proof_checks, "subtree_proof_tamper_rejections": tamper_rejections,
            "invalid_helper_inputs_rejected": rejected_inputs, "score_projection": {"representatives": 2, "all_tie_coordinates": 26},
            "affine_relation_comparisons": intersection_checks, "coverage": {"family_sizes": [len(s) for s in expected_sets],
                "distinct_plaintexts": len(union), "work": actual["work"], "preparation": actual["preparation"]},
            "input_sha256_before": before, "input_sha256_after": after,
            "non_claims": ["No universal efficiency gain", "No claim that sparse basis is globally sparsest",
                "Finite coverage materializes all supplied families before scoring", "No K4/K5 authentication"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--output", required=True)
    args = parser.parse_args(); output = Path(args.output)
    if output.exists():
        raise SystemExit("refusing to overwrite prior evidence")
    result = run(); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("all_checks_passed", "paired_plaintext_key_image_checks", "selected_coordinate_checks", "literal_actual_recipe_replays", "affine_relation_comparisons", "subtree_proof_reuse_checks", "subtree_proof_tamper_rejections", "coverage")}))
