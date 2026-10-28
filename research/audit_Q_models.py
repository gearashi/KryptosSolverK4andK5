"""Frozen finite Q71-90 controls. This program never starts a cipher search."""
import argparse
from collections import Counter
from hashlib import sha256
import itertools
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.geometry_constraints import frontier_paths, learn_turn_grammar, meet_paths, search_paths, tableau_registrations
from kryptos.language_constraints import (compile_joint_cribs, decode_codebook, expand_morphology,
    extraction_bank, robust_rank, segment_lattice, source_keys, verify_suggestions)


def oracle_paths(cells, start=0, end=None):
    """Literal coordinate DFS, no topology pruning or production helpers."""
    found = []; work = {"states": 0, "decisions": 0, "complete_routes": 0}
    def walk(path):
        work["states"] += 1
        if len(path) == len(cells):
            if end is None or path[-1] == end:
                found.append(tuple(path)); work["complete_routes"] += 1
            return
        a = cells[path[-1]]
        choices = [i for i, b in enumerate(cells) if i not in path and
                   sum(abs(a[j]-b[j]) for j in range(2)) == 1 and (i != end or len(path) == len(cells)-1)]
        if len(choices) > 1:
            work["decisions"] += 1
        for i in choices:
            walk(path+[i])
    walk([start])
    return sorted(found), work


def literal_keys(route, cipher, cribs, offsets=None, period=2, alphabet="ABC"):
    known = {}; offsets = offsets or [0]*len(cipher)
    for raw, symbol in cribs.items():
        i = int(raw); phase = i % period
        shift = (alphabet.index(cipher[route[i]])-offsets[route[i]]-alphabet.index(symbol)) % len(alphabet)
        if phase in known and known[phase] != shift:
            return False
        known[phase] = shift
    return True


def brute_language(text, lexicons, max_switches, unknown_score=-10, switch_penalty=0, grammar=()):
    """Literal complete segmentation/language enumeration, including unknowns."""
    pairs = {(g["previous"], g["next"]): g["score"] for g in grammar}
    best = None; work = {"states": 0, "complete_evaluations": 0}
    def walk(position, previous, switches, tag, score):
        nonlocal best
        work["states"] += 1
        if position == len(text):
            work["complete_evaluations"] += 1
            best = score if best is None else max(best, score)
            return
        for lex in lexicons:
            changed = previous is not None and previous != lex["language"]
            if switches+changed > max_switches:
                continue
            options = lex["entries"]+[{"text": text[position], "tag": "<unknown>", "score": unknown_score}]
            for entry in options:
                if text.startswith(entry["text"], position):
                    walk(position+len(entry["text"]), lex["language"], switches+changed, entry["tag"],
                         score+entry["score"]+pairs.get((tag, entry["tag"]), 0)+(switch_penalty if changed else 0))
    walk(0, None, 0, "<s>", 0)
    return best, work


def brute_codebook(text, codebook):
    work = {"states": 0, "complete_evaluations": 0}; outputs = []
    def walk(offset, output):
        work["states"] += 1
        if offset == len(text):
            outputs.append(output); work["complete_evaluations"] += 1
            return
        for token, value in codebook.items():
            if text.startswith(token, offset):
                walk(offset+len(token), output+value)
    walk(0, "")
    return outputs, work


def run():
    result = {"schema": "kryptos.Q-model-audit.v1", "python": platform.python_version(),
              "contract_sha256": sha256((ROOT/"research/phase_Q_models_contract.json").read_bytes()).hexdigest(),
              "geometry": [], "language": [], "codebook": [], "other": {}, "all_checks_passed": False}
    fixtures = [
        ("2x3", [(r, c) for r in range(2) for c in range(3)], 0, 5),
        ("3x3", [(r, c) for r in range(3) for c in range(3)], 0, 8),
        ("3x4", [(r, c) for r in range(3) for c in range(4)], 0, 11),
        ("disconnected", [(0, 0), (0, 1), (4, 0), (4, 1)], 0, 3),
        ("cross", [(0, 0), (0, 1), (0, -1), (1, 0), (-1, 0)], 1, 2),
        ("ragged", [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (2, 0), (2, 1)], 0, 6)]
    for name, cells, start, end in fixtures:
        expected, baseline = oracle_paths(cells, start, end)
        row = {"case": name, "input": {"cells": cells, "start": start, "end": end},
               "route_count": len(expected), "oracle": baseline, "variants": {}}
        for variant, flags in [("plain", (False, False, False)), ("connectivity", (True, False, False)),
                               ("degrees", (False, True, False)), ("articulation_bridges", (False, False, True)),
                               ("combined", (True, True, True))]:
            actual = search_paths(cells, start=start, end=end, connectivity=flags[0], degrees=flags[1], articulation=flags[2])
            assert sorted(tuple(r["route"]) for r in actual["routes"]) == expected
            row["variants"][variant] = actual["work"]
        frontier = frontier_paths(cells, start=start, end=end)
        assert frontier["count"] == len(expected)
        if frontier["route"] is not None:
            assert tuple(frontier["route"]) in expected
        meet = meet_paths(cells, start=start, end=end)
        assert [tuple(r) for r in meet["routes"]] == expected
        row["frontier"] = frontier; row["meet"] = meet["work"]
        result["geometry"].append(row)
    # Independently check the smallest domain through full permutation coverage.
    cells = fixtures[0][1]
    permutations = [p for p in itertools.permutations(range(6)) if p[0] == 0]
    legal = [p for p in permutations if all(sum(abs(cells[a][i]-cells[b][i]) for i in (0, 1)) == 1 for a, b in zip(p, p[1:]))]
    paths, _ = oracle_paths(cells)
    assert sorted(legal) == paths
    result["other"]["Q71"] = {"full_permutation_evaluations": len(permutations), "complete_graph_routes": len(paths)}
    cells = fixtures[2][1]; paths, work = oracle_paths(cells)
    cipher = "ABCABCABCABC"; cribs = {"0": "A", "2": "B", "4": "C", "7": "A"}
    expected = [r for r in paths if literal_keys(r, cipher, cribs)]
    actual = search_paths(cells, ciphertext=cipher, alphabet="ABC", period=2, cribs=cribs)
    assert [tuple(r["route"]) for r in actual["routes"]] == expected
    result["other"]["Q77"] = {"postfilter_complete_routes": len(paths), "accepted_routes": len(expected), "incremental": actual["work"]}
    positive_cribs = {str(i): "ABC"[("ABC".index(cipher[paths[0][i]])-(i % 2)) % 3] for i in (0, 2, 4, 7)}
    positive_expected = [r for r in paths if literal_keys(r, cipher, positive_cribs)]
    positive = search_paths(cells, ciphertext=cipher, alphabet="ABC", period=2, cribs=positive_cribs)
    assert positive_expected and [tuple(r["route"]) for r in positive["routes"]] == positive_expected
    result["other"]["Q77_positive"] = {"cribs": positive_cribs, "postfilter_complete_routes": len(paths),
                                          "accepted_routes": len(positive_expected), "incremental": positive["work"]}
    regs = [{"id": "identity", "offsets": [0]*len(cells), "source": "synthetic identity"},
            {"id": "alternating", "offsets": [i % 2 for i in range(len(cells))], "source": "synthetic alternating"},
            {"id": "identity-alias", "offsets": [3]*len(cells), "source": "same modulo three"}]
    expected = [(r, sorted(reg["id"] for reg in regs if literal_keys(r, cipher, cribs, reg["offsets"]))) for r in paths]
    expected = [(r, ids) for r, ids in expected if ids]
    actual = search_paths(cells, ciphertext=cipher, alphabet="ABC", period=2, cribs=cribs, registrations=regs)
    observed = [(tuple(r["route"]), sorted(a["id"] for reg in r["registrations"] for a in reg["aliases"])) for r in actual["routes"]]
    assert observed == expected
    result["other"]["Q80"] = {"separate_registration_route_checks": len(paths)*len(regs), "accepted_routes": len(expected), "shared": actual["work"]}
    registration = tableau_registrations([[0, 0], [0, 1]],
        [{"row": 2, "column": 3, "symbol": "B"}, {"row": 3, "column": 3, "symbol": "C"}],
        [{"id": "rotated", "matrix": [[0, -1], [1, 0]], "offset": [3, 3]},
         {"id": "missing", "matrix": [[1, 0], [0, 1]], "offset": [0, 0]}], source="synthetic registration")
    assert registration["registrations"][0]["offsets"] == [2, 1] and registration["rejected"][0]["id"] == "missing"
    result["other"]["Q80_coordinate_compilation"] = registration
    cells = fixtures[1][1]; paths, _ = oracle_paths(cells, start=4)
    quotient = search_paths(cells, start=4, symmetry=True)
    assert {tuple(m[i] for i in r["route"]) for r in quotient["routes"] for m in quotient["automorphisms"]} == set(paths)
    result["other"]["Q78"] = {"labelled_routes": len(paths), "representatives": quotient["route_count"], "work": quotient["work"]}
    cells = fixtures[0][1]; paths, _ = oracle_paths(cells)
    train = [0, 1, 2, 5, 4, 3]
    grammar = learn_turn_grammar([{"cells": cells, "route": train}], source="frozen synthetic training path")
    def allowed(route):
        directions = [(cells[b][0]-cells[a][0], cells[b][1]-cells[a][1]) for a, b in zip(route, route[1:])]
        tokens = []
        for u, v in zip(directions, directions[1:]):
            tokens.append("S" if u == v else "R" if u[0]*v[1]-u[1]*v[0] < 0 else "L")
        return all(t in grammar["turns"] for t in tokens) and all([a, b] in grammar["pairs"] for a, b in zip(tokens, tokens[1:]))
    expected = [p for p in paths if allowed(p)]
    actual = search_paths(cells, grammar=grammar)
    assert [tuple(r["route"]) for r in actual["routes"]] == expected
    result["other"]["Q79"] = {"postfilter_routes": len(paths), "accepted_routes": len(expected), "work": actual["work"], "grammar_sha256": grammar["sha256"]}
    lexicons = [{"language": "a", "source": "synthetic", "entries": [
        {"text": "A", "tag": "x", "score": 2}, {"text": "AA", "tag": "x", "score": 5}, {"text": "AAA", "tag": "y", "score": 4}]},
        {"language": "b", "source": "synthetic", "entries": [
        {"text": "AB", "tag": "y", "score": 7}, {"text": "B", "tag": "x", "score": 3}]}]
    grammar = [{"previous": "x", "next": "y", "score": 2}]
    for text in ("AAAAAA", "AAABAA", "ABAAZ"):
        for switches in (0, 1, 2):
            score, baseline = brute_language(text, lexicons, switches, switch_penalty=-1, grammar=grammar)
            actual = segment_lattice(text, lexicons, max_switches=switches, switch_penalty=-1, grammar=grammar)
            assert actual["score"] == score
            result["language"].append({"text": text, "switches": switches, "optimum": score, "enumeration": baseline, "lattice": actual["work"]})
    morphology = expand_morphology([{"text": "PORT", "class": "a", "score": 1}, {"text": "AM", "class": "v", "score": 2}],
        [{"text": "A", "classes": ["a"], "tag": "noun", "score": 3}, {"text": "O", "classes": ["v"], "tag": "verb", "score": 4}], source="synthetic Latin-shaped stems")
    assert [(r["text"], r["score"]) for r in morphology["entries"]] == [("AMO", 6), ("PORTA", 4)]
    result["other"]["Q82"] = morphology
    book = {"A": "X", "AA": "XX", "AAA": "Y"}
    for length in (6, 9, 12):
        outputs, baseline = brute_codebook("A"*length, book)
        for constraints in ({}, {"target_length": 4}, {"inventory": {"X": 2}},
                            {"residues": [{"symbol": "X", "modulus": 3, "value": 1}]},
                            {"target_length": 2, "inventory": {"X": 7}}):
            expected = Counter(o for o in outputs if ("target_length" not in constraints or len(o) == constraints["target_length"])
                and ("inventory" not in constraints or o.count("X") == constraints["inventory"]["X"])
                and ("residues" not in constraints or o.count("X") % 3 == 1))
            off = decode_codebook("A"*length, book, source="synthetic", necessary_filters=False, **constraints)
            on = decode_codebook("A"*length, book, source="synthetic", necessary_filters=True, **constraints)
            for actual in (off, on):
                assert {r["text"]: r["interpretation_count"] for r in actual["outputs"]} == dict(expected)
            result["codebook"].append({"length": length, "constraints": constraints, "outputs": len(expected),
                                      "enumeration": baseline, "without_filters": off["work"], "with_filters": on["work"]})
    ene = decode_codebook("EASTNORTHEASTBERLINCLOCK", {"EASTNORTHEAST": "ENE", "BERLINCLOCK": "BC"}, source="user-suggested conditional codebook")
    assert ene["outputs"][0]["text"] == "ENEBC"
    result["other"]["Q85_ENE_BC"] = ene
    recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": "standard", "stages": [
        {"operation": "repeat_substitution", "cipher": "vigenere", "key_pattern": "B"}]}
    seeds = verify_suggestions("BCD", [{"plaintext": "ABC", "recipe": recipe, "source": "chat test"},
                                      {"plaintext": "ABD", "recipe": recipe, "source": "chat test"}], cribs={"1": "B"})
    assert len(seeds["accepted"]) == len(seeds["rejected"]) == 1
    result["other"]["Q84"] = {"accepted": len(seeds["accepted"]), "rejected": len(seeds["rejected"])}
    keys = source_keys([{"id": "a", "text": "AB AB", "source": "synthetic"}, {"id": "b", "text": "A B", "source": "synthetic"}],
                       [{"operation": "letters"}, {"operation": "initials"}, {"operation": "letters", "reverse": True}])
    result["other"]["Q87"] = keys
    models = [{"id": "a", "source": "synthetic", "n": 1, "weights": {"A": 5, "B": 1}, "default": 0, "scale": 1},
              {"id": "b", "source": "synthetic", "n": 1, "weights": {"A": 1, "B": 3}, "default": 0, "scale": 1}]
    bank = [{"id": "a", "text": "AA"}, {"id": "b", "text": "BB"}, {"id": "c", "text": "AB"}, {"id": "d", "text": "AA"}]
    robust = robust_rank(bank, models); assert robust["candidates"][0]["text"] == "AB"
    result["other"]["Q88"] = robust
    extractions = [{"id": "k5-control", "indices": [0, 2, 4], "output_cribs": {"0": "A", "1": "B", "2": "C"},
                    "independent_source": "synthetic independently supplied output ABC"}]
    joint = compile_joint_cribs(12, extractions)
    assert joint["cribs"] == {"0": "A", "2": "B", "4": "C"}
    paths, _ = oracle_paths(fixtures[2][1])
    expected = [p for p in paths if literal_keys(p, cipher, joint["cribs"])]
    constrained = search_paths(fixtures[2][1], ciphertext=cipher, alphabet="ABC", period=2, cribs=joint["cribs"])
    assert [tuple(r["route"]) for r in constrained["routes"]] == expected
    result["other"]["Q89"] = {"literal_joint_constraints": joint, "postfilter_complete_routes": len(paths), "constrained": constrained["work"]}
    extraction = extraction_bank("ABAB", [{"id": "a", "indices": [0, 2], "source": "synthetic even"},
        {"id": "b", "indices": [2, 0], "source": "synthetic reversed even"}, {"id": "c", "indices": [1, 3], "source": "synthetic odd"}])
    assert len(extraction["outputs"]) == 2
    result["other"]["Q90"] = extraction
    result["all_checks_passed"] = True
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--output", required=True)
    args = parser.parse_args(); path = Path(args.output)
    if path.exists():
        raise SystemExit("refusing to overwrite an earlier audit result")
    result = run(); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"all_checks_passed": result["all_checks_passed"], "geometry_cases": len(result["geometry"]),
                      "language_cases": len(result["language"]), "codebook_cases": len(result["codebook"])}))
