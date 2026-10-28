import itertools
import unittest

from kryptos.geometry_constraints import (GeometryLimit, frontier_paths, learn_turn_grammar,
    meet_paths, replay_route, search_paths, tableau_registrations)
from kryptos.language_constraints import (compile_joint_cribs, decode_codebook, expand_morphology,
    extraction_bank, robust_rank, segment_lattice, source_keys, verify_suggestions)
from kryptos.model_lab import run


def literal_routes(cells, start=0, end=None):
    """Deliberately independent permutation oracle for tiny graph fixtures."""
    found = []
    for tail in itertools.permutations(i for i in range(len(cells)) if i != start):
        route = (start,)+tail
        if end is not None and route[-1] != end:
            continue
        if all(abs(cells[a][0]-cells[b][0])+abs(cells[a][1]-cells[b][1]) == 1 for a, b in zip(route, route[1:])):
            found.append(route)
    return sorted(found)


def literal_codebook(text, codebook):
    if not text:
        return [""]
    return [value+tail for key, value in codebook.items() if text.startswith(key)
            for tail in literal_codebook(text[len(key):], codebook)]


class GeometryTests(unittest.TestCase):
    def test_all_three_by_three_subgraphs_against_literal_prefix_search(self):
        rectangle = [(r, c) for r in range(3) for c in range(3)]
        for mask in range(1, 1 << len(rectangle)):
            cells = [c for i, c in enumerate(rectangle) if mask >> i & 1]
            expected = []
            def walk(path):
                if len(path) == len(cells):
                    expected.append(tuple(path)); return
                for i, point in enumerate(cells):
                    previous = cells[path[-1]]
                    if i not in path and abs(point[0]-previous[0])+abs(point[1]-previous[1]) == 1:
                        walk(path+[i])
            walk([0])
            actual = search_paths(cells)
            self.assertEqual([tuple(r["route"]) for r in actual["routes"]], sorted(expected), cells)

    def test_full_passage_length_supported(self):
        result = search_paths([(0, i) for i in range(97)], ciphertext="A"*97, cribs={"96": "A"})
        self.assertEqual(result["route_count"], 1)
        self.assertEqual(result["routes"][0]["route"], list(range(97)))

    def test_all_small_subgraphs_against_literal_permutations(self):
        rectangle = [(r, c) for r in range(2) for c in range(3)]
        for mask in range(1, 1 << len(rectangle)):
            cells = [c for i, c in enumerate(rectangle) if mask >> i & 1]
            expected = literal_routes(cells)
            for flags in [(False, False, False), (True, False, False), (False, True, False), (False, False, True), (True, True, True)]:
                actual = search_paths(cells, connectivity=flags[0], degrees=flags[1], articulation=flags[2])
                self.assertEqual([tuple(r["route"]) for r in actual["routes"]], expected, (cells, flags))
            for end in range(1, len(cells)):
                restricted = [r for r in expected if r[-1] == end]
                result = frontier_paths(cells, end=end)
                self.assertEqual(result["count"], len(restricted), cells)
                self.assertEqual(result["route"] is not None, bool(restricted))
                self.assertEqual([tuple(r) for r in meet_paths(cells, end=end)["routes"]], restricted)

    def test_singleton_and_budget_errors(self):
        self.assertEqual(frontier_paths([(1, 1)], end=0)["count"], 1)
        self.assertEqual(meet_paths([(1, 1)], end=0)["routes"], [[0]])
        with self.assertRaises(GeometryLimit):
            search_paths([(0, 0), (0, 1), (1, 0), (1, 1)], max_states=1)
        with self.assertRaises(GeometryLimit):
            frontier_paths([(0, 0), (0, 1), (1, 0), (1, 1)], end=1, max_states=1)

    def test_cribs_and_registration_match_literal_filter(self):
        cells = [(r, c) for r in range(2) for c in range(3)]
        regs = [{"id": "a", "offsets": [0]*6, "source": "test identity"},
                {"id": "b", "offsets": [0, 1, 0, 1, 0, 1], "source": "test alternating"},
                {"id": "duplicate", "offsets": [3]*6, "source": "same modulo three"}]
        cipher = "ABCCBA"; alphabet = "ABC"; known = {"0": "A", "2": "B", "4": "C"}
        actual = search_paths(cells, ciphertext=cipher, alphabet=alphabet, period=2, cribs=known, registrations=regs)
        expected = []
        for path in literal_routes(cells):
            aliases = []
            for reg in regs:
                shifts = [(alphabet.index(cipher[path[int(p)]])-reg["offsets"][path[int(p)]]-alphabet.index(s)) % 3 for p, s in known.items()]
                if len(set(shifts)) == 1:
                    aliases.append(reg["id"])
            if aliases:
                expected.append((path, sorted(aliases)))
        observed = [(tuple(r["route"]), sorted(a["id"] for reg in r["registrations"] for a in reg["aliases"])) for r in actual["routes"]]
        self.assertEqual(observed, expected)

    def test_symmetry_recovers_every_original_orbit(self):
        cells = [(r, c) for r in range(3) for c in range(3)]
        full = search_paths(cells, start=4)
        quotient = search_paths(cells, start=4, symmetry=True)
        reconstructed = {tuple(mapping[i] for i in r["route"]) for r in quotient["routes"] for mapping in quotient["automorphisms"]}
        self.assertEqual(reconstructed, {tuple(r["route"]) for r in full["routes"]})
        labelled = search_paths(cells, start=4, ciphertext="ABCDEFGHI", symmetry=True)
        self.assertEqual(len(labelled["automorphisms"]), 1)
        self.assertEqual(labelled["route_count"], full["route_count"])

    def test_grammar_freeze_and_literal_turn_replay(self):
        cells = [(r, c) for r in range(2) for c in range(3)]
        training = [0, 1, 2, 5, 4, 3]
        grammar = learn_turn_grammar([{"cells": cells, "route": training}], source="synthetic solved route")
        result = search_paths(cells, grammar=grammar)
        self.assertIn(training, [r["route"] for r in result["routes"]])
        self.assertEqual(grammar["turns"], ["R", "S"])
        self.assertEqual(grammar, learn_turn_grammar([{"cells": cells, "route": training}], source="synthetic solved route"))
        with self.assertRaises(ValueError):
            replay_route(cells, [0, 2, 1, 3, 4, 5])

    def test_tableau_registration_transform_and_missing_cells(self):
        result = tableau_registrations([[0, 0], [0, 1]],
            [{"row": 2, "column": 3, "symbol": "B"}, {"row": 3, "column": 3, "symbol": "C"}],
            [{"id": "rotated", "matrix": [[0, -1], [1, 0]], "offset": [3, 3]},
             {"id": "missing", "matrix": [[1, 0], [0, 1]], "offset": [0, 0]}], source="synthetic registration")
        self.assertEqual(result["registrations"][0]["offsets"], [2, 1])
        self.assertEqual(result["rejected"][0]["id"], "missing")


class LanguageTests(unittest.TestCase):
    def test_ambiguous_segmentation_and_unknown(self):
        lex = [{"language": "test", "source": "synthetic", "entries": [
            {"text": "A", "tag": "n", "score": 2}, {"text": "AA", "tag": "n", "score": 5},
            {"text": "AAA", "tag": "n", "score": 4}]}]
        result = segment_lattice("AAAAZ", lex, unknown_score=-7)
        self.assertEqual(result["score"], 3)
        self.assertEqual([t["text"] for t in result["tokens"]], ["AA", "AA", "Z"])
        self.assertTrue(result["tokens"][-1]["unknown"])
        self.assertGreater(result["work"]["merged_prefixes"], 0)

    def test_grammar_and_language_switches(self):
        lex = [{"language": "a", "source": "synthetic", "entries": [{"text": "AB", "tag": "x", "score": 5}]},
               {"language": "b", "source": "synthetic", "entries": [{"text": "CD", "tag": "y", "score": 6}]}]
        zero = segment_lattice("ABCDAB", lex, max_switches=0)
        one = segment_lattice("ABCDAB", lex, max_switches=1)
        two = segment_lattice("ABCDAB", lex, max_switches=2, switch_penalty=-1,
                              grammar=[{"previous": "x", "next": "y", "score": 3}])
        self.assertEqual(zero["score"], -10)
        self.assertEqual(one["score"], -9)
        self.assertEqual(two["score"], 17)
        self.assertEqual(two["switches"], 2)

    def test_morphology_finite_class_licensing(self):
        expanded = expand_morphology(
            [{"text": "PORT", "class": "a", "score": 1}, {"text": "AM", "class": "v", "score": 2}],
            [{"text": "A", "classes": ["a"], "tag": "noun", "score": 3},
             {"text": "O", "classes": ["v"], "tag": "verb", "score": 4}], source="synthetic Latin-shaped example")
        self.assertEqual(expanded["entries"], [{"text": "AMO", "tag": "verb", "score": 6}, {"text": "PORTA", "tag": "noun", "score": 4}])

    def test_codebook_outputs_counts_and_filters(self):
        book = {"A": "X", "AA": "XX", "AAA": "Y"}
        for length in range(1, 9):
            text = "A"*length
            literal = literal_codebook(text, book)
            for settings in [{}, {"target_length": 4}, {"inventory": {"X": 2}},
                             {"residues": [{"symbol": "X", "modulus": 3, "value": 1}]},
                             {"target": "XXY"}]:
                expected = [s for s in literal if
                    ("target_length" not in settings or len(s) == settings["target_length"]) and
                    ("inventory" not in settings or s.count("X") == 2) and
                    ("residues" not in settings or s.count("X") % 3 == 1) and
                    ("target" not in settings or s == settings["target"])]
                for enabled in (False, True):
                    result = decode_codebook(text, book, source="synthetic", necessary_filters=enabled, **settings)
                    observed = {entry["text"]: entry["interpretation_count"] for entry in result["outputs"]}
                    self.assertEqual(observed, {s: expected.count(s) for s in set(expected)}, (length, settings, enabled))

    def test_seed_replay_and_literal_cribs(self):
        recipe = {"schema": "kryptos.encryption-recipe.v1", "alphabet": "standard", "stages": [
            {"operation": "repeat_substitution", "cipher": "vigenere", "key_pattern": "B"}]}
        candidates = [{"plaintext": "ABC", "recipe": recipe, "source": "chat proposal"},
                      {"plaintext": "ABD", "recipe": recipe, "source": "chat proposal"}]
        result = verify_suggestions("BCD", candidates, cribs={"1": "B"})
        self.assertEqual(len(result["accepted"]), 1)
        self.assertEqual(len(result["rejected"]), 1)
        self.assertEqual(verify_suggestions("BCD", candidates, cribs={"1": "C"})["accepted"], [])

    def test_source_transducers_repeating_key_quotient(self):
        result = source_keys([{"id": "x", "text": "AB AB", "source": "synthetic"},
                              {"id": "y", "text": "A B", "source": "synthetic"}],
                             [{"operation": "letters"}])
        self.assertEqual([r["key"] for r in result["keys"]], ["AB"])
        self.assertEqual(len(result["keys"][0]["aliases"]), 2)

    def test_robust_declared_objective_and_duplicates(self):
        models = [{"id": "a", "source": "synthetic", "n": 1, "weights": {"A": 5, "B": 1}, "default": 0, "scale": 1},
                  {"id": "b", "source": "synthetic", "n": 1, "weights": {"A": 1, "B": 3}, "default": 0, "scale": 1}]
        bank = [{"id": "1", "text": "AA"}, {"id": "2", "text": "BB"}, {"id": "alias", "text": "AA"}, {"id": "3", "text": "AB"}]
        minimum = robust_rank(bank, models)
        total = robust_rank(bank, models, objective="sum")
        self.assertEqual(minimum["candidates"][0]["text"], "AB")
        self.assertEqual(total["candidates"][0]["text"], "AA")
        self.assertEqual(minimum["work"]["complete_candidate_evaluations"], 3)

    def test_joint_independent_crib_pullback_and_conflict(self):
        extraction = {"id": "k5", "indices": [2, 0], "output_cribs": {"0": "C"}, "independent_source": "synthetic independently supplied C"}
        result = compile_joint_cribs(3, [extraction], literal_cribs={"0": "A"})
        self.assertEqual(result["cribs"], {"0": "A", "2": "C"})
        self.assertTrue(result["feasible"])
        self.assertFalse(compile_joint_cribs(3, [extraction], literal_cribs={"2": "D"})["feasible"])
        with self.assertRaises(ValueError):
            compile_joint_cribs(3, [{**extraction, "output_cribs": {}}])

    def test_extraction_bank_witnesses(self):
        rules = [{"id": "a", "indices": [0, 2], "source": "every second character"},
                 {"id": "b", "indices": [2, 0], "source": "reversed selection"},
                 {"id": "c", "indices": [1, 3], "source": "offset second character"}]
        result = extraction_bank("ABAB", rules)
        self.assertEqual(result["work"]["distinct_output_evaluations"], 2)
        self.assertEqual(len(result["outputs"][0]["witnesses"]), 2)

    def test_dispatch_validation_and_no_paths(self):
        result = run({"method": "geometry", "parameters": {"cells": [[0, 0], [0, 1]]}})
        self.assertTrue(result["complete"])
        with self.assertRaises(ValueError):
            run({"method": "geometry", "parameters": {"cells": [[0, 0]], "file": "arbitrary"}})


if __name__ == "__main__":
    unittest.main()
