"""Independent key-space and literal-equation checks for shared schedules."""
import itertools
import unittest

from kryptos.general_layers import solve_layers
from kryptos.scheduled_layers import solve_scheduled, make_phase_map, stage_position_map

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def reference(text, keys, stages, alphabet=A, decrypt=False):
    for stage in (reversed(stages) if decrypt else stages):
        if stage["operation"] == "gather":
            permutation = stage["permutation"]
            if decrypt:
                inverse = [0] * len(text)
                for j, i in enumerate(permutation):
                    inverse[i] = j
                permutation = inverse
            text = "".join(text[i] for i in permutation)
            continue
        alpha = stage.get("alphabet", alphabet)
        key = keys[stage["key_id"]]
        phase = stage.get("phase_map", [i % len(key) for i in range(len(text))])
        output = []
        for i, symbol in enumerate(text):
            k = alpha.index(key[(phase[i] + stage.get("offset", 0)) % len(key)])
            x = alpha.index(symbol)
            cipher = stage.get("cipher", "vigenere")
            value = k - x if cipher == "beaufort" else x + k if (cipher == "variant") == decrypt else x - k
            output.append(alpha[value % 26])
        text = "".join(output)
    return text


class ScheduledLayerTests(unittest.TestCase):
    def test_distinct_keys_specialize_to_pinned_general_solver(self):
        permutation = [2, 5, 0, 4, 1, 3]
        stages = [{"operation": "substitution", "key_id": "first", "key_length": 2, "cipher": "beaufort"},
                  {"operation": "gather", "permutation": permutation},
                  {"operation": "substitution", "key_id": "second", "key_length": 3, "cipher": "variant"}]
        plain = "SECRET"
        cipher = reference(plain, {"first": "BD", "second": "EFG"}, stages)
        known = {i: plain[i] for i in (0, 3, 5)}
        scheduled = solve_scheduled(cipher, known, stages)
        old_stages = [{"operation": "substitution", "period": 2, "cipher": "beaufort"}, stages[1],
                      {"operation": "substitution", "period": 3, "cipher": "variant"}]
        original = solve_layers(cipher, known, old_stages)
        self.assertEqual(scheduled.summary()["distinct_plaintext_count"], original.distinct_plaintext_count)
        self.assertEqual({p for a, b, p in scheduled.enumerate_plaintexts(676)},
                         {p for a, b, p in original.enumerate_plaintexts(676)})

    def test_shared_key_and_explicit_offset_match_all676_letter_keys(self):
        stages = [{"operation": "substitution", "key_id": "shared", "key_length": 2},
                  {"operation": "gather", "permutation": [2, 0, 4, 1, 3]},
                  {"operation": "substitution", "key_id": "shared", "key_length": 2,
                   "cipher": "beaufort", "phase_map": [1, 0, 1, 1, 0], "offset": -1},
                  {"operation": "substitution", "key_id": "shared", "key_length": 2, "cipher": "variant"}]
        plain = "STONE"
        ciphertext = reference(plain, {"shared": "FU"}, stages)
        known = {1: "T"}
        brute, keys = set(), 0
        for symbols in itertools.product(A, repeat=2):
            text = reference(ciphertext, {"shared": "".join(symbols)}, stages, decrypt=True)
            if text[1] == "T":
                brute.add(text)
                keys += 1
        solution = solve_scheduled(ciphertext, known, stages)
        candidates = [solution.candidate(a, b) for a, b, _ in solution.enumerate_plaintexts(676)]
        self.assertEqual({row["plaintext"] for row in candidates}, brute)
        self.assertEqual(solution.key_assignment_count, keys)
        self.assertIn(plain, brute)
        for row in candidates:
            self.assertEqual(reference(row["plaintext"], row["keys_by_id"], stages), ciphertext)
            self.assertTrue(all(len(s["key_pattern"]) == len(plain) for s in row["encryption_recipe"]["stages"] if s["operation"] == "repeat_substitution"))
        expected_domains = [set(text[i] for text in brute) for i in range(len(plain))]
        self.assertEqual(list(map(set, solution.plaintext_domains())), expected_domains)

    def test_transported_shared_schedule_cancels_exactly(self):
        permutation = [2, 0, 4, 1, 3]
        phases = [0, 1, 0, 1, 0]
        stages = [{"operation": "substitution", "key_id": "k", "key_length": 2, "phase_map": phases},
                  {"operation": "gather", "permutation": permutation},
                  {"operation": "substitution", "key_id": "k", "key_length": 2, "cipher": "variant",
                   "phase_map": [phases[i] for i in permutation]}]
        ciphertext = "".join("ABCDE"[i] for i in permutation)
        solution = solve_scheduled(ciphertext, {}, stages)
        self.assertEqual(solution.plaintext(), "ABCDE")
        self.assertEqual(solution.distinct_plaintext_count, 1)
        self.assertEqual(solution.key_assignment_count, 676)
        self.assertEqual(len(solution.dependency_report()["structurally_cancelled_key_slots"]), 2)
        self.assertEqual(solution.candidate()["reencrypted_ciphertext"], ciphertext)

    def test_marginal_domains_have2_13_or26_letters(self):
        stage = {"operation": "substitution", "key_id": "same", "key_length": 1}
        for repetitions, count in ((1, 26), (2, 13), (13, 2)):
            result = solve_scheduled("A", {}, [stage] * repetitions)
            self.assertEqual(result.distinct_plaintext_count, count)
            self.assertEqual(len(result.plaintext_domains()[0]), count)
            self.assertEqual(result.key_assignment_count, 26)
        self.assertEqual(solve_scheduled("A", {}, [stage] * 13).plaintext_domains(), ["AN"])

    def test_ragged_schedule_frames_and_composed_position_maps(self):
        cells = [(0, 2), (0, 5), (2, 1), (2, 4), (2, 5)]
        first = {"operation": "gather", "permutation": [2, 0, 4, 1, 3]}
        second = {"operation": "gather", "permutation": [1, 4, 0, 3, 2]}
        self.assertEqual(stage_position_map(5, [first, second]), (0, 3, 2, 1, 4))
        self.assertEqual(make_phase_map(cells, "row_reset", 3), [0, 1, 0, 1, 2])
        self.assertEqual(make_phase_map(cells, "column", 3), [1, 0, 0, 2, 0])
        self.assertEqual(make_phase_map(cells, "serpentine", 3), [0, 1, 1, 0, 2])
        self.assertEqual(make_phase_map(cells, "row_reset", 3, frame="source", stage_to_source=first["permutation"]), [0, 0, 2, 1, 1])

    def test_validation_of_shared_lengths_and_known_alphabets(self):
        first = {"operation": "substitution", "key_id": "x", "key_length": 1}
        with self.assertRaises(ValueError):
            solve_scheduled("ABC", {}, [first, {**first, "key_length": 2}])
        with self.assertRaises(ValueError):
            solve_scheduled("ABC", {}, [{**first, "alphabet": "kryptos"}], "standard")
        with self.assertRaises(ValueError):
            solve_scheduled("ABC", {}, [{**first, "phase_map": [0, True, 0]}])
        with self.assertRaises(ValueError):
            make_phase_map([(0, 0)], "column", 1, frame="source")


if __name__ == "__main__":
    unittest.main()
