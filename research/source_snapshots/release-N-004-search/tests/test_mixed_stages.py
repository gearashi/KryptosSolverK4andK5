"""Compare true known-alphabet cyclic equations with complete small key banks."""
import itertools
import unittest

from kryptos.mixed_stages import solve_mixed_stages
from kryptos.scheduled_layers import solve_scheduled

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
K = "KRYPTOSABCDEFGHIJLMNQUVWXZ"


def reference(text, keys, stages, decrypt=False):
    """Independent literal equations; no test-directory import is required."""
    for stage in (reversed(stages) if decrypt else stages):
        if stage["operation"] == "gather":
            permutation = stage["permutation"]
            if decrypt:
                inverse = [0] * len(text)
                for j, i in enumerate(permutation):
                    inverse[i] = j
                permutation = inverse
            text = "".join(text[i] for i in permutation)
        else:
            alpha, key = stage["alphabet"], keys[stage["key_id"]]
            phases = stage.get("phase_map", [i % len(key) for i in range(len(text))])
            output = []
            for i, symbol in enumerate(text):
                x = alpha.index(symbol)
                k = alpha.index(key[(phases[i] + stage.get("offset", 0)) % len(key)])
                cipher = stage.get("cipher", "vigenere")
                value = k - x if cipher == "beaufort" else x + k if (cipher == "variant") == decrypt else x - k
                output.append(alpha[value % 26])
            text = "".join(output)
    return text


class MixedStageTests(unittest.TestCase):
    def test_shared_key_is_a_letter_not_a_reused_numeric_index(self):
        stages = [{"operation": "substitution", "key_id": "same", "key_length": 1, "alphabet": A},
                  {"operation": "substitution", "key_id": "same", "key_length": 1, "alphabet": B}]
        self.assertEqual(reference("ABCD", {"same": "A"}, stages), "CADE")
        expected = {key for key in A if reference("ABCD", {"same": key}, stages) == "CADE"}
        result = solve_mixed_stages("CADE", dict(enumerate("ABCD")), stages)
        self.assertTrue(result["complete"])
        self.assertEqual(result["key_assignment_count"], len(expected))
        self.assertEqual(set(result["key_letter_domains"]["same"][0]), expected)
        self.assertEqual(result["distinct_plaintext_count"], 1)
        self.assertEqual(result["candidates"][0]["plaintext"], "ABCD")

    def test_three_substitutions_two_gathers_exhaustive26_squared(self):
        stages = [{"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": A},
                  {"operation": "gather", "permutation": [2, 5, 0, 4, 1, 3]},
                  {"operation": "substitution", "key_id": "b", "key_length": 1, "alphabet": B, "cipher": "beaufort"},
                  {"operation": "gather", "permutation": [1, 4, 5, 0, 2, 3]},
                  {"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": K, "cipher": "variant"}]
        plain = "SECRET"
        ciphertext = reference(plain, {"a": "G", "b": "D"}, stages)
        known = {0: "S", 4: "E"}
        expected, assignments, key_domains = set(), 0, [set(), set()]
        for a, b in itertools.product(A, repeat=2):
            text = reference(ciphertext, {"a": a, "b": b}, stages, decrypt=True)
            if all(text[i] == c for i, c in known.items()):
                expected.add(text)
                assignments += 1
                key_domains[0].add(a)
                key_domains[1].add(b)
        result = solve_mixed_stages(ciphertext, known, stages, max_candidates=1000)
        self.assertTrue(result["complete"])
        self.assertEqual(result["key_assignment_count"], assignments)
        self.assertEqual(result["distinct_plaintext_count"], len(expected))
        self.assertEqual({r["plaintext"] for r in result["candidates"]}, expected)
        self.assertEqual([set(result["key_letter_domains"][key][0]) for key in ("a", "b")], key_domains)
        self.assertEqual(list(map(set, result["plaintext_domains"])), [set(p[i] for p in expected) for i in range(len(plain))])
        for row in result["candidates"]:
            self.assertEqual(reference(row["plaintext"], row["keys_by_id"], stages), ciphertext)

    def test_equal_alphabet_dispatch_and_direct_csp_agree(self):
        stages = [{"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": K},
                  {"operation": "gather", "permutation": [1, 2, 0]},
                  {"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": K}]
        scheduled = solve_scheduled("ABC", {}, stages, K)
        for dispatch in (True, False):
            result = solve_mixed_stages("ABC", {}, stages, dispatch_equal_alphabets=dispatch, max_candidates=100)
            self.assertTrue(result["complete"])
            self.assertEqual(result["key_assignment_count"], scheduled.key_assignment_count)
            self.assertEqual(result["distinct_plaintext_count"], scheduled.distinct_plaintext_count)
            self.assertEqual(list(map(set, result["plaintext_domains"])), list(map(set, scheduled.plaintext_domains())))

    def test_truncation_never_exposes_global_marginals(self):
        stages = [{"operation": "substitution", "key_id": "k", "key_length": 1, "alphabet": A},
                  {"operation": "substitution", "key_id": "k", "key_length": 1, "alphabet": B}]
        exhaustive = solve_mixed_stages("ABC", {}, stages, max_candidates=100)
        self.assertTrue(exhaustive["complete"])
        for options in ({"max_nodes": 0}, {"max_nodes": 2}, {"max_relation_checks": 1}, {"max_distinct_plaintexts": 1}):
            result = solve_mixed_stages("ABC", {}, stages, **options)
            self.assertFalse(result["complete"])
            self.assertLessEqual(result["key_assignment_lower_bound"], exhaustive["key_assignment_count"])
            self.assertLessEqual(result["distinct_plaintext_lower_bound"], exhaustive["distinct_plaintext_count"])
            self.assertIsNone(result["key_assignment_count"])
            self.assertIsNone(result["plaintext_domains"])
            self.assertIsNone(result["key_letter_domains"])
            self.assertIsNone(result["prediction_mask"])

    def test_unused_shared_key_slots_are_counted_without_branching(self):
        stages = [{"operation": "substitution", "key_id": "k", "key_length": 3, "phase_map": [0], "alphabet": A},
                  {"operation": "substitution", "key_id": "k", "key_length": 3, "phase_map": [0], "alphabet": B}]
        result = solve_mixed_stages("C", {0: "A"}, stages)
        expected = sum(reference("A", {"k": c + "AA"}, stages) == "C" for c in A)
        self.assertTrue(result["complete"])
        self.assertEqual(result["key_assignment_count"], expected * 26 ** 2)
        self.assertEqual(result["key_letter_domains"]["k"][1:], [A, A])

    def test_no_unknown_or_implicit_alphabet(self):
        with self.assertRaises(ValueError):
            solve_mixed_stages("A", {}, [{"operation": "substitution", "key_id": "a", "key_length": 1}])
        with self.assertRaises(ValueError):
            solve_mixed_stages("A", {}, [{"operation": "substitution", "key_id": "a", "key_length": 1, "alphabet": "unknown"}])


if __name__ == "__main__":
    unittest.main()
