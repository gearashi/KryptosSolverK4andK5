"""Small independently encrypted controls; no K4 scan or language assumptions."""
import itertools
import unittest

from kryptos.general_layers import solve_layers, literal_encrypt, LayerBudgetExceeded
from kryptos.layer_plan import compile_layer_plan


A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
R1 = [0, 2, 1, 3, 4, 6, 5, 7]
R2 = [0, 4, 2, 6, 1, 5, 3, 7]


def sub(period, cipher="vigenere"):
    return {"operation": "substitution", "period": period, "cipher": cipher}


def route(permutation):
    return {"operation": "gather", "permutation": permutation}


def independent_encrypt(text, keys, stages, alphabet=A):
    keys = iter(keys)
    for stage in stages:
        if stage["operation"] == "gather":
            text = "".join(text[i] for i in stage["permutation"])
            continue
        key = next(keys)
        values = []
        for i, char in enumerate(text):
            p, k = alphabet.index(char), alphabet.index(key[i % len(key)])
            c = stage.get("cipher", "vigenere")
            values.append(alphabet[(p + k if c == "vigenere" else k - p if c == "beaufort" else p - k) % 26])
        text = "".join(values)
    return text


class GeneralLayerTests(unittest.TestCase):
    def check_candidates(self, solution, cap=676):
        found = set()
        for a, b, text in solution.enumerate_plaintexts(cap):
            self.assertNotIn(text, found)
            found.add(text)
            candidate = solution.candidate(a, b)
            self.assertEqual(candidate["plaintext"], text)
            self.assertEqual(independent_encrypt(text, candidate["keys"], [s.to_dict() for s in solution.stages], solution.alphabet), solution.ciphertext)
        self.assertEqual(len(found), solution.distinct_plaintext_count)
        return found

    def test_existing_two_layer_families_are_exactly_equal(self):
        p, perm = "SECRET", [2, 5, 0, 4, 1, 3]
        for alphabet in (A, "KRYPTOSABCDEFGHIJLMNQUVWXZ"):
            for order in ("SST", "STS", "TSS"):
                periods = iter((2, 3))
                stages = [route(perm) if s == "T" else sub(next(periods)) for s in order]
                c = independent_encrypt(p, ("BJ", "FXQ"), stages, alphabet)
                known = {i: p[i] for i in (0, 3, 5)}
                old = compile_layer_plan(6, known, order, perm, 2, 3).solve(c, known, alphabet)["solution"]
                result = solve_layers(c, known, stages, alphabet)
                self.assertTrue(result.feasible)
                self.assertEqual(result.distinct_plaintext_count, old.distinct_plaintext_count)
                self.assertEqual(result.prediction_mask(), old.prediction_mask())
                self.assertEqual(self.check_candidates(result), {text for _, text in old.enumerate_plaintexts(676)})

    def test_three_substitutions_two_routes_and_all_equations(self):
        alphabet = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
        stages = [sub(2, "beaufort"), route([4, 2, 0, 6, 1, 3, 5]), sub(3, "variant"),
                  route([1, 4, 6, 0, 5, 2, 3]), sub(2)]
        p = "SPHINXZ"
        c = independent_encrypt(p, ("UV", "CDF", "KE"), stages, alphabet)
        result = solve_layers(c, dict(enumerate(p)), stages, alphabet)
        self.assertTrue(result.feasible)
        self.assertEqual(self.check_candidates(result), {p})
        self.assertEqual(literal_encrypt(p, result.keys(), stages, alphabet), c)

    def test_ranks_differ_modulo_two_and_thirteen(self):
        stages = [sub(2), route(R1), sub(2), route(R2), sub(2)]
        p = "ABCDEFGH"
        c = independent_encrypt(p, ("BC", "DE", "FG"), stages)
        known = {i: p[i] for i in (0, 3, 5, 6)}
        result = solve_layers(c, known, stages)
        self.assertEqual((result.field2.rank, result.field13.rank), (3, 4))
        self.assertEqual((result.dimensions_mod2, result.dimensions_mod13), (1, 0))
        self.assertEqual(result.distinct_plaintext_count, 2)
        self.assertEqual(result.key_assignment_count, 1352)
        texts = self.check_candidates(result)
        self.assertIn(p, texts)
        other = next(text for text in texts if text != p)
        self.assertEqual(other, "AOPDRFGU")
        affine = result.affine_plaintext()
        self.assertEqual(affine["domains"], (2,))
        for a, b, text in result.enumerate_plaintexts(2):
            self.assertEqual(text, "".join(A[(base + sum(col[i] * value for col, value in zip(affine["columns"], a + b))) % 26]
                                          for i, base in enumerate(affine["base"])))
        with self.assertRaises(LayerBudgetExceeded):
            result.enumerate_plaintexts(1)

    def test_independent_bruteforce_constant_key_three_layer_family(self):
        stages = [sub(1, "beaufort"), route([2, 0, 3, 1]), sub(1, "variant"),
                  route([1, 3, 0, 2]), sub(1)]
        c = independent_encrypt("WXYZ", ("K", "Q", "D"), stages)
        solution = solve_layers(c, {}, stages)
        # Forward-encrypt all constant-letter plaintexts shifted from the true
        # plaintext and all keys. This key-space check does not use solver bases.
        observed = set()
        for a, b, d in itertools.product(range(26), repeat=3):
            # Reverse the literal stages, directly, for each of all 26^3 keys.
            text = "".join(A[(A.index(x) - d) % 26] for x in c)
            inv2 = [2, 0, 3, 1]
            text = "".join(text[i] for i in inv2)
            text = "".join(A[(A.index(x) + b) % 26] for x in text)
            inv1 = [1, 3, 0, 2]
            text = "".join(text[i] for i in inv1)
            text = "".join(A[(a - A.index(x)) % 26] for x in text)
            observed.add(text)
        self.assertEqual(solution.key_assignment_count, 26 ** 3)
        self.assertEqual(self.check_candidates(solution), observed)

    def test_conflict_certificates_cancel_coefficients(self):
        for ciphertext, expected_moduli in (("AB", {2, 13}), ("AC", {13})):
            result = solve_layers(ciphertext, {0: "A", 1: "A"}, [sub(1)])
            self.assertFalse(result.feasible)
            summary = result.summary()
            self.assertEqual({c["modulus"] for c in summary["conflicts"]}, expected_moduli)
            for certificate in summary["conflicts"]:
                prime = certificate["modulus"]
                weights = {row["constraint_index"]: row["weight"] for row in certificate["constraint_weights"]}
                for col in range(result.key_slots):
                    self.assertEqual(sum(weights.get(i, 0) * row["key_coefficients_mod26"][col] for i, row in enumerate(summary["constraints"])) % prime, 0)
                residue = sum(weights.get(i, 0) * row["rhs_mod26"] for i, row in enumerate(summary["constraints"])) % prime
                self.assertEqual(residue, certificate["resultant_residue"])
                self.assertNotEqual(residue, 0)
            with self.assertRaises(ValueError):
                result.plaintext()

    def test_routes_only_and_unused_key_slots(self):
        stages = [route([2, 0, 1])]
        result = solve_layers("CAB", {}, stages)
        self.assertEqual(result.candidate()["plaintext"], "ABC")
        self.assertEqual(result.key_assignment_count, 1)
        self.assertFalse(solve_layers("CAB", {0: "X"}, stages).feasible)
        result = solve_layers("BC", {0: "A", 1: "B"}, [sub(5)])
        self.assertEqual(result.distinct_plaintext_count, 1)
        self.assertEqual(result.key_assignment_count, 26 ** 3)
        self.assertEqual(result.prediction_mask(), "AB")

    def test_validation_and_budget_failures_are_not_infeasibility(self):
        with self.assertRaises(ValueError):
            solve_layers("A", {}, [{"operation": "substitution", "period": 1, "alphabet": "unknown"}])
        with self.assertRaises(ValueError):
            solve_layers("A", {}, [sub(1)] * 17)
        with self.assertRaises(ValueError):
            solve_layers("A", {True: "A"}, [sub(1)])
        for kwargs in ({"max_key_slots": 0}, {"max_matrix_cells": 1}, {"max_operations": 1}):
            with self.assertRaises(LayerBudgetExceeded):
                solve_layers("AB", {0: "A"}, [sub(2)], **kwargs)
        result = solve_layers("AB", {}, [sub(1)])
        for args in (([2], [0]), ([0], [13]), ([True], [0]), ([], [])):
            with self.assertRaises(ValueError):
                result.plaintext(*args)


if __name__ == "__main__":
    unittest.main()
