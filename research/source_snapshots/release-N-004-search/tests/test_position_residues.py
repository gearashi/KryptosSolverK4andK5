import unittest
from kryptos.position_residues import check_position_residues


class PositionResiduesTests(unittest.TestCase):
    def test_hand_vector_and_repeated_letter_conflict(self):
        # F(A)=3, F(B)=10; step=3: D+3,G; K+6,Q; D+9,M.
        known = dict(enumerate("ABA"))
        result = check_position_residues("GQM", known, modulus=26, step=3)
        self.assertTrue(result["feasible"])
        self.assertEqual(result["letter_residues"], {"A": 3, "B": 10})
        self.assertEqual(check_position_residues("GQN", known, modulus=26, step=3)["witness"]["kind"], "repeated_letter")

    def test_bijection_capacity_is_not_just_repeat_consistency(self):
        known = dict(enumerate("ABCDEFGHIJKLMN"))
        result = check_position_residues("A" * 14, known, step=0)
        self.assertEqual(result["witness"]["kind"], "bijection_capacity")

    def test_modular_fit_does_not_imply_full_fit(self):
        self.assertTrue(check_position_residues("ACE", dict(enumerate("AAA")), step=0)["feasible"])
        self.assertFalse(check_position_residues("ACE", dict(enumerate("AAA")), modulus=26, step=0)["feasible"])
        # Alternating parity remains possible with nonconstant odd increments.
        self.assertTrue(check_position_residues("BCH", dict(enumerate("AAA")), step=1)["feasible"])
        self.assertFalse(any(check_position_residues("BCH", dict(enumerate("AAA")), modulus=26, step=d)["feasible"] for d in range(26)))

    def test_partition_count(self):
        self.assertEqual(check_position_residues("A", {}, step=0)["residue_partition_completions"], 10400600)
        self.assertEqual(check_position_residues("A", {0: "A"}, modulus=26, step=0)["residue_partition_completions"], 15511210043330985984000000)

    def test_invalid_inputs(self):
        for args in ({"modulus": 3}, {"modulus": True}, {"step": False}):
            with self.assertRaises(ValueError):
                check_position_residues("ABC", {}, **args)
