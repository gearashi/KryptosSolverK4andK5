import itertools
import unittest

from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.score_sensitivity import affine_marginals, report

A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Fixture:
    def __init__(self, affine):
        self.affine = affine

    def affine_plaintext(self):
        return self.affine


class ScoreSensitivityTests(unittest.TestCase):
    def test_exact_marginals_against_independent_cartesian_images(self):
        for domains, columns in (([2, 13], [[0, 13, 0, 13], [0, 0, 2, 4]]),
                                 ([3, 2], [[0, 1, 3, 0], [0, 0, 2, 0]]),
                                 ([1], [[9, 8, 7, 6]])):
            base = [0, 1, 2, 3]
            affine = {"alphabet": A, "base": base, "columns": columns, "domains": domains}
            points = list(itertools.product(*(range(d) for d in domains)))
            expected = [set(A[(b + sum(c[i] * x for c, x in zip(columns, p))) % 26] for p in points) for i, b in enumerate(base)]
            self.assertEqual([set(d) for d in affine_marginals(affine)], expected)

    def test_indirect_fixed_letters_can_remove_all_scoring_windows(self):
        affine = {"alphabet": A, "base": list(range(9)),
                  "columns": [[0, 1, 1, 0, 1, 1, 0, 1, 1]], "domains": [26]}
        text = "ABCDEFGHI"
        model = train_ngram_model([CorpusDocument(text * 2, "authored-control")], label="tiny", order=3, normalization="identity")
        original = model.score(text, [0]).to_dict()
        value = report(Fixture(affine), model, text, {0: "A"})
        self.assertEqual(value["additional_fixed_positions_zero_based"], [3, 6])
        self.assertEqual(value["supplied_mask_score"], original)
        self.assertEqual(value["model_fixed_mask_score"]["windows"], 0)
        self.assertIsNone(value["model_fixed_mask_score"]["mean_log_probability"])
        self.assertFalse(value["model_fixed_mask_score"]["available"])
        self.assertFalse(value["changes_candidate_ranking"])

    def test_reference_score_with_expanded_mask_and_no_mutation(self):
        affine = {"alphabet": A, "base": list(range(9)),
                  "columns": [[0, 0, 1, 1, 1, 1, 1, 1, 0]], "domains": [26]}
        text = "ABCDEFGHI"
        model = train_ngram_model([CorpusDocument(text * 2, "authored-control")], label="tiny", order=2, normalization="identity")
        known = {0: "A"}
        value = report(Fixture(affine), model, text, known)
        self.assertEqual(value["model_fixed_mask_score"], model.score(text, [0, 1, 8]).to_dict())
        self.assertEqual(value["model_fixed_mask_score"]["windows"], 5)
        self.assertEqual(known, {0: "A"})

    def test_invalid_or_unconditioned_input_rejected(self):
        model = train_ngram_model([CorpusDocument("ABCABC", "authored")], label="tiny", order=2, normalization="identity")
        affine = {"alphabet": A, "base": [0, 1, 2], "columns": [[1, 1, 1]], "domains": [26]}
        with self.assertRaises(ValueError):
            report(Fixture(affine), model, "ABC", {0: "A"})
        with self.assertRaises(ValueError):
            affine_marginals({**affine, "domains": [True]})


if __name__ == "__main__":
    unittest.main()
