import unittest

from kryptos.data import K4_CIPHERTEXT
from kryptos.sculpture import (TRANSFORMS, apply_gather, cells, fixed_overlay, fixed_routes,
                              load_layout, section_cells, section_text, transform_coordinate,
                              transformed_shape)
from research.geometry_benchmarks import known_answers


class SculptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = load_layout()

    def test_primary_rows_and_known_pairs(self):
        self.assertEqual([row["letters"] for row in known_answers(self.layout)], [63, 369, 336, 97])
        self.assertEqual(len(section_text("ALL", self.layout)), 865)
        self.assertEqual(section_text("K4", self.layout), K4_CIPHERTEXT)

    def test_punctuation_and_extra_l_are_not_normalized_away(self):
        punctuation = [(c.row, c.column) for c in cells("cipher", self.layout) if c.symbol == "?"]
        self.assertEqual(punctuation, [(3, 6), (7, 8), (9, 7), (24, 26)])
        tableau = {(c.row, c.column): c.symbol for c in cells("tableau", self.layout)}
        self.assertEqual(tableau[14, 31], "L")
        self.assertEqual(tableau[0, 0], " ")
        self.assertEqual(tableau[27, 0], " ")

    def test_k4_physical_claim_is_only_transcription_ordinal(self):
        source = section_cells("K4", self.layout)
        self.assertEqual((source[0].row, source[0].column, source[0].symbol), (24, 27, "O"))
        self.assertEqual((source[-1].row, source[-1].column, source[-1].symbol), (27, 30, "R"))
        self.assertTrue(all(value is None for value in self.layout["physical_measurements"].values()))

    def test_non_square_rotation_independent_hand_vector(self):
        # ABC / DEF rotates clockwise to DA / EB / FC.
        mapped = [(transform_coordinate(i // 3, i % 3, 2, 3, "rotate90"), ch)
                  for i, ch in enumerate("ABCDEF")]
        self.assertEqual("".join(ch for _, ch in sorted(mapped)), "DAEBFC")
        self.assertEqual(transformed_shape(2, 3, "rotate90"), (3, 2))
        self.assertEqual(apply_gather("ABCDE", (2, 0, 4, 1, 3)), "CAEBD")
        self.assertEqual(apply_gather("CAEBD", (2, 0, 4, 1, 3), inverse=True), "ABCDE")

    def test_all_fixed_routes_preserve_symbols_and_inverse(self):
        for section in ("K1", "K2", "K3", "K4", "ALL"):
            text = section_text(section, self.layout)
            routes = fixed_routes(section, self.layout)
            self.assertEqual(len(routes), len({tuple(r["permutation"]) for r in routes}))
            self.assertEqual(sum(len(r["aliases"]) for r in routes), 16)
            for route in routes:
                result = apply_gather(text, route["permutation"])
                self.assertEqual(apply_gather(result, route["permutation"], inverse=True), text)

    def test_overlay_missing_positions_are_explicit(self):
        for transform in TRANSFORMS:
            overlay = fixed_overlay("K4", transform, self.layout)
            self.assertEqual(len(overlay["mapping"]), 97)
            self.assertEqual(overlay["matched_letters"] + len(overlay["missing_or_blank"]), 97)
            self.assertEqual(overlay["missing_or_blank"],
                             [r["input_index"] for r in overlay["mapping"] if not r["occupied_tableau_letter"]])
        # A clockwise rotation sends the last cipher column index30 to row30,
        # outside the tableau's 28 ordinal rows; it must not wrap modulo28.
        overlay = fixed_overlay("K4", "rotate90", self.layout)
        self.assertIsNone(overlay["mapping"][-1]["tableau_symbol"])

    def test_invalid_coordinates_and_permutations(self):
        for coordinate in ((True, 0, 2, 3), (2, 0, 2, 3), (0, 0, 0, 3)):
            with self.assertRaises(ValueError):
                transform_coordinate(*coordinate, "identity")
        with self.assertRaises(ValueError):
            apply_gather("ABC", [0, 0, 2])
        with self.assertRaises(ValueError):
            fixed_routes("K5", self.layout)


if __name__ == "__main__":
    unittest.main()
