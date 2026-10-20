import unittest

from kryptos.grid import check_grid_model, coordinate_routes, encrypt_grid, k4_cells


class GridTests(unittest.TestCase):
    cells = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]
    permutation = [0, 2, 3, 1, 5, 4]
    rows, columns = {0: 1, 1: 4}, {0: 2, 1: 7, 2: 11}

    def test_hand_vectors_all_four_phase_frames(self):
        vectors = {("source", "source"): "DOJJUP", ("source", "destination"): "DKSEQT",
                   ("destination", "source"): "DOGMUP", ("destination", "destination"): "DKPHQT"}
        for (row_frame, column_frame), ciphertext in vectors.items():
            with self.subTest(row=row_frame, column=column_frame):
                options = {"alphabet": "standard", "row_frame": row_frame, "column_frame": column_frame}
                self.assertEqual(encrypt_grid("ABCDEF", self.rows, self.columns, self.cells, self.permutation, **options), ciphertext)
                result = check_grid_model(ciphertext, dict(enumerate("ABCDEF")), self.cells, self.permutation, **options)
                self.assertTrue(result["feasible"])
                self.assertEqual(result["representative_plaintext"], "ABCDEF")
                self.assertEqual(result["reencrypted_ciphertext"], ciphertext)
                self.assertEqual(result["plaintext_dimension"], 0)

    def test_noninvolutive_route_and_cycle_rejection(self):
        known = dict(enumerate("ABCDEF"))
        wrong_inverse = [0, 3, 1, 2, 5, 4]
        rejected = check_grid_model("DOJJUP", known, self.cells, wrong_inverse, alphabet="standard")
        self.assertFalse(rejected["feasible"])
        rejected = check_grid_model("EOJJUP", known, self.cells, self.permutation, alphabet="standard")
        self.assertFalse(rejected["feasible"])
        coefficients = {}
        residue = 0
        for edge in rejected["witness"]["cycle_edges"]:
            value = edge["coefficient"]
            coefficients[edge["row_vertex"]] = coefficients.get(edge["row_vertex"], 0) + value
            coefficients[edge["column_vertex"]] = coefficients.get(edge["column_vertex"], 0) - value
            residue += value * edge["residue"]
        self.assertTrue(all(value == 0 for value in coefficients.values()))
        self.assertNotEqual(residue % 26, 0)
        self.assertEqual(residue % 26, rejected["witness"]["residual_mod_26"])

    def test_forced_unknown_position_and_correlated_uncertainty(self):
        result = check_grid_model("DOJJUP", {0: "A", 1: "B", 3: "D"}, self.cells, self.permutation, alphabet="standard")
        self.assertTrue(result["feasible"])
        self.assertEqual(result["plaintext_mask"], "AB?DE?")
        self.assertEqual(result["forced_unknown_positions"], [5])
        self.assertEqual(result["crib_components"], 2)
        self.assertEqual(result["full_components"], 1)
        self.assertEqual(result["key_assignment_count"], 26 ** 2)
        self.assertEqual(result["distinct_plaintext_count"], 26)

    def test_exact_plaintext_count_against_independent_enumeration(self):
        cells = [(0, 0), (0, 1), (1, 0), (1, 1)]
        result = check_grid_model("DJIO", {0: "A"}, cells, [0, 1, 2, 3], alphabet="standard")
        # Fix row0=0 by gauge; crib A forces column0=3. Enumerate remaining
        # row1 and column1 independently using hand-derived modular formulas.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        completions = {"A" + alphabet[(9 - b) % 26] + alphabet[(5 - a) % 26] + alphabet[(14 - a - b) % 26]
                       for a in range(26) for b in range(26)}
        self.assertEqual(len(completions), result["distinct_plaintext_count"])
        self.assertEqual(result["key_assignment_count"], 26 ** 3)
        self.assertEqual(result["plaintext_dimension"], 2)
        self.assertEqual(result["plaintext_mask"], "A???")
        self.assertIn(result["representative_plaintext"], completions)
        self.assertTrue(all(len({text[i] for text in completions}) == 26 for i in (1, 2, 3)))

    def test_empty_cribs_and_coordinate_origin_translation(self):
        empty = check_grid_model("DOJJUP", {}, self.cells, self.permutation, alphabet="standard")
        self.assertEqual(empty["key_assignment_dimension"], 5)
        self.assertEqual(empty["plaintext_dimension"], 4)
        self.assertEqual(empty["plaintext_mask"], "??????")
        translated = [(r + 100, c - 200) for r, c in self.cells]
        other = check_grid_model("DOJJUP", {}, translated, self.permutation, alphabet="standard")
        for field in ("plaintext_dimension", "plaintext_mask", "representative_plaintext", "distinct_plaintext_count"):
            self.assertEqual(empty[field], other[field])

    def test_hand_shifted_lookup_vectors(self):
        for frame, ciphertext in (("source", "IIONIT"), ("destination", "IOJMUH")):
            options = {"alphabet": "standard", "row_frame": frame, "column_frame": frame,
                       "row_shift": 1, "column_shift": 1}
            self.assertEqual(encrypt_grid("ABCDEF", self.rows, self.columns, self.cells, self.permutation, **options), ciphertext)
            result = check_grid_model(ciphertext, dict(enumerate("ABCDEF")), self.cells, self.permutation, **options)
            self.assertTrue(result["feasible"])
            self.assertEqual(result["representative_plaintext"], "ABCDEF")

    def test_independent_ragged_vectors_with_different_row_column_offsets(self):
        cells, permutation = [(0, 1), (1, 0), (1, 1)], [2, 0, 1]
        rows, columns = {0: 2, 1: 7}, {0: 11, 1: 5}
        vectors = {("source", "source"): "TPA", ("source", "destination"): "NPG",
                   ("destination", "source"): "YPV", ("destination", "destination"): "SPB"}
        for (row_frame, column_frame), ciphertext in vectors.items():
            with self.subTest(row=row_frame, column=column_frame):
                options = {"alphabet": "standard", "row_frame": row_frame, "column_frame": column_frame,
                           "row_shift": 1, "column_shift": -1}
                self.assertEqual(encrypt_grid("DOG", rows, columns, cells, permutation, **options), ciphertext)
                result = check_grid_model(ciphertext, dict(enumerate("DOG")), cells, permutation, **options)
                self.assertTrue(result["feasible"])
                self.assertEqual(result["representative_plaintext"], "DOG")

    def test_geometric_and_diagonal_routes_are_occupied_cell_bijections(self):
        rows = coordinate_routes(self.cells)
        rotation = next(row for row in rows if "geometry/rotate90/forward" in row["aliases"])
        self.assertEqual(rotation["permutation"], [3, 0, 4, 1, 5, 2])
        ragged = [(0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]
        rows = coordinate_routes(ragged)
        antidiagonal = next(row for row in rows if "antidiagonals/major0/minor0/snake0/forward" in row["aliases"])
        self.assertEqual(antidiagonal["permutation"], [0, 2, 1, 4, 3])
        self.assertTrue(all(sorted(row["permutation"]) == list(range(5)) for row in rows))
        self.assertEqual(len(rows), len({tuple(row["permutation"]) for row in rows}))

    def test_k4_geometry_and_validation(self):
        cells = k4_cells()
        self.assertEqual(len(cells), 97)
        self.assertEqual(cells[:4], [(0, 27), (0, 28), (0, 29), (0, 30)])
        self.assertEqual(cells[4], (1, 0))
        self.assertEqual(cells[-1], (3, 30))
        for cells_bad in ([], [(0, 0), (0, 0)], [(True, 0)], [(0, 0, 1)]):
            with self.subTest(cells=cells_bad), self.assertRaises(ValueError):
                coordinate_routes(cells_bad)
        with self.assertRaises(ValueError):
            check_grid_model("ABCDEF", {6: "A"}, self.cells, self.permutation)
        with self.assertRaises(ValueError):
            check_grid_model("ABCDEF", {}, self.cells, [0] * 6)


if __name__ == "__main__":
    unittest.main()
