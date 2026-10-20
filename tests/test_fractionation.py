import itertools
import unittest

from kryptos.fractionation import (
    STANDARD_ALPHABET, fractionate_decrypt, fractionate_encrypt,
    rank_digits, unrank_digits,
)


class FractionationTests(unittest.TestCase):
    def test_independent_rectangular_hand_vectors(self):
        # 2x13, AN: grouped coordinates 0,1,0,0 in radices 2,2,13,13
        # have rank 169; 169 = 6*26 + 13 => GN.
        self.assertEqual(fractionate_encrypt("AN", period=2), "GN")
        self.assertEqual(fractionate_decrypt("GN", period=2), "AN")
        # CA grouped digits 0,0,2,0 have rank 26 => base-26 BA.
        self.assertEqual(fractionate_encrypt("CA", period=2), "BA")
        self.assertEqual(fractionate_decrypt("BA", period=2), "CA")
        # 13x2, CA grouped digits 1,0,0,0 have rank 52 => CA.
        self.assertEqual(fractionate_encrypt("CA", rows=13, columns=2, period=2), "CA")

    def test_square_matches_coordinate_regrouping(self):
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Exactly 25 explicit symbols.
        text = "AFZCIPHER"
        coordinates = [divmod(alphabet.index(c), 5) for c in text]
        grouped = [r for r, _ in coordinates] + [c for _, c in coordinates]
        expected = "".join(alphabet[5*grouped[i]+grouped[i+1]] for i in range(0, len(grouped), 2))
        actual = fractionate_encrypt(text, alphabet=alphabet, rows=5, columns=5, period=len(text))
        self.assertEqual(actual, expected)
        self.assertEqual(fractionate_encrypt("AF", alphabet=alphabet, rows=5, columns=5, period=2), "BA")
        self.assertEqual(fractionate_decrypt(actual, alphabet=alphabet, rows=5, columns=5, period=len(text)), text)

    def test_all_two_letter_blocks_are_bijections(self):
        inputs = ["".join(pair) for pair in itertools.product(STANDARD_ALPHABET, repeat=2)]
        for rows, columns in ((2, 13), (13, 2)):
            outputs = set()
            for text in inputs:
                encrypted = fractionate_encrypt(text, rows=rows, columns=columns, period=2)
                outputs.add(encrypted)
                self.assertEqual(fractionate_decrypt(encrypted, rows=rows, columns=columns, period=2), text)
            self.assertEqual(len(outputs), 26**2)

    def test_identity_short_block_and_custom_alphabet(self):
        alphabet = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        text = alphabet + "KRYPTOS"
        self.assertEqual(fractionate_encrypt(text, alphabet=alphabet, period=1), text)
        for period in (2, 5, 7, 97):
            encrypted = fractionate_encrypt(text, alphabet=alphabet, period=period)
            self.assertEqual(len(encrypted), len(text))
            self.assertEqual(fractionate_decrypt(encrypted, alphabet=alphabet, period=period), text)
        self.assertEqual(fractionate_encrypt(""), "")
        self.assertEqual(fractionate_decrypt(""), "")

    def test_invalid_coordinates_are_rejected(self):
        # A naive rectangular regrouping can put digit 2 into a binary row.
        with self.assertRaises(ValueError):
            rank_digits([0, 0, 2, 0], [2, 13, 2, 13])
        with self.assertRaises(ValueError):
            unrank_digits(26, [2, 13])
        with self.assertRaises(ValueError):
            rank_digits([0], [2, 13])
        self.assertEqual(rank_digits([1, 12], [2, 13]), 25)
        self.assertEqual(unrank_digits(25, [2, 13]), [1, 12])

    def test_validation_and_no_implicit_ij_merging(self):
        for period in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                fractionate_encrypt("ABC", period=period)
        for text in ("a", "A B", "A?", None):
            with self.assertRaises(ValueError):
                fractionate_encrypt(text)
        with self.assertRaises(ValueError):
            fractionate_encrypt("ABC", alphabet="A"*26)
        with self.assertRaises(ValueError):
            fractionate_encrypt("J", alphabet="ABCDEFGHIKLMNOPQRSTUVWXYZ", rows=5, columns=5)
        with self.assertRaises(ValueError):
            fractionate_encrypt("A", rows=0)


if __name__ == "__main__":
    unittest.main()
