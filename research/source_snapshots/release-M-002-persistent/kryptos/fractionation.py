"""Explicit, reversible coordinate fractionation hypotheses.

For each block, group all row digits followed by all column digits. Interpret
that grouped string with its actual mixed radices, then convert its integer
rank to interleaved row/column digits. For a square, all digit radices coincide
and this is ordinary coordinate regrouping. The rectangular mixed-radix
extension is a modeling choice, not an asserted historical Kryptos technique.
"""

from __future__ import annotations

from math import prod

STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")


def rank_digits(digits: list[int], radices: list[int]) -> int:
    """Rank a digit vector; invalid digits are rejected, never folded modulo."""
    if len(digits) != len(radices):
        raise ValueError("one radix is required for every digit")
    result = 0
    for digit, radix in zip(digits, radices):
        _positive_int(radix, "radix")
        if isinstance(digit, bool) or not isinstance(digit, int) or not 0 <= digit < radix:
            raise ValueError("digit lies outside its declared radix")
        result = result * radix + digit
    return result


def unrank_digits(value: int, radices: list[int]) -> list[int]:
    """Unrank within the exact product domain; quotient/remainders are exact."""
    for radix in radices:
        _positive_int(radix, "radix")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < prod(radices):
        raise ValueError("rank lies outside the declared product domain")
    result = [0] * len(radices)
    for i in range(len(radices)-1, -1, -1):
        value, result[i] = divmod(value, radices[i])
    assert value == 0
    return result


def _transform(text: str, alphabet: str, rows: int, columns: int,
               period: int, decoding: bool) -> str:
    for value, label in ((rows, "rows"), (columns, "columns"), (period, "period")):
        _positive_int(value, label)
    if not isinstance(alphabet, str) or len(alphabet) != rows * columns or len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must have exactly rows*columns distinct symbols")
    if not isinstance(text, str) or any(symbol not in alphabet for symbol in text):
        raise ValueError("text must consist only of declared alphabet symbols; no normalization is applied")
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    output = []
    for start in range(0, len(text), period):
        block = text[start:start+period]
        n = len(block)
        coordinates = [divmod(index[symbol], columns) for symbol in block]
        grouped_radices = [rows] * n + [columns] * n
        interleaved_radices = [rows, columns] * n
        if decoding:
            interleaved = [digit for pair in coordinates for digit in pair]
            grouped = unrank_digits(rank_digits(interleaved, interleaved_radices), grouped_radices)
            pairs = zip(grouped[:n], grouped[n:])
        else:
            grouped = [r for r, _ in coordinates] + [c for _, c in coordinates]
            interleaved = unrank_digits(rank_digits(grouped, grouped_radices), interleaved_radices)
            pairs = zip(interleaved[::2], interleaved[1::2])
        for row, column in pairs:
            # These checks make the radix convention explicit at the boundary.
            if not 0 <= row < rows or not 0 <= column < columns:
                raise ValueError("invalid reconstructed coordinate")
            output.append(alphabet[row * columns + column])
    return "".join(output)


def fractionate_encrypt(plaintext: str, *, alphabet: str = STANDARD_ALPHABET,
                       rows: int = 2, columns: int = 13, period: int = 5) -> str:
    """Encrypt blocks; the final short block is processed at its actual length."""
    return _transform(plaintext, alphabet, rows, columns, period, False)


def fractionate_decrypt(ciphertext: str, *, alphabet: str = STANDARD_ALPHABET,
                       rows: int = 2, columns: int = 13, period: int = 5) -> str:
    """Exact inverse of fractionate_encrypt under the same parameters."""
    return _transform(ciphertext, alphabet, rows, columns, period, True)
