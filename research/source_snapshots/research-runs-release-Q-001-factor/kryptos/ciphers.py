"""Explicit classical-cipher conventions used by the hypothesis search.

Every symbol (plaintext, ciphertext, and key) is indexed in the selected
alphabet.  Vigenere: C=P+K; Beaufort: C=K-P; variant Beaufort: C=P-K.
All arithmetic is modulo 26. Crib starts are one-based plaintext positions.
"""

from __future__ import annotations

import string

STANDARD_ALPHABET = string.ascii_uppercase
KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ALPHABETS = {"standard": STANDARD_ALPHABET, "kryptos": KRYPTOS_ALPHABET}
CIPHERS = ("vigenere", "beaufort", "variant")


def normalize_letters(value: str, label: str = "text") -> str:
    """Remove whitespace and uppercase ASCII letters; reject other symbols."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    result = "".join(value.split()).upper()
    if not result or any(character not in STANDARD_ALPHABET for character in result):
        raise ValueError(f"{label} must contain A-Z letters and optional whitespace only")
    return result


def get_alphabet(name: str = "standard") -> str:
    try:
        return ALPHABETS[name]
    except (KeyError, TypeError) as exc:
        raise ValueError("alphabet must be standard or kryptos") from exc


def _transform(text: str, key: str, cipher: str, alphabet: str, decoding: bool) -> str:
    letters = get_alphabet(alphabet)
    if cipher not in CIPHERS:
        raise ValueError("cipher must be vigenere, beaufort, or variant")
    text = normalize_letters(text)
    key = normalize_letters(key, "key")
    index = {character: position for position, character in enumerate(letters)}
    key_values = [index[character] for character in key]
    result = []
    for position, character in enumerate(text):
        value, shift = index[character], key_values[position % len(key_values)]
        if cipher == "beaufort":
            transformed = shift - value
        elif cipher == "variant":
            transformed = value + shift if decoding else value - shift
        else:
            transformed = value - shift if decoding else value + shift
        result.append(letters[transformed % 26])
    return "".join(result)


def encrypt(plaintext: str, key: str, cipher: str = "vigenere", alphabet: str = "standard") -> str:
    return _transform(plaintext, key, cipher, alphabet, False)


def decrypt(ciphertext: str, key: str, cipher: str = "vigenere", alphabet: str = "standard") -> str:
    return _transform(ciphertext, key, cipher, alphabet, True)


def derive_crib_constraints(
    ciphertext: str, period: int, cribs: list[dict],
    cipher: str = "vigenere", alphabet: str = "standard",
) -> tuple[dict[int, int], str | None]:
    """Return required key indexes and a conflict reason, without guessing.

    A conflict proves incompatibility only with this repeating-key model,
    period, alphabet, cipher convention, and supplied crib positions.
    """
    ciphertext = normalize_letters(ciphertext, "ciphertext")
    letters = get_alphabet(alphabet)
    if cipher not in CIPHERS:
        raise ValueError("unknown cipher convention")
    if isinstance(period, bool) or not isinstance(period, int) or period < 1:
        raise ValueError("period must be a positive integer")
    index = {character: position for position, character in enumerate(letters)}
    fixed = {}
    for crib in cribs:
        text = normalize_letters(crib["text"], "crib text")
        start = crib["start"]
        if isinstance(start, bool) or not isinstance(start, int) or start < 1 or start + len(text) - 1 > len(ciphertext):
            raise ValueError("crib positions must lie inside the ciphertext (one-based)")
        for offset, character in enumerate(text):
            position = start - 1 + offset
            plain, encrypted = index[character], index[ciphertext[position]]
            if cipher == "beaufort":
                value = (encrypted + plain) % 26
            elif cipher == "variant":
                value = (plain - encrypted) % 26
            else:
                value = (encrypted - plain) % 26
            key_position = position % period
            if key_position in fixed and fixed[key_position] != value:
                return fixed, f"period {period}: incompatible crib requirements for key position {key_position + 1}"
            fixed[key_position] = value
    return fixed, None


def crib_match_count(plaintext: str, cribs: list[dict]) -> tuple[int, int]:
    """Count unique constrained positions, so overlapping cribs do not inflate scores."""
    expected = {}
    for crib in cribs:
        for offset, letter in enumerate(crib["text"]):
            expected[crib["start"] - 1 + offset] = letter
    return sum(plaintext[position] == letter for position, letter in expected.items()), len(expected)
