"""K3 known-answer reference and explicit route convention.

Provenance:
* Ciphertext: https://www.elonka.com/kryptos/transcript.html
* Plaintext / first-person solver record: Jim Gillogly, The Cryptogram,
  September/October 1999, printed pp. 5-7 (PDF pp. 3-5):
  https://www.thekryptosproject.com/kryptos/cia/thecryptogram/pdfs/Binder1.pdf
* Gillogly's June 1999 announcement mirror:
  https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html

The two-route formula below is a computationally verified equivalent for the
336-letter known pair, NOT a claim about Sanborn's original construction.
Gillogly's paper describes three route widths 14, 24, 8; that prose alone
does not specify the same two-step convention. See docs/LAYER_SOURCES.md.

Applying these widths to length 97, with skipped empty cells, is an explicitly
chosen K4 hypothesis. Its connection to K3 is not established historical fact.
"""

K3_CIPHERTEXT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETP"
    "RNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLS"
    "EDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOAS"
    "FIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHI"
    "LCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEI"
    "MEHNLSSTTRTVDOHW"
)

K3_PLAINTEXT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"
    "LOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREAC"
    "HINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDT"
    "HECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAME"
    "TOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCA"
    "NYOUSEEANYTHINGQ"
)


def route_indices(length: int, width: int) -> tuple[int, ...]:
    """Fill rows left-to-right; read columns right-to-left, top-to-bottom.

    For a ragged final row, nonexistent cells are skipped without padding.
    The returned tuple maps each output position to its input position.
    """
    if length < 0 or width < 1:
        raise ValueError("length must be nonnegative and width positive")
    return tuple(
        row_start + col
        for col in range(min(width, length) - 1, -1, -1)
        for row_start in range(0, length, width)
        if row_start + col < length
    )


def route(text: str, width: int) -> str:
    """Apply the declared route; no characters are altered or dropped."""
    return "".join(text[i] for i in route_indices(len(text), width))


def unroute(text: str, width: int) -> str:
    """Inverse of route(), including its explicit ragged-grid convention."""
    result = [""] * len(text)
    for output_index, input_index in enumerate(route_indices(len(text), width)):
        result[input_index] = text[output_index]
    return "".join(result)


def decrypt_k3(ciphertext: str = K3_CIPHERTEXT) -> str:
    """Known-pair-equivalent decryption: T_8(T_24(ciphertext))."""
    if len(ciphertext) != 336:
        raise ValueError("Historical K3 reference requires exactly 336 letters")
    return route(route(ciphertext, 24), 8)


def encrypt_k3(plaintext: str = K3_PLAINTEXT) -> str:
    """Inverse of the verified equivalent K3 decryption."""
    if len(plaintext) != 336:
        raise ValueError("Historical K3 reference requires exactly 336 letters")
    return unroute(unroute(plaintext, 8), 24)


def validate() -> dict:
    """Tiny deterministic known-answer check; no cryptanalytic search."""
    assert len(K3_CIPHERTEXT) == len(K3_PLAINTEXT) == 336
    assert decrypt_k3() == K3_PLAINTEXT
    assert encrypt_k3() == K3_CIPHERTEXT
    assert sorted(route_indices(336, 24)) == list(range(336))
    assert sorted(route_indices(336, 8)) == list(range(336))
    return {"letters": 336, "plaintext_matches": True, "reencryption_matches": True}


if __name__ == "__main__":
    import json
    print(json.dumps(validate(), sort_keys=True))
