"""Small, transparent English ranking heuristic; a rank is never a proof.

The score combines average English monogram log-likelihood, hand-selected
common n-gram bonuses, and conspicuous spelling penalties. It is not a
trained language model, calibrated probability, or confidence of a solution.
Callers exclude crib positions explicitly. Features touching excluded positions
are omitted, and gaps never create new n-grams. Scores are comparable only with
the same mask and this same English heuristic.
"""

from __future__ import annotations

import math

_FREQUENCIES = (
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
    0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
    6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
)
_MONOGRAM = {chr(65 + position): math.log(value / 100) for position, value in enumerate(_FREQUENCIES)}
_BIGRAMS = set("TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR ST TO NT NG SE HA AS OU IO LE VE CO ME DE HI RI RO IC NE EA RA CE LI CH LL BE MA SI OM UR CA EL TA LA NS DI FO HO PE EC PR NO CT US AC OT IL TR LY NC ET UT SS SO RS UN LO WA GE IE WH EE WI EM AD OL RT PO WE NA UL NI TS MO OW PA IM MI AI SH IR SU ID OS IV IA AM FI CI VI PL IG TU EV LD RY MP FE BL AB GH TY OP WO SA AY EX KE FR OO AV AG IF AP GR OD BO SP RD DO UC BU EI OV BY RM EP TT OC FA EF CU RN SC GI DA YO CR CL DU GA QU UE".split())
_TRIGRAMS = set("THE AND ING HER ERE ENT THA NTH WAS ETH FOR DTH HAT SHE ION TIO VER EST HIS OTH RES ONT REA EVE NOT TER ERT ERS ATI ALL ITH HES TIN ATE ILL ORE CON RST STO ARE EAR INT NCE ESS IVE MEN ONE OUR OUT YOU TED COM ONS PRO NDE WIT BUT HAV ICH WER GHT STA THI STH OUS ITE HAN TTH EEN ECT OME CHA NED ANS MAN IES LIN ISE HEN ANT STR ESE NTO HIN RAN WHE HAD EDT TED ROU ION ACK IDE RIN EAN PER OSE UND OVE ABO OUL OUN FRO OTE VER ELL HEA EAS ETT EWH ERE EFO SOF SHO IFT OLD AIN ILE TLE SIO EVA STO TWA ETO TIS ELI HEL LOW WOR ORL RLD ATT TAC CKD KDA DAW AWN BER ERL RLI LIN CLO LOC OCK EAS AST NOR ORT RTH".split())
_TETRAGRAMS = set("TION NTHE THER THAT OFTH FTHE WITH ATIO MENT OULD FROM THIS TING THEY HAVE HICH WHIC CTIO ATTH THEM INTH WERE ETHE ANDT THES HERE OTHE RTHE DTHE EAND HING THEI NGTH EDTH GHTH OUGH THOU THRO EVER OVER UNDE NDER OUTH INTO ONTH TTHE SOME WILL THEN THAN WHEN WHAT BEEN ENCE TION INGS ERSI ERIN ANCE INTE ENTH ESTH SAND HECO EFOR BEFO FORE YTHE THEC ERTH THERE THEIR ABOUT BERL ERLI RLIN EAST NORT ORTH CLOCK HELLO WORLD ATTACK DAWN LIGHT SHADOW BETWEEN SUBTLE INVISIBLE".split())


# Remove the prototype's appended sculpture/test-plaintext features. These
# hand-selected tables still require calibration; they are not a trained model.
_TRIGRAMS.difference_update("HEL LOW WOR ORL RLD ATT TAC CKD KDA DAW AWN BER ERL RLI LIN CLO LOC OCK EAS AST NOR ORT RTH".split())
_TETRAGRAMS = {word for word in _TETRAGRAMS if len(word) == 4}
_TETRAGRAMS.difference_update("BERL ERLI RLIN EAST NORT ORTH DAWN".split())


def _run_score(text: str) -> float:
    """Unnormalized feature sum for one contiguous unmasked run."""
    length = len(text)
    score = sum(_MONOGRAM.get(letter, -15.0) for letter in text)
    score += 1.05 * sum(text[index:index + 2] in _BIGRAMS for index in range(length - 1))
    score += 2.2 * sum(text[index:index + 3] in _TRIGRAMS for index in range(length - 2))
    score += 3.0 * sum(text[index:index + 4] in _TETRAGRAMS for index in range(length - 3))
    score -= 2.5 * sum(text[index] == "Q" and text[index + 1] != "U" for index in range(length - 1))
    score -= 1.5 * sum(text[index] == text[index + 1] and text[index] not in "ELOSTFNRPMDC" for index in range(length - 1))
    return score


def english_score(text: str, excluded_positions=()) -> float:
    """Rank only unmasked text, with zero-based excluded positions.

    Exclude every feature touching a masked character, including spelling
    penalties. An empty or completely masked text returns neutral 0.0; callers
    must report zero scored characters rather than treating it as evidence.
    """
    excluded = frozenset(excluded_positions)
    if any(type(i) is not int or not 0 <= i < len(text) for i in excluded):
        raise ValueError("excluded positions must be zero-based indices inside the text")
    eligible = len(text) - len(excluded)
    if not eligible:
        return 0.0
    runs, start = [], 0
    for i in sorted(excluded):
        if start < i:
            runs.append(text[start:i])
        start = i + 1
    if start < len(text):
        runs.append(text[start:])
    return sum(_run_score(run) for run in runs) / eligible


SCORE_DESCRIPTION = (
    "Average monogram log-likelihood plus common bigram/trigram/tetragram bonuses "
    "and spelling penalties. Higher ranks better; score is not solution confidence. "
    "Crib letters and all features touching them are excluded. Gaps are not joined. "
    "Compare only identical masks/coverage under this English heuristic. "
    "Zero scored characters gives neutral 0, not evidence of English."
)
