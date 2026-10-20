"""Exact necessary-condition check for a stream of NATO spelling words.

Strip spaces and hyphens, use only the 26 letter words, and allow every order
and word boundary. A missing adjacent-letter pair proves a string impossible.
Presence of every pair would not prove a string possible.
"""
import argparse
import json
from pathlib import Path

SOURCE = "https://www.nato.int/en/news-and-events/articles/news/2017/12/21/nato-phonetic-alphabet-codes-and-signals"
WORDS = "ALFA BRAVO CHARLIE DELTA ECHO FOXTROT GOLF HOTEL INDIA JULIETT KILO LIMA MIKE NOVEMBER OSCAR PAPA QUEBEC ROMEO SIERRA TANGO UNIFORM VICTOR WHISKEY XRAY YANKEE ZULU".split()


def pairs(text):
    return {text[i:i + 2] for i in range(len(text) - 1)}


def analyze():
    assert len(WORDS) == 26
    assert "".join(word[0] for word in WORDS) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert min(map(len, WORDS)) > 1
    internal = set().union(*(pairs(word) for word in WORDS))
    boundary = {left[-1] + right[0] for left in WORDS for right in WORDS}
    allowed = internal | boundary
    # Independently enumerate every ordered pair of complete words.
    assert allowed == set().union(*(pairs(a + b) for a in WORDS for b in WORDS))
    controls = []
    for indices, expected in [([4, 13, 4], "ECHONOVEMBERECHO"), ([1, 2], "BRAVOCHARLIE")]:
        text = "".join(WORDS[i] for i in indices)
        assert text == expected and not (pairs(text) - allowed)
        controls.append({"words": [WORDS[i] for i in indices], "text": text, "all_pairs_allowed": True})
    findings = []
    for crib, witness in [("EASTNORTHEAST", "ST"), ("BERLINCLOCK", "NC")]:
        absent = sorted(pairs(crib) - allowed)
        assert witness in absent
        findings.append({"crib": crib, "impossible_pairs": absent, "witness": witness,
                         "possible_as_substring_of_codeword_stream": False})
    return {"source": SOURCE, "normalized_letter_words": WORDS,
            "internal_pairs": sorted(internal), "boundary_pairs": sorted(boundary),
            "allowed_pairs": sorted(allowed), "positive_controls": controls,
            "findings": findings, "ordered_word_pairs_checked": 26 * 26,
            "scope": "Only a literal stream consisting entirely of the 26 NATO letter words, with spaces/hyphens removed; arbitrary word order and substring alignment.",
            "non_claims": ["No exclusion of a custom codebook, acrostic, mixed prose/codeword text, or another spelling alphabet.",
                           "No exclusion of a separate intermediate text carrying NATO words.",
                           "No K4 or K5 decryption and no key search."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Use a fresh output path to preserve evidence.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(analyze(), indent=2) + "\n", encoding="utf-8")
    print("Exact NATO bigram check passed; both known phrases have impossible pairs.")
