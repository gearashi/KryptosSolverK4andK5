"""Frozen bounded K4 cyclic-alphabet experiments plus independent controls."""
import argparse
import itertools
import json
from pathlib import Path
import string
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from kryptos.keyed_alphabet import recover_cyclic_alphabet


def encrypt(text, alphabet, key, cipher):
    out = []
    for i, c in enumerate(text):
        p, k = alphabet.index(c), key[i % len(key)]
        out.append(alphabet[(p+k if cipher == "vigenere" else k-p if cipher == "beaufort" else p-k) % 26])
    return "".join(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    controls = []
    a = string.ascii_uppercase
    plaintext = a + a[::-1] + "WXYZWAWBXCYDZ"
    for cipher in ("vigenere", "beaufort", "variant"):
        ciphertext = encrypt(plaintext, a[:22]+"YWZX", [3,19], cipher)
        expected = set()
        for tail in itertools.permutations("WXYZ"):
            alphabet = a[:22]+"".join(tail)
            key = []
            for i in range(2):
                p, c = alphabet.index(plaintext[i]), alphabet.index(ciphertext[i])
                key.append((c-p if cipher == "vigenere" else c+p if cipher == "beaufort" else p-c) % 26)
            if encrypt(plaintext, alphabet, key, cipher) == ciphertext:
                expected.add((alphabet, "".join(alphabet[k] for k in key)))
        result = recover_cyclic_alphabet(ciphertext, [{"start":1,"text":plaintext}], period=2,
            cipher=cipher, fixed_indices={c:i for i,c in enumerate(a[:22])}, max_candidates=100,
            max_states=10000, time_limit_seconds=2)
        actual = {(c["alphabet"],c["key_pattern"]) for c in result["candidates"]}
        assert result["complete"] and actual == expected and expected
        controls.append({"cipher":cipher,"brute_alphabets":24,"answer_key_supplied":False,
                         "supplied_indices":22,"complete_plaintext_supplied":True,"result":result})
    records = [recover_cyclic_alphabet(K4_CIPHERTEXT, K4_CRIBS, period=p, cipher=cipher,
        max_states=4000,max_candidates=2,time_limit_seconds=1)
        for cipher in ("vigenere","beaufort","variant") for p in range(1,9)]
    result = {"controls":controls,"k4":records,
        "summary":{"models":len(records),"complete_rejections":sum(r["complete"] and r["feasible"] is False for r in records),
                   "witness_models":sum(r["feasible"] is True for r in records),
                   "censored_models":sum(not r["complete"] for r in records)},
        "interpretation":"Only repeating periods1..8 under one unknown shared cyclic alphabet. No transposition included. Censored no-witness runs are inconclusive. Assignment counts are not distinct plaintext counts."}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,allow_nan=False)
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()
