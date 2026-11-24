"""Exact clue checks on the seven-column layout, with reproducible full-message controls.

The leading question mark occupies cell zero and has no key or enciphered
value. K4 positions 1..97 are cell numbers. All indices are modulo 26.
Run with python -B -m kryptos.round_t PRESET.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from math import gcd
import random

from .ciphers import ALPHABETS, STANDARD_ALPHABET
from .data import K4_CIPHERTEXT, K4_CRIBS

PRESETS = {
    "shared-pair": {
        "title": "One key symbol for each pair",
        "scope": "In each seven-cell row, pair columns 2 and 3, 4 and 5, and 6 and 7. Allow the right cell to multiply the shared shift and add one common offset.",
        "rules_out": "the tested shared-pair shifts with standard or KRYPTOS plaintext and ciphertext alphabets",
    },
    "column-cipher": {
        "title": "Seven ciphertext alphabets",
        "scope": "Build seven ciphertext alphabets by rotating a keyword. Allow each row its own shift and keep the plaintext alphabet fixed.",
        "rules_out": "the four tested keyword constructions on the ciphertext side, for every choice of row shifts",
    },
    "column-plain": {
        "title": "Seven plaintext alphabets",
        "scope": "Build seven plaintext alphabets by rotating a keyword. Allow each row its own shift and keep the ciphertext alphabet fixed.",
        "rules_out": "the four tested keyword constructions on the plaintext side, for every choice of row shifts",
    },
    "column-both": {
        "title": "Seven alphabets on both sides",
        "scope": "Use different keywords to build the plaintext and ciphertext columns. Try both reading directions and every starting phase on each side, with a separate shift for each row.",
        "rules_out": "the tested pairs of distinct keyword constructions, for every choice of row shifts",
    },
}

WORDS = ("KRYPTOS", "PALIMPSEST", "BERLINCLOCK", "WELTZEITUHR")
SEED = 20261124
SHUFFLES = 20
CLUES = {row["start"] + i: ch for row in K4_CRIBS for i, ch in enumerate(row["text"])}
# Every fully known pair, irrespective of whether its ciphertext letters match.
LEFT_CELLS = tuple(j for j in CLUES if j % 7 in (1, 3, 5) and j + 1 in CLUES)
END_PAIRS = tuple(j for j in LEFT_CELLS if j % 7 == 5)
ROWS = sorted({j // 7 for j in CLUES})


def _alphabet_banks():
    banks = {name: (alpha,) * 7 for name, alpha in ALPHABETS.items()}
    for word in WORDS:
        head = "".join(dict.fromkeys(word))
        tail = "".join(ch for ch in STANDARD_ALPHABET if ch not in head)
        rotations = [head[i:] + head[:i] + tail for i in range(len(head))]
        for start in range(len(head)):
            for step in (1, -1):
                label = f"{word}/{start}/{step:+d}"
                banks[label] = tuple(rotations[(start + step * col) % len(head)] for col in range(7))
    return banks


BANKS = _alphabet_banks()
MIXED = tuple(name for name in BANKS if name not in ALPHABETS)


@dataclass(frozen=True)
class Setting:
    plain: str
    cipher: str
    sign: int
    multiplier: int = 1


def _settings(preset):
    if preset == "shared-pair":
        for plain in ALPHABETS:
            for cipher in ALPHABETS:
                for sign in (1, -1):
                    for multiplier in range(1, 26):
                        if gcd(multiplier, 26) == 1:
                            yield Setting(plain, cipher, sign, multiplier)
        return
    plain_banks = ALPHABETS if preset == "column-cipher" else MIXED
    cipher_banks = ALPHABETS if preset == "column-plain" else MIXED
    for plain in plain_banks:
        for cipher in cipher_banks:
            if preset == "column-both" and plain.split("/")[0] == cipher.split("/")[0]:
                continue
            for sign in (1, -1):
                yield Setting(plain, cipher, sign)


def _fit_pairs(delta, multiplier):
    # The left clue fixes its pair's shift. The right fixes the offset.
    # Each additional complete pair gives one independent check of the offset.
    offsets = {j: (delta[j + 1] - multiplier * delta[j]) % 26 for j in LEFT_CELLS}
    end_fit = len({offsets[j] for j in END_PAIRS}) == 1
    if len(set(offsets.values())) == 1:
        return end_fit, {"offset": next(iter(offsets.values()))}
    return end_fit, None


def _fit_rows(delta):
    # One observed cell per represented row trains the shift for that row.
    end_fit = all(delta[j] == delta[j + 1] for j in END_PAIRS)
    shifts = {}
    for cell, value in delta.items():
        row = cell // 7
        if shifts.setdefault(row, value) != value:
            return end_fit, None
    return end_fit, {"row_shifts": shifts}


def _scan(preset, settings, cipher, stop):
    plain_indices = {name: {j: bank[j % 7].index(ch) for j, ch in CLUES.items()}
                     for name, bank in BANKS.items()}
    cipher_indices = {name: {j: bank[j % 7].index(cipher[j - 1]) for j in CLUES}
                      for name, bank in BANKS.items()}
    tested = end_fits = 0
    flags = []
    for setting in settings:
        if stop is not None and stop.is_set():
            break
        p, c = plain_indices[setting.plain], cipher_indices[setting.cipher]
        delta = {j: (c[j] - setting.sign * p[j]) % 26 for j in CLUES}
        if preset == "shared-pair":
            end_fit, witness = _fit_pairs(delta, setting.multiplier)
        else:
            end_fit, witness = _fit_rows(delta)
        tested += 1
        end_fits += int(end_fit)
        if witness is not None:
            flags.append({"setting": asdict(setting), **witness})
    return tested, end_fits, flags


def _plant(preset, index):
    # Construct the whole ciphertext forward, including the 73 non-clue cells.
    # Different fixed settings and independently sampled keys for the two plants.
    randomizer = random.Random(SEED + 1 + index)
    plain = [randomizer.choice(STANDARD_ALPHABET) for _ in range(97)]
    for cell, ch in CLUES.items():
        plain[cell - 1] = ch
    left = ("PALIMPSEST/1/+1", "WELTZEITUHR/2/-1")[index]
    right = ("KRYPTOS/3/-1", "BERLINCLOCK/1/+1")[index]
    fixed = ("standard", "kryptos")[index]
    sign = (1, -1)[index]
    if preset == "shared-pair":
        setting = Setting(fixed, ("kryptos", "standard")[index], sign, (5, 25)[index])
    elif preset == "column-plain":
        setting = Setting(left, fixed, sign)
    elif preset == "column-cipher":
        setting = Setting(fixed, right, sign)
    else:
        setting = Setting(left, right, sign)
    cipher = []
    row_keys = [randomizer.randrange(26) for _ in range(14)]
    offset = (7, 19)[index]
    for row in range(14):
        pair_keys = [randomizer.randrange(26) for _ in range(4)]
        for col in range(7):
            cell = 7 * row + col
            if cell == 0:
                continue
            if preset == "shared-pair":
                shift = pair_keys[(col + 1) // 2]
                if col in (2, 4, 6):
                    shift = setting.multiplier * shift + offset
            else:
                shift = row_keys[row]
            p = BANKS[setting.plain][col].index(plain[cell - 1])
            cipher.append(BANKS[setting.cipher][col][(sign * p + shift) % 26])
    witness = {"offset": offset} if preset == "shared-pair" else {"row_shifts": {r: row_keys[r] for r in ROWS}}
    return "".join(cipher), {"setting": asdict(setting), **witness}


def run_preset(preset_id, *, cipher=None, stop=None):
    """Run two positive controls and twenty matched shuffles before testing the target."""
    if preset_id not in PRESETS:
        raise ValueError("Unknown seven-column preset")
    cipher = K4_CIPHERTEXT if cipher is None else cipher
    if not isinstance(cipher, str) or len(cipher) != 97 or any(ch not in STANDARD_ALPHABET for ch in cipher):
        raise ValueError("Expected exactly 97 uppercase A-Z letters")
    held_out = len(LEFT_CELLS) - 1 if preset_id == "shared-pair" else len(CLUES) - len(ROWS)
    if held_out < 6:
        raise ValueError("Insufficient independent clues for this preset")
    settings = tuple(_settings(preset_id))
    controls = {"passed": False, "planted_found": 0, "planted_total": 2, "planted": [],
                "shuffled_flagged": 0, "shuffled_total": SHUFFLES, "shuffle_flag_counts": [], "seed": SEED}
    for index in range(2):
        generated, expected = _plant(preset_id, index)
        count, _, flags = _scan(preset_id, settings, generated, stop)
        if count != len(settings):
            break
        found = expected in flags
        controls["planted_found"] += int(found)
        controls["planted"].append({"expected": expected, "found": found, "flags": len(flags)})
    randomizer = random.Random(SEED)
    for _ in range(SHUFFLES):
        if stop is not None and stop.is_set():
            break
        letters = list(cipher)
        randomizer.shuffle(letters)
        count, _, flags = _scan(preset_id, settings, "".join(letters), stop)
        if count != len(settings):
            break
        controls["shuffled_flagged"] += bool(flags)
        controls["shuffle_flag_counts"].append(len(flags))
    controls["passed"] = (controls["planted_found"] == 2 and len(controls["shuffle_flag_counts"]) == SHUFFLES
                          and controls["shuffled_flagged"] == 0)
    tested, end_fits, flags = 0, 0, []
    if controls["passed"]:
        tested, end_fits, flags = _scan(preset_id, settings, cipher, stop)
    completed = tested == len(settings) and controls["passed"]
    if not completed:
        conclusion = "Incomplete run. A stop or control failure leaves this family open."
    elif flags:
        conclusion = "At least one setting fits all 24 clue letters. Each flagged setting still leaves key symbols unknown."
    else:
        conclusion = f"The 24 public clues rule out {PRESETS[preset_id]['rules_out']} on this target."
    return {"preset": preset_id, "title": PRESETS[preset_id]["title"], "tested": tested,
            "decidable": tested, "planned": len(settings), "flagged_count": len(flags), "flags": flags,
            "held_out": held_out, "completed": completed, "controls": controls, "conclusion": conclusion,
            "column_6_7_only_fits": end_fits, "known_end_pairs": list(END_PAIRS),
            "matching_end_pair_rows": [r + 1 for r in range(14) if cipher[7*r + 4] == cipher[7*r + 5]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("preset", choices=PRESETS)
    args = parser.parse_args()
    result = run_preset(args.preset)
    print(json.dumps(result, indent=2))
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
