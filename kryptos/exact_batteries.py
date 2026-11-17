"""Exact clue tests for K4 (research round S).

Every battery decides a whole key space from the 24 published clue letters without trying a key:
the clue letters are turned into equations (mod 26) or equalities, and one algebraic check says
whether any key of the family can satisfy them.  A negative result excludes the family only under
the stated assumptions: the clue letters and positions are right and the ciphertext has no slip
in those 24 letters.  Nothing here produces or scores a plaintext.

Standard library only.  ``python -B -m kryptos.exact_batteries --help`` lists the batteries.
"""
from __future__ import annotations

import argparse
import itertools
import json
import threading
import time
from math import log10

from .data import K4_CIPHERTEXT, K4_CRIBS

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KRY = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
ALPHABETS = {"standard": STD, "kryptos": KRY}
N = 97
FLAG_RESIDUAL = 6  # clue letters that must be left over as an independent test before a fit is reported
ASSUMPTIONS = ("Clue letters and positions as published; no enciphering slip in those 24 letters. "
               "A family is reported only when at least six clue letters remain as an independent test.")


def clue_map(cribs=None):
    """Zero-based position -> plaintext letter."""
    return {c["start"] - 1 + j: ch for c in (K4_CRIBS if cribs is None else cribs) for j, ch in enumerate(c["text"])}


def _check_cipher(cipher):
    cipher = K4_CIPHERTEXT if cipher is None else str(cipher).upper()
    if len(cipher) != N or any(ch not in STD + "?" for ch in cipher):
        raise ValueError("Ciphertext must be 97 letters")
    return cipher


# ---------------------------------------------------------------- linear algebra mod 26
def _eliminate(rows, modulus, rhs):
    rows = [[x % modulus for x in r] for r in rows]
    columns = len(rows[0]) - rhs
    rank = 0
    for c in range(columns):
        pivot = next((r for r in range(rank, len(rows)) if rows[r][c]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][c], -1, modulus)
        lead = rows[rank] = [(x * inverse) % modulus for x in rows[rank]]
        for r in range(rank + 1, len(rows)):
            f = rows[r][c]
            if f:
                rows[r] = [(x - f * y) % modulus for x, y in zip(rows[r], lead)]
        rank += 1
        if rank == len(rows):
            break
    return rank, [all(r[columns + j] == 0 for r in rows[rank:]) for j in range(rhs)]


def solve(rows, rhs=1):
    """rows: [coefficients..., rhs values...].  Returns (consistent per rhs, residual equations)."""
    if not rows:
        return [True] * rhs, 0
    r2, c2 = _eliminate(rows, 2, rhs)
    r13, c13 = _eliminate(rows, 13, rhs)
    return [a and b for a, b in zip(c2, c13)], len(rows) - max(r2, r13)


def conventions(cipher, plain):
    """Eight fixed conventions: (name, {position: key index})."""
    out = []
    for pn, pa in ALPHABETS.items():
        for cn, ca in ALPHABETS.items():
            out.append((f"plain {pn}, cipher {cn}, c=p+k", {i: (ca.index(cipher[i]) - pa.index(p)) % 26 for i, p in plain.items()}))
            out.append((f"plain {pn}, cipher {cn}, c=k-p", {i: (ca.index(cipher[i]) + pa.index(p)) % 26 for i, p in plain.items()}))
    return out


def _result(battery, tested, decidable, survivors, started, **extra):
    return {"battery": battery, "title": BATTERIES[battery]["title"], "tested": tested, "decidable": decidable,
            "survivors": survivors, "survivor_count": len(survivors), "seconds": round(time.monotonic() - started, 3),
            "assumptions": ASSUMPTIONS, **extra}


# ---------------------------------------------------------------- batteries
def periodic_keys(cipher=None, cribs=None, stop=None):
    """Periodic key, clue letters in place: fixed alphabets, or one unknown mixed alphabet solved as unknowns."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain)
    survivors = []; tested = decidable = 0; table = {}
    plain_letters = sorted(set(plain.values())); cipher_letters = sorted({cipher[i] for i in known})
    conv = conventions(cipher, plain)
    for p in range(1, 27):
        base = [[1 if i % p == j else 0 for j in range(p)] for i in known]
        ok, residual = solve([b + [k[i] for _, k in conv] for b, i in zip(base, known)], rhs=len(conv))
        for (name, _), good in zip(conv, ok):
            tested += 1; decidable += residual >= FLAG_RESIDUAL
            if good:
                table.setdefault(f"fixed alphabets ({name})", []).append({"period": p, "residual": residual})
                if residual >= FLAG_RESIDUAL:
                    survivors.append({"model": f"period {p}, {name}", "residual": residual})
        for side, letters, text, targets in (("unknown plaintext alphabet", plain_letters, plain, [[a.index(cipher[i]) for a in ALPHABETS.values()] for i in known]),
                                             ("unknown ciphertext alphabet", cipher_letters, {i: cipher[i] for i in known}, [[a.index(plain[i]) for a in ALPHABETS.values()] for i in known])):
            rows = [[1 if text[i] == x else 0 for x in letters] + b + t for i, b, t in zip(known, base, targets)]
            ok, residual = solve(rows, rhs=2)
            for name, good in zip(ALPHABETS, ok):
                tested += 1; decidable += residual >= FLAG_RESIDUAL
                if good:
                    table.setdefault(f"{side}, other alphabet {name}", []).append({"period": p, "residual": residual})
                    if residual >= FLAG_RESIDUAL:
                        survivors.append({"model": f"period {p}, {side}, other alphabet {name}", "residual": residual})
    return _result("periodic", tested, decidable, survivors, started, consistent_periods=table)


def compound_keys(cipher=None, cribs=None, stop=None):
    """Key = two periodic keys, or periodic key + one key letter per grid row, with an optional steady drift
    and (for a single periodic key) an optional multiple of an earlier ciphertext or plaintext letter."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain)
    conv = conventions(cipher, plain); survivors = []; tested = decidable = 0; stopped = False

    def run(label, columns, usable=None):
        nonlocal tested, decidable
        use = known if usable is None else usable
        if len(use) < 8:
            return
        width = max(len(c) for c in columns.values())
        ok, residual = solve([columns[i] + [0] * (width - len(columns[i])) + [k[i] for _, k in conv] for i in use], rhs=len(conv))
        tested += len(conv)
        if residual >= FLAG_RESIDUAL:
            decidable += len(conv)
            survivors.extend({"model": f"{label}, {name}", "residual": residual} for (name, _), good in zip(conv, ok) if good)

    for p in range(1, 27):
        if stop is not None and stop.is_set():
            stopped = True
            break
        per = {i: [1 if i % p == j else 0 for j in range(p)] for i in known}
        for drift in (0, 1):
            tail = {i: ([i] if drift else []) for i in known}; d = " + drift" if drift else ""
            for q in range(p + 1, 27):
                run(f"periods {p} and {q}{d}", {i: per[i] + [1 if i % q == j else 0 for j in range(q)] + tail[i] for i in known})
            for w in range(2, 50):
                for o in (0, 1):
                    rows_used = sorted({(i + o) // w for i in known})
                    run(f"period {p} + row key (width {w}, start {o}){d}", {i: per[i] + [1 if (i + o) // w == r else 0 for r in rows_used] + tail[i] for i in known})
                    run(f"period {p} + row step (width {w}, start {o}){d}", {i: per[i] + [(i + o) // w] + tail[i] for i in known})
            for lag in range(1, 74):
                for an, a in ALPHABETS.items():
                    use = [i for i in known if i - lag >= 0]
                    run(f"period {p} + ciphertext letter {lag} back ({an}){d}", {i: per[i] + [a.index(cipher[i - lag])] + tail[i] for i in use}, use)
                    use = [i for i in known if i - lag in plain]
                    run(f"period {p} + plaintext letter {lag} back ({an}){d}", {i: per[i] + [a.index(plain[i - lag])] + tail[i] for i in use}, use)
    return _result("compound", tested, decidable, survivors, started, stopped=stopped)


def recurrences(cipher=None, cribs=None, stop=None):
    """Key stream obeys a linear recurrence (order 1-7, with constant), a two-lag recurrence, or polynomial + periodic key."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain)
    segments = []
    for i in known:
        if segments and segments[-1][-1] == i - 1:
            segments[-1].append(i)
        else:
            segments.append([i])
    survivors = []; tested = decidable = 0
    for name, key in conventions(cipher, plain):
        models = [(f"recurrence of order {d}", [[key[i - j] for j in range(1, d + 1)] + [1, key[i]] for s in segments for i in s[d:]]) for d in range(1, 8)]
        models += [(f"two-lag recurrence ({a},{b})", [[key[i - a], key[i - b], 1, key[i]] for s in segments for i in s[b:]]) for b in range(2, 10) for a in range(1, b)]
        models += [(f"degree-{deg} polynomial + period {p}", [[pow(i, e, 26) for e in range(1, deg + 1)] + [1 if i % p == j else 0 for j in range(p)] + [key[i]] for i in known]) for deg in (2, 3) for p in range(1, 14)]
        for label, rows in models:
            if len(rows) < 6:
                continue
            ok, residual = solve(rows); tested += 1; decidable += residual >= 3
            if ok[0] and residual >= 3:
                survivors.append({"model": f"{label}, {name}", "residual": residual})
    return _result("recurrence", tested, decidable, survivors, started, note="Reported at three or more clue letters left over.")


def grid_tableau(cipher=None, cribs=None, stop=None):
    """Unknown alphabet + one key letter per column + one per row, on every grid width 2-31 and every grid start."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain)
    plain_letters = sorted(set(plain.values())); cipher_letters = sorted({cipher[i] for i in known}); survivors = []; tested = decidable = 0
    for w in range(2, 32):
        for o in range(w):
            rows_used = sorted({(i + o) // w for i in known})
            grid = {i: [1 if (i + o) % w == j else 0 for j in range(w)] + [1 if (i + o) // w == r else 0 for r in rows_used] for i in known}
            for side, rows in (("unknown plaintext alphabet", [[1 if plain[i] == x else 0 for x in plain_letters] + grid[i] + [a.index(cipher[i]) for a in ALPHABETS.values()] for i in known]),
                               ("unknown ciphertext alphabet", [[1 if cipher[i] == x else 0 for x in cipher_letters] + grid[i] + [a.index(plain[i]) for a in ALPHABETS.values()] for i in known])):
                ok, residual = solve(rows, rhs=2); tested += 2; decidable += 2 * (residual >= 2)
                survivors.extend({"model": f"width {w}, grid starts {o} cells before K4, {side}, other alphabet {name}", "residual": residual}
                                 for name, good in zip(ALPHABETS, ok) if good and residual >= 2)
    return _result("grid", tested, decidable, survivors, started, note="Reported at two or more clue letters left over; the 14 x 7 grid that starts at the question mark is width 7, start 1.")


SYMBOLS = STD + "?"


def trifid_equalities(text, plain, period, start, direction):
    """Equalities between cube coordinates forced by the clue letters for one Trifid setting."""
    n = len(text); starts = sorted({0} | {i for i in range(n) if i % period == start % period}) + [n]
    for b0, b1 in zip(starts, starts[1:]):
        length = b1 - b0
        for j in range(length):
            for t in range(3):
                k = 3 * j + t; source = b0 + k % length; coordinate = k // length
                if direction == "encipher":
                    if source in plain:
                        yield (text[b0 + j], t), (plain[source], coordinate)
                elif b0 + j in plain:
                    yield (plain[b0 + j], t), (text[source], coordinate)


def cube_exists(equalities):
    """True when some assignment of 27 distinct coordinate triples (any cube) satisfies the equalities."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for a, b in equalities:
        parent[find(a)] = find(b)
    classes = {}
    triples = [tuple(classes.setdefault(find((s, c)), len(classes)) for c in range(3)) for s in SYMBOLS]
    if len(set(triples)) < 27:
        return False
    value = [None] * len(classes)
    order = sorted(range(len(classes)), key=lambda k: -sum(k in t for t in triples))

    def clash():
        seen = set()
        for t in triples:
            v = (value[t[0]], value[t[1]], value[t[2]])
            if None not in v:
                if v in seen:
                    return True
                seen.add(v)
        return False

    def search(depth):
        if depth == len(order):
            return True
        for v in range(3):
            value[order[depth]] = v
            if not clash() and search(depth + 1):
                return True
        value[order[depth]] = None
        return False
    return search(0)


def trifid_all_cubes(cipher=None, cribs=None, stop=None):
    """Trifid on 27 symbols for every possible cube: periods 2-98, every block start, both directions, with or without the question-mark cell."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain0 = clue_map(cribs); survivors = []; tested = 0
    for variant in ("with question mark", "letters only"):
        text = "?" + cipher if variant == "with question mark" else cipher
        shift = 1 if variant == "with question mark" else 0
        plain = {i + shift: ch for i, ch in plain0.items()}
        for direction in ("encipher", "decipher"):
            for period in range(2, len(text) + 1):
                for start in range(period):
                    tested += 1
                    if cube_exists(trifid_equalities(text, plain, period, start, direction)):
                        survivors.append({"model": f"Trifid period {period}, block start {start}, {direction}, {variant}"})
    return _result("trifid", tested, tested, survivors, started)


def _transposition_tests(n, pi, cipher_index, plain_index, known, label, survivors, max_period):
    inverse = [0] * n
    for j, source in enumerate(pi):
        inverse[source] = j
    q = pi[0] if n == 98 else -1
    cells = []; where = []
    for i in known:
        ip = i + (i >= q) if n == 98 else i
        j = inverse[ip]
        if n == 98 and j == 0:
            return 0
        cells.append(j); where.append(ip)
    tested = 0
    for v in range(8):
        pa, ca = v >> 2, (v >> 1) & 1
        values = [(cipher_index[ca][(j - 1) if n == 98 else j] + plain_index[pa][e]) % 26 if v & 1 else (cipher_index[ca][(j - 1) if n == 98 else j] - plain_index[pa][e]) % 26 for e, j in enumerate(cells)]
        for mode, index in (("substitute, then transpose", where), ("transpose, then substitute", cells)):
            for period in range(1, max_period + 1):
                tested += 1; slot = {}
                for r, val in zip(index, values):
                    if slot.setdefault(r % period, val) != val:
                        break
                else:
                    if len(values) - len(slot) >= FLAG_RESIDUAL:
                        alphabet = (STD, KRY)[ca]
                        survivors.append({"model": f"{label}; {mode}; period {period}; plain {('standard', 'kryptos')[pa]}, cipher {('standard', 'kryptos')[ca]}, {'c=k-p' if v & 1 else 'c=p+k'}",
                                          "key": "".join(alphabet[slot[r]] if r in slot else "?" for r in range(period)), "residual": len(values) - len(slot)})
    return tested


def columnar(n, width, order, upward):
    out = []
    for c in order:
        column = [r * width + c for r in range((n - c + width - 1) // width)]
        out += column[::-1] if upward else column
    return out


def grid_turn(n, width, style, sequence):
    rows = n // width; out = []
    for k in range(width):
        c = width - 1 - k if style & 1 else k
        out += [sequence[(rows - 1 - t if style & 2 else t) * width + c] for t in range(rows)]
    return out


def transposition_periodic(cipher=None, cribs=None, stop=None, max_width=8, max_period=13):
    """Transposition layered with a periodic keyed substitution (clue positions are plaintext positions here).
    97 letters: every columnar order up to ``max_width`` columns; 98 cells with the question mark: every order of the
    complete 14 x 7 grid and K3-style single and double grid turns; inverses of all of them."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain)
    if not 2 <= int(max_width) <= 9 or not 1 <= int(max_period) <= 13:
        raise ValueError("max_width must be 2-9 and max_period 1-13")
    cipher_index = [[a.index(ch) for ch in cipher] for a in (STD, KRY)]
    plain_index = [[a.index(plain[i]) for i in known] for a in (STD, KRY)]
    survivors = []; tested = permutations = 0; stopped = False

    def both(n, pi, label):
        nonlocal tested, permutations
        inverse = [0] * n
        for j, s in enumerate(pi):
            inverse[s] = j
        for perm, name in ((pi, label), (inverse, label + ", inverse")):
            permutations += 1
            tested += _transposition_tests(n, perm, cipher_index, plain_index, known, name, survivors, int(max_period))

    for n, widths in ((97, range(2, int(max_width) + 1)), (98, (2, 7))):
        for width in widths:
            for order in itertools.permutations(range(width)):
                if stop is not None and stop.is_set():
                    stopped = True; break
                for upward in (0, 1):
                    both(n, columnar(n, width, order, upward), f"{n} cells, columnar width {width}, order {''.join(map(str, order))}, read {'up' if upward else 'down'}")
    identity = list(range(98))
    for w1 in (2, 7, 14, 49):
        for s1 in range(4):
            first = grid_turn(98, w1, s1, identity); both(98, first, f"98 cells, grid turn width {w1} style {s1}")
            for w2 in (2, 7, 14, 49):
                for s2 in range(4):
                    both(98, grid_turn(98, w2, s2, first), f"98 cells, grid turns width {w1} style {s1} then width {w2} style {s2}")
    return _result("transposition", tested, tested, survivors, started, permutations=permutations, max_width=int(max_width), max_period=int(max_period), stopped=stopped)


def reciprocal_and_pair_ciphers(cipher=None, cribs=None, stop=None):
    """Porta (any key) and Slidefair (any key, any period) against the clue letters."""
    started = time.monotonic(); cipher = _check_cipher(cipher); plain = clue_map(cribs); known = sorted(plain); survivors = []; tested = 0; detail = []
    for name, a in ALPHABETS.items():
        tested += 1; bad = sum((a.index(plain[i]) < 13) == (a.index(cipher[i]) < 13) for i in known)
        detail.append({"model": f"Porta, {name} alphabet", "clue_letters_that_break_it": bad})
        if not bad:
            survivors.append({"model": f"Porta, {name} alphabet"})
        for align in (0, 1):
            pairs = [(i, i + 1) for i in range(align, N - 1, 2) if i in plain and i + 1 in plain]
            for kind in ("Vigenere", "Variant", "Beaufort"):
                good = 0
                for i, j in pairs:
                    p1, p2, c1, c2 = (a.index(x) for x in (plain[i], plain[j], cipher[i], cipher[j]))
                    k1, k2 = {"Vigenere": ((p2 - c1) % 26, (c2 - p1) % 26), "Variant": ((c1 - p2) % 26, (p1 - c2) % 26), "Beaufort": ((c1 + p2) % 26, (c2 + p1) % 26)}[kind]
                    good += k1 == k2
                tested += 1; label = f"Slidefair {kind}, {name} alphabet, pairs start {'even' if align == 0 else 'odd'}"
                detail.append({"model": label, "pairs_that_fit": good, "pairs": len(pairs)})
                if good == len(pairs):
                    survivors.append({"model": label})
    return _result("pairs", tested, tested, survivors, started, detail=detail)


BATTERIES = {
    "periodic": {"title": "Periodic key in place (fixed or one unknown alphabet)", "run": periodic_keys, "typical_seconds": 1},
    "compound": {"title": "Compound keys in place (two periods, row keys, drift, lagged letters)", "run": compound_keys, "typical_seconds": 120},
    "recurrence": {"title": "Key stream from a recurrence or polynomial", "run": recurrences, "typical_seconds": 1},
    "grid": {"title": "Unknown alphabet with column and row keys on every grid", "run": grid_tableau, "typical_seconds": 3},
    "trifid": {"title": "Trifid with the question mark as 27th symbol, every cube", "run": trifid_all_cubes, "typical_seconds": 5},
    "pairs": {"title": "Porta and Slidefair", "run": reciprocal_and_pair_ciphers, "typical_seconds": 1},
    "transposition": {"title": "Transposition layered with a periodic keyed substitution", "run": transposition_periodic, "typical_seconds": 240},
}


def catalog():
    return {"interpretation": ("Exact tests on the 24 published K4 clue letters. An empty survivor list excludes the stated family only; "
                               "it is not a statement about K4 as a whole, and no plaintext is produced."),
            "assumptions": ASSUMPTIONS,
            "batteries": [{"id": key, "title": value["title"], "description": " ".join((value["run"].__doc__ or "").split()), "typical_seconds": value["typical_seconds"]}
                          for key, value in BATTERIES.items()]}


def run_battery(battery, cipher=None, stop=None, **options):
    if battery not in BATTERIES:
        raise ValueError("Unknown battery")
    return BATTERIES[battery]["run"](cipher=cipher, stop=stop, **options)


class ExactRunner:
    """One battery at a time on a background thread, for the local dashboard."""

    def __init__(self):
        self.lock = threading.Lock(); self.thread = None; self.stop = threading.Event()
        self.state = {"state": "idle", "battery": None, "result": None, "error": None}

    def view(self):
        with self.lock:
            return dict(self.state)

    def start(self, body):
        if not isinstance(body, dict) or not set(body) <= {"battery", "cipher"} or body.get("battery") not in BATTERIES:
            raise ValueError("Send {\"battery\": one of " + ", ".join(BATTERIES) + "} and optionally a 97-letter cipher")
        cipher = _check_cipher(body.get("cipher"))
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise ValueError("An exact clue test is already running")
            self.stop = threading.Event()
            self.state = {"state": "running", "battery": body["battery"], "result": None, "error": None}
            self.thread = threading.Thread(target=self._work, args=(body["battery"], cipher, self.stop), daemon=True)
            self.thread.start()
            return dict(self.state)

    def _work(self, battery, cipher, stop):
        try:
            result = run_battery(battery, cipher=cipher, stop=stop); update = {"state": "stopped" if stop.is_set() else "complete", "result": result}
        except Exception as error:  # reported to the page; the thread must not die silently
            update = {"state": "failed", "error": str(error)}
        with self.lock:
            if self.stop is stop:
                self.state.update(update)

    def cancel(self):
        with self.lock:
            self.stop.set()
            return dict(self.state)

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -B -m kryptos.exact_batteries", description=catalog()["interpretation"])
    parser.add_argument("battery", nargs="*", choices=[*BATTERIES, "all"], default="all")
    parser.add_argument("--cipher", help="97-letter ciphertext to test instead of K4 (for controls)")
    parser.add_argument("--max-width", type=int, default=8, help="transposition battery: widest columnar transposition (2-9; 9 takes much longer)")
    parser.add_argument("--out", help="write the JSON results to this file")
    args = parser.parse_args(argv)
    names = list(BATTERIES) if args.battery == "all" or "all" in args.battery else args.battery
    results = []
    for name in names:
        result = run_battery(name, cipher=args.cipher, **({"max_width": args.max_width} if name == "transposition" else {}))
        results.append(result)
        print(f"{name}: tested {result['tested']}, decidable {result['decidable']}, survivors {result['survivor_count']}, {result['seconds']} s", flush=True)
        for s in result["survivors"][:10]:
            print("   ", json.dumps(s))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump({"results": results}, handle, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
