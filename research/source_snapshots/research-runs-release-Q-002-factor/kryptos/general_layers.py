"""Exact shared-alphabet linear cipher layers over Z/26Z.

Stages are in encryption order. Gather means output[j] = input[permutation[j]].
Unknown repeating keys belong to separate substitution stages. We solve over
F2 and F13, then project key freedoms to plaintext before applying CRT. A fit
establishes consistency with the supplied model, never authentication.
"""
from dataclasses import dataclass
from itertools import product
import string


ALPHABETS = {"standard": string.ascii_uppercase,
             "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
SIGNS = {"vigenere": (1, 1), "beaufort": (-1, 1), "variant": (1, -1)}


class LayerBudgetExceeded(ValueError):
    """The exact calculation exceeded a declared bound; no verdict is given."""


class _Budget:
    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def charge(self, amount):
        if self.used + amount > self.limit:
            raise LayerBudgetExceeded("general-layer scalar-work budget exceeded")
        self.used += amount


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _alphabet(value):
    if not isinstance(value, str):
        raise ValueError("one known shared alphabet is required; mixed/unknown alphabets are unsupported")
    value = ALPHABETS.get(value, value)
    if len(value) != 26 or set(value) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be a known uppercase A-Z permutation")
    return value


@dataclass(frozen=True)
class Stage:
    operation: str
    period: int = 0
    cipher: str = ""
    permutation: tuple = ()

    def to_dict(self):
        if self.operation == "gather":
            return {"operation": "gather", "permutation": list(self.permutation)}
        return {"operation": "substitution", "period": self.period, "cipher": self.cipher}


def _stages(stages, length, max_key_slots):
    if not isinstance(stages, (list, tuple)) or not 1 <= len(stages) <= 16:
        raise ValueError("stages must contain 1..16 explicit operations")
    normalized, slots = [], 0
    for stage in stages:
        if not isinstance(stage, dict):
            raise ValueError("each stage must be an object")
        op = stage.get("operation")
        if op == "substitution":
            if set(stage) - {"operation", "period", "cipher"}:
                raise ValueError("unsupported substitution field; stage-specific or unknown alphabets are unsupported")
            period = _integer(stage.get("period"), "period", 1, 256)
            cipher = stage.get("cipher", "vigenere")
            if cipher not in SIGNS:
                raise ValueError("substitution must be vigenere, beaufort, or variant")
            slots += period
            normalized.append(Stage(op, period, cipher))
        elif op == "gather":
            if set(stage) != {"operation", "permutation"}:
                raise ValueError("a gather requires only its explicit permutation")
            perm = stage["permutation"]
            if (not isinstance(perm, (list, tuple)) or len(perm) != length
                    or any(type(i) is not int for i in perm)
                    or sorted(perm) != list(range(length))):
                raise ValueError("gather must be a zero-based bijection of the text positions")
            normalized.append(Stage(op, permutation=tuple(perm)))
        else:
            raise ValueError("unsupported operation; use substitution or gather")
    if slots > max_key_slots:
        raise LayerBudgetExceeded("general-layer key-slot budget exceeded")
    return tuple(normalized), slots


def literal_encrypt(plaintext, keys, stages, alphabet="standard"):
    """Literal forward replay, with no linear-system or projection helpers."""
    alphabet = _alphabet(alphabet)
    if not isinstance(plaintext, str) or not 1 <= len(plaintext) <= 4096 or any(c not in alphabet for c in plaintext):
        raise ValueError("plaintext must be a complete nonempty A-Z string")
    normalized, _ = _stages(stages, len(plaintext), 8192)
    if not isinstance(keys, (list, tuple)) or len(keys) != sum(s.operation == "substitution" for s in normalized):
        raise ValueError("one complete key is required per substitution stage")
    text, key_index = plaintext, 0
    for stage in normalized:
        if stage.operation == "gather":
            text = "".join(text[i] for i in stage.permutation)
        else:
            key = keys[key_index]
            key_index += 1
            if not isinstance(key, str) or len(key) != stage.period or any(c not in alphabet for c in key):
                raise ValueError("a key must have its declared period and alphabet")
            output = []
            for i, symbol in enumerate(text):
                p, k = alphabet.index(symbol), alphabet.index(key[i % len(key)])
                value = p + k if stage.cipher == "vigenere" else k - p if stage.cipher == "beaufort" else p - k
                output.append(alphabet[value % 26])
            text = "".join(output)
    return text


@dataclass(frozen=True)
class FieldSolution:
    modulus: int
    feasible: bool
    rank: int
    key_base: tuple
    key_nullity: int
    plaintext_base: tuple
    plaintext_columns: tuple
    key_lifts: tuple
    conflict_weights: tuple = ()
    conflict_residue: int = 0

    @property
    def plaintext_dimension(self):
        return len(self.plaintext_columns)


def _rref(matrix, rhs, width, modulus, budget):
    """Return an affine key solution or a checkable inconsistent row relation."""
    count = len(matrix)
    rows = [[v % modulus for v in row] + [rhs[i] % modulus] for i, row in enumerate(matrix)]
    proof = [[int(i == j) for j in range(count)] for i in range(count)]
    pivots, top = [], 0
    for col in range(width):
        pivot = next((i for i in range(top, count) if rows[i][col]), None)
        if pivot is None:
            continue
        rows[top], rows[pivot] = rows[pivot], rows[top]
        proof[top], proof[pivot] = proof[pivot], proof[top]
        inverse = pow(rows[top][col], -1, modulus)
        budget.charge(width + 1 + count)
        rows[top] = [(v * inverse) % modulus for v in rows[top]]
        proof[top] = [(v * inverse) % modulus for v in proof[top]]
        for i in range(count):
            if i != top and rows[i][col]:
                factor = rows[i][col]
                budget.charge(width + 1 + count)
                rows[i] = [(a - factor * b) % modulus for a, b in zip(rows[i], rows[top])]
                proof[i] = [(a - factor * b) % modulus for a, b in zip(proof[i], proof[top])]
        pivots.append(col)
        top += 1
        if top == count:
            break
    for i, row in enumerate(rows):
        if not any(row[:width]) and row[width]:
            return None, (), len(pivots), tuple(proof[i]), row[width]
    base = [0] * width
    for i, col in enumerate(pivots):
        base[col] = rows[i][width]
    null = []
    pivot_set = set(pivots)
    for free in range(width):
        if free in pivot_set:
            continue
        vector = [0] * width
        vector[free] = 1
        for i, col in enumerate(pivots):
            vector[col] = -rows[i][free] % modulus
        null.append(tuple(vector))
    return tuple(base), tuple(null), len(pivots), (), 0


def _field(matrix, rhs, width, plain_constant, plain_map, modulus, budget):
    base, null, rank, weights, residual = _rref(matrix, rhs, width, modulus, budget)
    if base is None:
        return FieldSolution(modulus, False, rank, (), 0, (), (), (), weights, residual)
    length = len(plain_constant)
    budget.charge(length * width)
    plain_base = tuple((c + sum(a * x for a, x in zip(row, base))) % modulus
                       for c, row in zip(plain_constant, plain_map))
    independent, images, lifts = [], [], []
    for vector in null:
        budget.charge(length * width)
        image = tuple(sum(a * x for a, x in zip(row, vector)) % modulus for row in plain_map)
        reduced = list(image)
        for pivot, basis in independent:
            factor = reduced[pivot]
            if factor:
                budget.charge(length)
                reduced = [(a - factor * b) % modulus for a, b in zip(reduced, basis)]
        pivot = next((i for i, value in enumerate(reduced) if value), None)
        if pivot is not None:
            inv = pow(reduced[pivot], -1, modulus)
            budget.charge(length)
            independent.append((pivot, tuple(value * inv % modulus for value in reduced)))
            # Keep the ORIGINAL image and its key lift: this preserves a simple
            # auditable map from every retained plaintext freedom to actual keys.
            images.append(image)
            lifts.append(vector)
    return FieldSolution(modulus, True, rank, base, len(null), plain_base, tuple(images), tuple(lifts))


def _crt(a, b):
    return (13 * a + 14 * b) % 26


def _values(values, count, modulus):
    if values is None:
        return (0,) * count
    if not isinstance(values, (tuple, list)) or len(values) != count or any(type(v) is not int or not 0 <= v < modulus for v in values):
        raise ValueError(f"expected {count} residues in 0..{modulus - 1}")
    return tuple(values)


@dataclass(frozen=True)
class GeneralLayerSolution:
    ciphertext: str
    known: tuple
    stages: tuple
    alphabet: str
    key_slots: int
    constraints: tuple
    field2: FieldSolution
    field13: FieldSolution
    work: int
    bounds: tuple

    @property
    def feasible(self):
        return self.field2.feasible and self.field13.feasible

    @property
    def dimensions_mod2(self):
        return self.field2.plaintext_dimension if self.feasible else None

    @property
    def dimensions_mod13(self):
        return self.field13.plaintext_dimension if self.feasible else None

    @property
    def distinct_plaintext_count(self):
        return 2 ** self.dimensions_mod2 * 13 ** self.dimensions_mod13 if self.feasible else 0

    @property
    def key_assignment_count(self):
        return 2 ** self.field2.key_nullity * 13 ** self.field13.key_nullity if self.feasible else 0

    def _require_fit(self):
        if not self.feasible:
            raise ValueError("the declared layer model is inconsistent")

    def _coordinates(self, values2, values13):
        self._require_fit()
        return _values(values2, self.dimensions_mod2, 2), _values(values13, self.dimensions_mod13, 13)

    def plaintext(self, values2=None, values13=None):
        coordinates = self._coordinates(values2, values13)
        field_text = []
        for field, values in zip((self.field2, self.field13), coordinates):
            field_text.append(tuple((base + sum(column[i] * value for column, value in zip(field.plaintext_columns, values))) % field.modulus
                                    for i, base in enumerate(field.plaintext_base)))
        return "".join(self.alphabet[_crt(a, b)] for a, b in zip(*field_text))

    def keys(self, values2=None, values13=None):
        coordinates = self._coordinates(values2, values13)
        residues = []
        for field, values in zip((self.field2, self.field13), coordinates):
            residues.append(tuple((base + sum(lift[i] * value for lift, value in zip(field.key_lifts, values))) % field.modulus
                                  for i, base in enumerate(field.key_base)))
        combined = tuple(_crt(a, b) for a, b in zip(*residues))
        keys, offset = [], 0
        for stage in self.stages:
            if stage.operation == "substitution":
                keys.append("".join(self.alphabet[value] for value in combined[offset:offset + stage.period]))
                offset += stage.period
        return tuple(keys)

    def representative_keys(self):
        return self.keys()

    def prediction_mask(self):
        self._require_fit()
        base = self.plaintext()
        return "".join("?" if any(column[i] for field in (self.field2, self.field13) for column in field.plaintext_columns) else symbol
                       for i, symbol in enumerate(base))

    def affine_plaintext(self):
        """Finite-domain affine form: idx(P[i]) = base[i]+sum(col[i]*v) mod26.

        Variables are ordered F2 coordinates, then F13 coordinates. They range
        over domain sizes 2 and 13 respectively, NOT independently over 26.
        """
        self._require_fit()
        return {"alphabet": self.alphabet,
                "base": tuple(_crt(a, b) for a, b in zip(self.field2.plaintext_base, self.field13.plaintext_base)),
                "columns": tuple(tuple(13 * v % 26 for v in col) for col in self.field2.plaintext_columns)
                           + tuple(tuple(14 * v % 26 for v in col) for col in self.field13.plaintext_columns),
                "domains": (2,) * self.dimensions_mod2 + (13,) * self.dimensions_mod13}

    def candidate(self, values2=None, values13=None):
        values2, values13 = self._coordinates(values2, values13)
        plaintext, keys = self.plaintext(values2, values13), self.keys(values2, values13)
        reencrypted = literal_encrypt(plaintext, keys, [s.to_dict() for s in self.stages], self.alphabet)
        if reencrypted != self.ciphertext or any(plaintext[i] != symbol for i, symbol in self.known):
            raise AssertionError("general-layer candidate failed literal re-encryption or cribs")
        return {"plaintext": plaintext, "keys": list(keys), "values_mod2": list(values2), "values_mod13": list(values13),
                "reencrypted_ciphertext": reencrypted, "reencryption_matches": True, "authenticated_solution": False}

    def enumerate_plaintexts(self, max_candidates=676):
        """Return triples (values2, values13, plaintext), once per distinct text.

        Reject the entire request before iteration if the exact family exceeds
        the cap. No arbitrary partial family is silently enumerated.
        """
        self._require_fit()
        _integer(max_candidates, "max_candidates", 1, 1_000_000)
        if self.distinct_plaintext_count > max_candidates:
            raise LayerBudgetExceeded(f"requires {self.distinct_plaintext_count} plaintexts; cap is {max_candidates}")
        return ((a, b, self.plaintext(a, b))
                for a in product(range(2), repeat=self.dimensions_mod2)
                for b in product(range(13), repeat=self.dimensions_mod13))

    def summary(self):
        conflicts = []
        for field in (self.field2, self.field13):
            if not field.feasible:
                conflicts.append({"modulus": field.modulus,
                                  "constraint_weights": [{"constraint_index": i, "weight": value} for i, value in enumerate(field.conflict_weights) if value],
                                  "resultant_residue": field.conflict_residue,
                                  "meaning": "The weighted key coefficients vanish, but the weighted right side is nonzero."})
        result = {"feasible": self.feasible, "alphabet": self.alphabet,
                  "stages": [s.to_dict() for s in self.stages], "key_slots": self.key_slots,
                  "rank_mod2": self.field2.rank, "rank_mod13": self.field13.rank,
                  "dimensions_mod2": self.dimensions_mod2, "dimensions_mod13": self.dimensions_mod13,
                  "distinct_plaintext_count": self.distinct_plaintext_count, "key_assignment_count": self.key_assignment_count,
                  "constraints": [{"plaintext_position_zero_based": i, "ciphertext_position_zero_based": j,
                                   "key_coefficients_mod26": list(row), "rhs_mod26": rhs} for i, j, row, rhs in self.constraints],
                  "conflicts": conflicts, "scalar_work_units": self.work, "bounds": dict(self.bounds),
                  "authenticated_solution": False}
        if self.feasible:
            result.update(prediction_mask=self.prediction_mask(), key_nullity_mod2=self.field2.key_nullity,
                          key_nullity_mod13=self.field13.key_nullity,
                          gauge_dimension_mod2=self.field2.key_nullity - self.dimensions_mod2,
                          gauge_dimension_mod13=self.field13.key_nullity - self.dimensions_mod13)
        return result


def solve_layers(ciphertext, known, stages, alphabet="standard", *, max_key_slots=256,
                 max_matrix_cells=2_000_000, max_operations=20_000_000):
    """Solve an explicit finite layer model with separate F2/F13 certificates.

    known maps zero-based ORIGINAL plaintext positions to letters. Bounds cover
    dense storage estimates and counted scalar algebra work; they are not a
    wall-clock guarantee. A budget exception provides no feasibility verdict.
    """
    alphabet = _alphabet(alphabet)
    if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 4096 or any(c not in alphabet for c in ciphertext):
        raise ValueError("ciphertext must contain 1..4096 uppercase letters")
    if (not isinstance(known, dict) or any(type(i) is not int or not 0 <= i < len(ciphertext)
            or not isinstance(c, str) or len(c) != 1 or c not in alphabet for i, c in known.items())):
        raise ValueError("known must map original zero-based plaintext positions to single letters")
    _integer(max_key_slots, "max_key_slots", 0, 512)
    _integer(max_matrix_cells, "max_matrix_cells", 1, 20_000_000)
    _integer(max_operations, "max_operations", 1, 200_000_000)
    normalized, width = _stages(stages, len(ciphertext), max_key_slots)
    length, count = len(ciphertext), len(known)
    # Conservative peak estimate includes transform, projection bases, RREF
    # rows and proof rows. No unbounded matrix is allocated before this check.
    estimate = 4 * length * (width + 1) + 4 * width * width + 2 * count * (width + count + 1)
    if estimate > max_matrix_cells:
        raise LayerBudgetExceeded(f"estimated {estimate} matrix cells exceed cap {max_matrix_cells}")
    budget = _Budget(max_operations)
    originals = list(range(length))
    signs = [1] * length
    coeff = [[0] * width for _ in range(length)]
    offset = 0
    for stage in normalized:
        if stage.operation == "gather":
            originals = [originals[i] for i in stage.permutation]
            signs = [signs[i] for i in stage.permutation]
            coeff = [coeff[i] for i in stage.permutation]
        else:
            plain_sign, key_sign = SIGNS[stage.cipher]
            budget.charge(length * (width + 1))
            for j in range(length):
                signs[j] *= plain_sign
                coeff[j] = [(plain_sign * value) % 26 for value in coeff[j]]
                coeff[j][offset + j % stage.period] = (coeff[j][offset + j % stage.period] + key_sign) % 26
            offset += stage.period
    original_to_final = [0] * length
    for j, i in enumerate(originals):
        original_to_final[i] = j
    matrix, rhs, constraints = [], [], []
    for i, symbol in sorted(known.items()):
        j = original_to_final[i]
        row = tuple(coeff[j])
        value = (alphabet.index(ciphertext[j]) - signs[j] * alphabet.index(symbol)) % 26
        matrix.append(row)
        rhs.append(value)
        constraints.append((i, j, row, value))
    constant, plain_map = [], []
    for i, j in enumerate(original_to_final):
        constant.append(signs[j] * alphabet.index(ciphertext[j]) % 26)
        plain_map.append(tuple(-signs[j] * value % 26 for value in coeff[j]))
    fields = [_field(matrix, rhs, width, constant, plain_map, p, budget) for p in (2, 13)]
    return GeneralLayerSolution(ciphertext, tuple(sorted(known.items())), normalized, alphabet, width,
                                tuple(constraints), *fields, budget.used,
                                (("max_key_slots", max_key_slots), ("max_matrix_cells", max_matrix_cells),
                                 ("max_operations", max_operations), ("estimated_matrix_cells", estimate)))
