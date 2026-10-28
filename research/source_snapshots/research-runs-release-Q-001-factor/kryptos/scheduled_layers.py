"""Exact shared-key additive layers with explicit, fixed phase schedules.

The pinned general_layers finite-field machinery is reused unchanged. This
module constructs a new matrix with shared columns and provides independent
literal replay. All alphabets in this linear solver must be the same known one.
"""
from dataclasses import dataclass
import re
import string

from .general_layers import (GeneralLayerSolution, LayerBudgetExceeded,
                             _Budget, _field)

ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
SIGNS = {"vigenere": (1, 1), "beaufort": (-1, 1), "variant": (1, -1)}


def alphabet_letters(value):
    if not isinstance(value, str):
        raise ValueError("a known alphabet is required")
    value = ALPHABETS.get(value, value)
    if len(value) != 26 or set(value) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be a known A-Z permutation")
    return value


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _permutation(value, length):
    if (not isinstance(value, (list, tuple)) or len(value) != length
            or any(type(i) is not int for i in value) or sorted(value) != list(range(length))):
        raise ValueError("position map must be an explicit zero-based bijection")
    return tuple(value)


def stage_position_map(length, stages):
    """Map each current position to its source position after declared gathers."""
    _integer(length, "length", 1, 4096)
    if not isinstance(stages, (list, tuple)) or len(stages) > 16:
        raise ValueError("at most16 preceding stages are supported")
    mapping = tuple(range(length))
    for stage in stages:
        if not isinstance(stage, dict):
            raise ValueError("stages must be objects")
        if stage.get("operation") == "gather":
            mapping = tuple(mapping[i] for i in _permutation(stage.get("permutation"), length))
        elif stage.get("operation") != "substitution":
            raise ValueError("only substitutions and gathers have supported position maps")
    return mapping


def make_phase_map(cells, kind, key_length, *, frame="current", stage_to_source=None, offset=0):
    """Fixed occupied-cell schedules, never fitted coordinates.

    row_reset: column-sorted occupied rank within each row, restarting at zero.
    column: rank of the occupied column label among all occupied columns.
    serpentine: global occupied rank in sorted rows, reversing alternate rows.
    Source frame uses cells[stage_to_source[j]]; current frame uses cells[j].
    Missing cells do not consume a phase. Offsets shift the resulting key index.
    """
    _integer(key_length, "key_length", 1, 256)
    if type(offset) is not int:
        raise ValueError("phase offset must be an integer")
    if not isinstance(cells, (list, tuple)) or not 1 <= len(cells) <= 4096:
        raise ValueError("cells must contain1..4096 occupied coordinate pairs")
    occupied = []
    for cell in cells:
        if not isinstance(cell, (list, tuple)) or len(cell) != 2 or any(type(v) is not int for v in cell):
            raise ValueError("occupied coordinates must be integer pairs")
        occupied.append(tuple(cell))
    if len(set(occupied)) != len(occupied):
        raise ValueError("occupied cells must be distinct")
    if frame == "source":
        mapping = _permutation(stage_to_source, len(occupied))
    elif frame == "current" and stage_to_source is None:
        mapping = tuple(range(len(occupied)))
    else:
        raise ValueError("source frame requires a position map; current frame must omit it")
    if kind not in ("row_reset", "column", "serpentine"):
        raise ValueError("schedule kind must be row_reset, column, or serpentine")
    phase = {}
    if kind == "column":
        columns = {c: i for i, c in enumerate(sorted({c for r, c in occupied}))}
        phase = {cell: columns[cell[1]] for cell in occupied}
    else:
        cursor = 0
        for row_number, row in enumerate(sorted({r for r, c in occupied})):
            group = sorted((cell for cell in occupied if cell[0] == row), key=lambda cell: cell[1],
                           reverse=kind == "serpentine" and row_number % 2 == 1)
            for local, cell in enumerate(group):
                phase[cell] = local if kind == "row_reset" else cursor
                cursor += 1
    return [(phase[occupied[i]] + offset) % key_length for i in mapping]


@dataclass(frozen=True)
class ScheduledStage:
    operation: str
    permutation: tuple = ()
    key_id: str = ""
    key_length: int = 0
    cipher: str = ""
    alphabet: str = ""
    phases: tuple = ()

    def to_dict(self):
        if self.operation == "gather":
            return {"operation": "gather", "permutation": list(self.permutation)}
        return {"operation": "substitution", "key_id": self.key_id, "key_length": self.key_length,
                "cipher": self.cipher, "alphabet": self.alphabet, "phase_map": list(self.phases), "offset": 0}


def normalize_stages(length, stages, *, default_alphabet=None, max_key_slots=256):
    """Validate shared letter-key identities and resolve every phase to an index."""
    _integer(length, "length", 1, 4096)
    _integer(max_key_slots, "max_key_slots", 0, 512)
    if not isinstance(stages, (list, tuple)) or not 1 <= len(stages) <= 16:
        raise ValueError("supply1..16 explicit stages")
    known_default = None if default_alphabet is None else alphabet_letters(default_alphabet)
    normalized, layout, slots = [], {}, 0
    for stage in stages:
        if not isinstance(stage, dict):
            raise ValueError("each stage must be an object")
        if stage.get("operation") == "gather":
            if set(stage) != {"operation", "permutation"}:
                raise ValueError("gather needs only its explicit permutation")
            normalized.append(ScheduledStage("gather", _permutation(stage["permutation"], length)))
            continue
        if stage.get("operation") != "substitution" or set(stage) - {"operation", "key_id", "key_length", "cipher", "alphabet", "phase_map", "offset"}:
            raise ValueError("unsupported scheduled stage or field")
        key_id = stage.get("key_id")
        if not isinstance(key_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key_id) is None:
            raise ValueError("key_id must be an explicit1..64-character letter/digit/_.- identifier")
        size = _integer(stage.get("key_length"), "key_length", 1, 256)
        if key_id in layout and layout[key_id][1] != size:
            raise ValueError("a shared key_id must have one consistent key_length")
        if key_id not in layout:
            layout[key_id] = (slots, size)
            slots += size
        if slots > max_key_slots:
            raise LayerBudgetExceeded("shared key-slot budget exceeded")
        cipher = stage.get("cipher", "vigenere")
        if cipher not in SIGNS:
            raise ValueError("cipher must be vigenere, beaufort, or variant")
        alphabet = alphabet_letters(stage.get("alphabet", known_default))
        offset = stage.get("offset", 0)
        if type(offset) is not int:
            raise ValueError("offset must be an integer")
        raw = stage.get("phase_map", [i % size for i in range(length)])
        if (not isinstance(raw, (list, tuple)) or len(raw) != length
                or any(type(v) is not int or not 0 <= v < size for v in raw)):
            raise ValueError("phase_map must supply one key index per current stage position")
        normalized.append(ScheduledStage("substitution", key_id=key_id, key_length=size, cipher=cipher,
                                         alphabet=alphabet, phases=tuple((v + offset) % size for v in raw)))
    return tuple(normalized), tuple((key, start, size) for key, (start, size) in layout.items())


def expanded_recipe(stages, keys_by_id, length):
    result = []
    for stage in stages:
        if stage.operation == "gather":
            result.append({"operation": "gather", "permutation": list(stage.permutation)})
        else:
            key = keys_by_id.get(stage.key_id)
            if not isinstance(key, str) or len(key) != stage.key_length or any(c not in string.ascii_uppercase for c in key):
                raise ValueError("keys_by_id must supply complete letter keys of the declared lengths")
            if len(stage.phases) != length:
                raise ValueError("normalized phase map length differs from the text")
            result.append({"operation": "repeat_substitution", "cipher": stage.cipher, "alphabet": stage.alphabet,
                           "key_pattern": "".join(key[index] for index in stage.phases)})
    return {"schema": "kryptos.expanded-recipe.v1", "stages": result,
            "key_sharing_convention": "identical letter symbols, interpreted in each stage's known alphabet"}


def replay_expanded(plaintext, recipe):
    """Literal equations, separate from the finite-field matrix construction."""
    if not isinstance(plaintext, str) or not plaintext or any(c not in string.ascii_uppercase for c in plaintext):
        raise ValueError("a complete uppercase plaintext is required")
    if not isinstance(recipe, dict) or recipe.get("schema") != "kryptos.expanded-recipe.v1":
        raise ValueError("unsupported expanded recipe")
    stages = recipe.get("stages")
    if not isinstance(stages, list) or not 1 <= len(stages) <= 16:
        raise ValueError("expanded recipe requires1..16 stages")
    text, trace = plaintext, []
    for stage in stages:
        if stage.get("operation") == "gather":
            text = "".join(text[i] for i in _permutation(stage.get("permutation"), len(text)))
        elif stage.get("operation") == "repeat_substitution":
            alphabet = alphabet_letters(stage.get("alphabet"))
            key, cipher = stage.get("key_pattern"), stage.get("cipher")
            if not isinstance(key, str) or len(key) != len(text) or any(c not in alphabet for c in key) or cipher not in SIGNS:
                raise ValueError("expanded substitution needs one complete letter key per text position")
            output = []
            for p, k in zip(text, key):
                p, k = alphabet.index(p), alphabet.index(k)
                value = p + k if cipher == "vigenere" else k - p if cipher == "beaufort" else p - k
                output.append(alphabet[value % 26])
            text = "".join(output)
        else:
            raise ValueError("unsupported expanded operation")
        trace.append(text)
    return {"ciphertext": text, "stage_outputs": trace}


@dataclass(frozen=True)
class ScheduledSolution:
    linear: GeneralLayerSolution
    stages: tuple
    key_layout: tuple
    final_coefficients: tuple
    references: tuple

    def __getattr__(self, name):
        return getattr(self.linear, name)

    def keys(self, values2=None, values13=None):
        a, b = self.linear._coordinates(values2, values13)
        residues = []
        for field, values in zip((self.field2, self.field13), (a, b)):
            residues.append(tuple((base + sum(lift[i] * value for lift, value in zip(field.key_lifts, values))) % field.modulus
                                  for i, base in enumerate(field.key_base)))
        combined = [(13 * x + 14 * y) % 26 for x, y in zip(*residues)]
        return {key: "".join(self.alphabet[v] for v in combined[start:start + size]) for key, start, size in self.key_layout}

    def representative_keys(self):
        return self.keys()

    def plaintext_domains(self):
        self.linear._require_fit()
        result = []
        for i in range(len(self.ciphertext)):
            residues = []
            for field in (self.field2, self.field13):
                residues.append(set(range(field.modulus)) if any(col[i] for col in field.plaintext_columns)
                                else {field.plaintext_base[i]})
            result.append("".join(c for v, c in enumerate(self.alphabet) if v % 2 in residues[0] and v % 13 in residues[1]))
        return result

    def dependency_report(self):
        empty, cancelled = [], []
        for key, start, size in self.key_layout:
            for phase in range(size):
                slot = start + phase
                row = {"key_id": key, "key_position_zero_based": phase, "stage_position_references": self.references[slot]}
                if not self.references[slot]:
                    empty.append(row)
                elif not any(coeff[slot] for coeff in self.final_coefficients):
                    cancelled.append(row)
        return {"unreferenced_key_slots": empty, "structurally_cancelled_key_slots": cancelled,
                "meaning": "Zero coefficient in every final ciphertext equation; this is algebraic cancellation, not a guessed key.",
                "conditional_gauge_dimension_mod2": self.field2.key_nullity - self.dimensions_mod2 if self.feasible else None,
                "conditional_gauge_dimension_mod13": self.field13.key_nullity - self.dimensions_mod13 if self.feasible else None}

    def candidate(self, values2=None, values13=None):
        a, b = self.linear._coordinates(values2, values13)
        text, keys = self.plaintext(a, b), self.keys(a, b)
        recipe = expanded_recipe(self.stages, keys, len(text))
        replay = replay_expanded(text, recipe)
        if replay["ciphertext"] != self.ciphertext or any(text[i] != c for i, c in self.known):
            raise AssertionError("scheduled candidate failed literal replay or cribs")
        return {"plaintext": text, "keys_by_id": keys, "values_mod2": list(a), "values_mod13": list(b),
                "encryption_recipe": recipe, "reencrypted_ciphertext": replay["ciphertext"],
                "stage_outputs": replay["stage_outputs"], "reencryption_matches": True, "authenticated_solution": False}

    def summary(self):
        result = self.linear.summary()
        result.update(stages=[stage.to_dict() for stage in self.stages],
                      key_layout=[{"key_id": key, "slot_start": start, "key_length": size} for key, start, size in self.key_layout],
                      key_sharing_convention="identical letters in one shared known alphabet",
                      key_dependency_report=self.dependency_report())
        if self.feasible:
            result["plaintext_domains"] = self.plaintext_domains()
            result["plaintext_domain_sizes"] = list(map(len, result["plaintext_domains"]))
        return result


def solve_scheduled(ciphertext, known, stages, alphabet="standard", *, max_key_slots=256,
                    max_matrix_cells=2_000_000, max_operations=20_000_000):
    alphabet = alphabet_letters(alphabet)
    if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 4096 or any(c not in alphabet for c in ciphertext):
        raise ValueError("ciphertext must contain1..4096 uppercase letters")
    if not isinstance(known, dict) or any(type(i) is not int or not 0 <= i < len(ciphertext)
            or not isinstance(c, str) or len(c) != 1 or c not in alphabet for i, c in known.items()):
        raise ValueError("known must map original zero-based positions to single letters")
    normalized, layout = normalize_stages(len(ciphertext), stages, default_alphabet=alphabet, max_key_slots=max_key_slots)
    if any(stage.operation == "substitution" and stage.alphabet != alphabet for stage in normalized):
        raise ValueError("mixed known alphabets require mixed_stages; this solver is linear in one shared alphabet")
    width = sum(size for _, _, size in layout)
    n, m = len(ciphertext), len(known)
    _integer(max_matrix_cells, "max_matrix_cells", 1, 20_000_000)
    _integer(max_operations, "max_operations", 1, 200_000_000)
    estimate = 4 * n * (width + 1) + 4 * width * width + 2 * m * (width + m + 1)
    if estimate > max_matrix_cells:
        raise LayerBudgetExceeded("scheduled matrix-cell budget exceeded")
    budget = _Budget(max_operations)
    starts = {key: start for key, start, size in layout}
    originals, signs = list(range(n)), [1] * n
    coefficients, references = [[0] * width for _ in range(n)], [0] * width
    for stage in normalized:
        if stage.operation == "gather":
            originals = [originals[i] for i in stage.permutation]
            signs = [signs[i] for i in stage.permutation]
            coefficients = [coefficients[i] for i in stage.permutation]
        else:
            ps, ks = SIGNS[stage.cipher]
            budget.charge(n * (width + 1))
            for j in range(n):
                slot = starts[stage.key_id] + stage.phases[j]
                references[slot] += 1
                signs[j] *= ps
                coefficients[j] = [(ps * value) % 26 for value in coefficients[j]]
                coefficients[j][slot] = (coefficients[j][slot] + ks) % 26
    inverse = [0] * n
    for j, i in enumerate(originals):
        inverse[i] = j
    matrix, rhs, constraints = [], [], []
    for i, symbol in sorted(known.items()):
        j = inverse[i]
        row, value = tuple(coefficients[j]), (alphabet.index(ciphertext[j]) - signs[j] * alphabet.index(symbol)) % 26
        matrix.append(row)
        rhs.append(value)
        constraints.append((i, j, row, value))
    constant = [signs[j] * alphabet.index(ciphertext[j]) % 26 for j in inverse]
    mapping = [tuple(-signs[j] * value % 26 for value in coefficients[j]) for j in inverse]
    f2, f13 = [_field(matrix, rhs, width, constant, mapping, p, budget) for p in (2, 13)]
    linear = GeneralLayerSolution(ciphertext, tuple(sorted(known.items())), (), alphabet, width, tuple(constraints), f2, f13,
                                  budget.used, (("max_key_slots", max_key_slots), ("max_matrix_cells", max_matrix_cells),
                                                ("max_operations", max_operations), ("estimated_matrix_cells", estimate)))
    return ScheduledSolution(linear, normalized, layout, tuple(tuple(row) for row in coefficients), tuple(references))
