"""Exact occupied-cell routes and row-plus-column additive crib constraints.

Coordinates describe a chosen text layout, not authenticated encryption rules.
Gather convention: T(text)[j] = text[permutation[j]]. Arithmetic is modulo 26.
"""

from collections import deque
import string


ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}


def k4_cells():
    """Local zero-based K4 coordinates: four rightmost cells, then 3 full rows.

    This reproduces research/check_physical_routes.py. Absolute sculpture row
    numbering is deliberately not asserted. Earlier passages are outside this
    occupied-cell surrogate, not padding or null characters.
    """
    return [(0, 27 + i) for i in range(4)] + [(1 + i // 31, i % 31) for i in range(93)]


def _cells(cells, length=None):
    if not isinstance(cells, (list, tuple)) or not 1 <= len(cells) <= 4096:
        raise ValueError("cells must contain 1 through 4096 coordinate pairs")
    result = []
    for cell in cells:
        if not isinstance(cell, (list, tuple)) or len(cell) != 2:
            raise ValueError("each cell must have a row and column")
        if any(isinstance(v, bool) or not isinstance(v, int) for v in cell):
            raise ValueError("cell coordinates must be integers")
        result.append(tuple(cell))
    if len(set(result)) != len(result) or (length is not None and len(result) != length):
        raise ValueError("cells must be distinct and match text length")
    return result


def coordinate_routes(cells):
    """Finite axis/diagonal/snake scans and rectangle symmetries, plus inverses.

    Each transformed occupied set is read without inventing missing cells.
    Exact duplicate gather permutations retain aliases and are returned once.
    """
    cells = _cells(cells)
    result = {}

    def add(name, permutation):
        inverse = [0] * len(cells)
        for output, source in enumerate(permutation):
            inverse[source] = output
        for suffix, indices in (("forward", permutation), ("inverse", inverse)):
            signature = tuple(indices)
            if signature not in result:
                result[signature] = {"permutation": list(signature), "aliases": []}
            result[signature]["aliases"].append(name + "/" + suffix)

    for axis in ("rows", "columns", "diagonals", "antidiagonals"):
        def axes(cell):
            r, c = cell
            return {"rows": (r, c), "columns": (c, r),
                    "diagonals": (r + c, r), "antidiagonals": (r - c, r)}[axis]
        coordinates = [axes(cell) for cell in cells]
        for reverse_major in (False, True):
            groups = sorted({value[0] for value in coordinates}, reverse=reverse_major)
            for reverse_minor in (False, True):
                for snake in (False, True):
                    order = []
                    for group_number, major in enumerate(groups):
                        reverse = reverse_minor ^ (snake and group_number % 2 == 1)
                        group = [i for i, value in enumerate(coordinates) if value[0] == major]
                        order.extend(sorted(group, key=lambda i: coordinates[i][1], reverse=reverse))
                    add(f"{axis}/major{int(reverse_major)}/minor{int(reverse_minor)}/snake{int(snake)}", order)
    min_r, min_c = min(r for r, c in cells), min(c for r, c in cells)
    local = [(r - min_r, c - min_c) for r, c in cells]
    height, width = max(r for r, c in local) + 1, max(c for r, c in local) + 1
    transforms = {
        "identity": lambda r, c: (r, c),
        "rotate90": lambda r, c: (c, height - 1 - r),
        "rotate180": lambda r, c: (height - 1 - r, width - 1 - c),
        "rotate270": lambda r, c: (width - 1 - c, r),
        "reflect_columns": lambda r, c: (r, width - 1 - c),
        "reflect_rows": lambda r, c: (height - 1 - r, c),
        "transpose": lambda r, c: (c, r),
        "antitranspose": lambda r, c: (width - 1 - c, height - 1 - r),
    }
    for name, transform in transforms.items():
        transformed = [transform(r, c) for r, c in local]
        add("geometry/" + name, sorted(range(len(cells)), key=lambda i: transformed[i]))
    return list(result.values())


def _validate(text, known, cells, permutation, alphabet, row_frame, column_frame, row_shift, column_shift):
    alphabet = ALPHABETS.get(alphabet, alphabet) if isinstance(alphabet, str) else ""
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be standard, kryptos, or an uppercase A-Z permutation")
    if not isinstance(text, str) or not text or any(symbol not in alphabet for symbol in text):
        raise ValueError("text must be nonempty uppercase letters")
    cells = _cells(cells, len(text))
    if not isinstance(permutation, (list, tuple)) or len(permutation) != len(text):
        raise ValueError("permutation must match text length")
    if any(isinstance(i, bool) or not isinstance(i, int) for i in permutation) or set(permutation) != set(range(len(text))):
        raise ValueError("permutation must be a zero-based gather bijection")
    if row_frame not in ("source", "destination") or column_frame not in ("source", "destination"):
        raise ValueError("phase frames must be source or destination")
    if any(isinstance(s, bool) or not isinstance(s, int) for s in (row_shift, column_shift)):
        raise ValueError("phase shifts must be integer cyclic text offsets")
    if not isinstance(known, dict):
        raise ValueError("known must map zero-based plaintext positions to letters")
    for i, symbol in known.items():
        if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(text):
            raise ValueError("known positions must be zero-based and inside the text")
        if not isinstance(symbol, str) or len(symbol) != 1 or symbol not in alphabet:
            raise ValueError("known values must be single alphabet letters")
    inverse = [0] * len(text)
    for j, i in enumerate(permutation):
        inverse[i] = j
    return cells, alphabet, inverse


def encrypt_grid(plaintext, row_keys, column_keys, cells, permutation, *, alphabet="kryptos",
                 row_frame="source", column_frame="source", row_shift=0, column_shift=0):
    """Literal before-route/after-route shifts, independent of graph equations.

    Key dictionaries map coordinate labels to integer shifts in 0..25. The
    coordinate lookup index is (stage_position + shift) modulo text length.
    """
    cells, alphabet, _ = _validate(plaintext, {}, cells, permutation, alphabet, row_frame, column_frame,
                                   row_shift, column_shift)
    for keys, axis in ((row_keys, 0), (column_keys, 1)):
        if not isinstance(keys, dict) or set(keys) != {cell[axis] for cell in cells}:
            raise ValueError("keys must cover exactly the occupied row or column labels")
        if any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < 26 for v in keys.values()):
            raise ValueError("key shifts must be integers 0 through 25")
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    result = plaintext
    for frame in ("source", "destination"):
        if frame == "destination":
            result = "".join(result[i] for i in permutation)
        for axis, keys, chosen_frame, shift in ((0, row_keys, row_frame, row_shift),
                                                (1, column_keys, column_frame, column_shift)):
            if chosen_frame == frame:
                result = "".join(alphabet[(index[symbol] + keys[cells[(position + shift) % len(cells)][axis]]) % 26]
                                 for position, symbol in enumerate(result))
    return result


def _cycle(left, right, closing, parents, edges):
    # Closed walk left->right->tree root->left. Repeated tree edges can cancel.
    walk = [(left, right, closing)]
    node = right
    while parents[node] is not None:
        parent, edge = parents[node]
        walk.append((node, parent, edge))
        node = parent
    left_up = []
    node = left
    while parents[node] is not None:
        parent, edge = parents[node]
        left_up.append((parent, node, edge))
        node = parent
    walk.extend(reversed(left_up))
    certificate = []
    for source, destination, edge_id in walk:
        edge = edges[edge_id]
        coefficient = 1 if source == edge["row_vertex"] else -1
        certificate.append({**edge, "coefficient": coefficient})
    residual = sum(edge["coefficient"] * edge["residue"] for edge in certificate) % 26
    assert residual != 0
    return {"kind": "inconsistent_modular_cycle", "cycle_edges": certificate, "residual_mod_26": residual}


def _component_count(adjacency):
    visited, count = set(), 0
    for root in range(len(adjacency)):
        if root in visited:
            continue
        count += 1
        visited.add(root)
        pending = [root]
        while pending:
            for neighbor in adjacency[pending.pop()]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)
    return count


def check_grid_model(ciphertext, known, cells, permutation, *, alphabet="kryptos",
                     row_frame="source", column_frame="source", row_shift=0, column_shift=0):
    """Exact row-plus-column model; preserve uncertainty beyond one representative.

    With j=inverse(permutation)[i], C[j]=P[i]+R[row phase]+K[column phase].
    Each phase comes from cells[(i or j + its cyclic shift) % text_length].
    All arithmetic uses the same fixed alphabet. No English scoring is used.
    """
    cells, alphabet, inverse = _validate(ciphertext, known, cells, permutation, alphabet, row_frame,
                                         column_frame, row_shift, column_shift)
    row_labels, column_labels = sorted({r for r, c in cells}), sorted({c for r, c in cells})
    row_index = {label: i for i, label in enumerate(row_labels)}
    column_index = {label: len(row_labels) + i for i, label in enumerate(column_labels)}
    vertex_count = len(row_labels) + len(column_labels)
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    phases = []
    full_adjacency = [[] for _ in range(vertex_count)]
    for i, j in enumerate(inverse):
        r = cells[((i if row_frame == "source" else j) + row_shift) % len(cells)][0]
        c = cells[((i if column_frame == "source" else j) + column_shift) % len(cells)][1]
        left, right = row_index[r], column_index[c]
        phases.append((left, right))
        full_adjacency[left].append(right)
        full_adjacency[right].append(left)
    edges, adjacency = [], [[] for _ in range(vertex_count)]
    for i, symbol in sorted(known.items()):
        left, right = phases[i]
        edge_id = len(edges)
        edges.append({"row_vertex": left, "column_vertex": right, "plaintext_position": i + 1,
                      "ciphertext_position": inverse[i] + 1, "residue": (index[ciphertext[inverse[i]]] - index[symbol]) % 26})
        adjacency[left].append(edge_id)
        adjacency[right].append(edge_id)
    potentials, parents, components = [None] * vertex_count, [None] * vertex_count, [None] * vertex_count
    component_count = 0
    for root in range(vertex_count):
        if potentials[root] is not None:
            continue
        potentials[root], components[root] = 0, component_count
        component_count += 1
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for edge_id in adjacency[node]:
                edge = edges[edge_id]
                left, right, residue = edge["row_vertex"], edge["column_vertex"], edge["residue"]
                neighbor = right if node == left else left
                expected = (potentials[node] - residue if node == left else potentials[node] + residue) % 26
                if potentials[neighbor] is None:
                    potentials[neighbor], parents[neighbor], components[neighbor] = expected, (node, edge_id), components[node]
                    queue.append(neighbor)
                elif potentials[neighbor] != expected:
                    return {"feasible": False, "witness": _cycle(left, right, edge_id, parents, edges),
                            "crib_edges": len(edges), "key_slots": vertex_count}
    row_keys = {label: potentials[row_index[label]] for label in row_labels}
    column_keys = {label: -potentials[column_index[label]] % 26 for label in column_labels}
    representative, mask, forced = [], [], []
    for i, (left, right) in enumerate(phases):
        symbol = alphabet[(index[ciphertext[inverse[i]]] - potentials[left] + potentials[right]) % 26]
        fixed = components[left] == components[right]
        representative.append(symbol)
        mask.append(symbol if fixed else "?")
        if fixed:
            forced.append(i + 1)
    representative = "".join(representative)
    assert all(representative[i] == symbol for i, symbol in known.items())
    reencrypted = encrypt_grid(representative, row_keys, column_keys, cells, permutation, alphabet=alphabet,
                               row_frame=row_frame, column_frame=column_frame, row_shift=row_shift, column_shift=column_shift)
    assert reencrypted == ciphertext
    full_components = _component_count(full_adjacency)
    dimension = component_count - full_components
    assert dimension >= 0
    return {"feasible": True, "witness": None, "crib_edges": len(edges), "key_slots": vertex_count,
            "crib_components": component_count, "full_components": full_components,
            "key_assignment_dimension": component_count, "key_assignment_count": 26 ** component_count,
            "plaintext_dimension": dimension, "distinct_plaintext_count": 26 ** dimension,
            "forced_positions": forced, "forced_unknown_positions": [i for i in forced if i - 1 not in known],
            "plaintext_mask": "".join(mask), "representative_plaintext": representative,
            "row_keys": row_keys, "column_keys": column_keys, "component_ids": components,
            "reencrypted_ciphertext": reencrypted, "reencryption_matches": True,
            "warning": "A representative completes the model and cribs; positions marked '?' each allow all 26 letters marginally."}
