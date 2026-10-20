"""Exact crib constraints for two additive substitutions and one permutation.

No search, language scoring, networking, or app imports. All arithmetic is
modulo 26. The permutation convention is T(text)[j] = text[permutation[j]].
Run the tiny, independent hand-vector checks with:
    python research/layer_constraints.py --self-test
"""

from __future__ import annotations

from collections import deque


def _validate(ciphertext, known, alphabet, order, permutation, period_a, period_b):
    if not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26:
        raise ValueError("alphabet must contain exactly 26 distinct symbols")
    if not isinstance(ciphertext, str) or not ciphertext or any(c not in alphabet for c in ciphertext):
        raise ValueError("ciphertext must be a nonempty string in the stated alphabet")
    if order not in ("SST", "STS", "TSS"):
        raise ValueError("order must be SST, STS, or TSS; substitutions are A then B")
    n = len(ciphertext)
    if not isinstance(permutation, (list, tuple)) or len(permutation) != n:
        raise ValueError("permutation must have one output-to-input index per symbol")
    if any(isinstance(i, bool) or not isinstance(i, int) for i in permutation) or sorted(permutation) != list(range(n)):
        raise ValueError("permutation must be a bijection of zero-based text positions")
    if not isinstance(known, dict):
        raise ValueError("known must map zero-based original plaintext positions to symbols")
    for i, value in known.items():
        if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < n:
            raise ValueError("known plaintext positions must be zero-based and inside the text")
        if not isinstance(value, str) or len(value) != 1 or value not in alphabet:
            raise ValueError("known plaintext values must be single alphabet symbols")
    for name, period in (("period_a", period_a), ("period_b", period_b)):
        if isinstance(period, bool) or not isinstance(period, int) or period < 1:
            raise ValueError(f"{name} must be a positive integer")


def apply_layers(plaintext, key_a, key_b, alphabet, order, permutation):
    """Encrypt by literal stage composition; used to check a representative."""
    _validate(plaintext, {}, alphabet, order, permutation, len(key_a), len(key_b))
    if any(value not in alphabet for value in key_a + key_b):
        raise ValueError("keys must use the stated alphabet")
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    result = plaintext
    next_key = iter((key_a, key_b))
    for stage in order:
        if stage == "T":
            result = "".join(result[i] for i in permutation)
        else:
            key = next(next_key)
            result = "".join(alphabet[(index[value] + index[key[i % len(key)]]) % 26]
                             for i, value in enumerate(result))
    return result


def _phases(i, j, order, period_a, period_b):
    if order == "SST":
        return i % period_a, i % period_b
    if order == "STS":
        return i % period_a, j % period_b
    return j % period_a, j % period_b


def _cycle_witness(left, right, closing_id, parents, edges, potentials):
    # The tree path from A to B telescopes to potential[A] - potential[B].
    left_path, left_ancestors = [], {left: 0}
    node = left
    while parents[node] is not None:
        parent, edge_id = parents[node]
        left_path.append((node, parent, edge_id))
        node = parent
        left_ancestors[node] = len(left_path)
    right_path = []
    node = right
    while node not in left_ancestors:
        parent, edge_id = parents[node]
        right_path.append((node, parent, edge_id))
        node = parent
    path = left_path[:left_ancestors[node]]
    path += [(parent, child, edge_id) for child, parent, edge_id in reversed(right_path)]
    cycle = []
    for source, destination, edge_id in path:
        edge = edges[edge_id]
        coefficient = 1 if source == edge["a_vertex"] else -1
        cycle.append({**_public_edge(edge), "coefficient": coefficient})
    closing = edges[closing_id]
    cycle.append({**_public_edge(closing), "coefficient": -1})
    implied = (potentials[left] - potentials[right]) % 26
    residual = (implied - closing["residue"]) % 26
    assert sum(edge["coefficient"] * edge["residue"] for edge in cycle) % 26 == residual
    return {
        "kind": "inconsistent_modular_cycle", "cycle_edges": cycle,
        "required_residue": closing["residue"], "implied_residue": implied,
        "residual_mod_26": residual,
        "interpretation": "The displayed signed sum must be 0 modulo 26 but is nonzero.",
    }


def _public_edge(edge):
    return {name: value for name, value in edge.items() if name not in ("a_vertex", "b_vertex")}


def check_layers(ciphertext, known, alphabet, order, permutation, period_a, period_b):
    """Decide crib consistency for this exact pair of additive key periods.

    ``known`` maps zero-based ORIGINAL plaintext positions to symbols. The
    first S uses key A; the second uses B. Period means a declared repeating
    key length, permitting a smaller fundamental period. No key words or
    statistical restrictions are assumed. ``free_components`` includes unused
    key slots. Success returns one representative completion, not a solution
    claim, with literal stage-by-stage re-encryption checked independently of
    the graph equations. Inputs are never modified.
    """
    _validate(ciphertext, known, alphabet, order, permutation, period_a, period_b)
    index = {symbol: i for i, symbol in enumerate(alphabet)}
    inverse = [0] * len(permutation)
    for output, original in enumerate(permutation):
        inverse[original] = output
    count = period_a + period_b
    edges, adjacency = [], [[] for _ in range(count)]
    for i, plaintext in sorted(known.items()):
        j = inverse[i]
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        edge = {
            "a_vertex": phase_a, "b_vertex": period_a + phase_b,
            "plaintext_position": i + 1, "ciphertext_position": j + 1,
            "key_a_position": phase_a + 1, "key_b_position": phase_b + 1,
            "plaintext_symbol": plaintext, "ciphertext_symbol": ciphertext[j],
            "residue": (index[ciphertext[j]] - index[plaintext]) % 26,
        }
        edge_id = len(edges)
        edges.append(edge)
        adjacency[edge["a_vertex"]].append(edge_id)
        adjacency[edge["b_vertex"]].append(edge_id)
    # h(A)=key_A and h(B)=-key_B, hence h(A)-h(B)=edge residue.
    potentials = [None] * count
    parents = [None] * count
    components = 0
    for root in range(count):
        if potentials[root] is not None:
            continue
        components += 1
        potentials[root] = 0
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for edge_id in adjacency[node]:
                edge = edges[edge_id]
                left, right, residue = edge["a_vertex"], edge["b_vertex"], edge["residue"]
                neighbor = right if node == left else left
                expected = (potentials[node] - residue if node == left else potentials[node] + residue) % 26
                if potentials[neighbor] is None:
                    potentials[neighbor] = expected
                    parents[neighbor] = (node, edge_id)
                    queue.append(neighbor)
                elif potentials[neighbor] != expected:
                    return {
                        "feasible": False,
                        "witness": _cycle_witness(left, right, edge_id, parents, edges, potentials),
                        "keys": None, "free_components": None,
                        "representative_plaintext": None, "reencrypted_ciphertext": None,
                    }
    values_a = potentials[:period_a]
    values_b = [(-value) % 26 for value in potentials[period_a:]]
    keys = {"a": "".join(alphabet[value] for value in values_a),
            "b": "".join(alphabet[value] for value in values_b)}
    plaintext = []
    for i, j in enumerate(inverse):
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        plaintext.append(alphabet[(index[ciphertext[j]] - values_a[phase_a] - values_b[phase_b]) % 26])
    plaintext = "".join(plaintext)
    if any(plaintext[i] != symbol for i, symbol in known.items()):
        raise AssertionError("internal error: graph representative violates a supplied crib")
    reencrypted = apply_layers(plaintext, keys["a"], keys["b"], alphabet, order, permutation)
    if reencrypted != ciphertext:
        raise AssertionError("internal error: literal layer composition did not reproduce ciphertext")
    return {
        "feasible": True, "witness": None, "keys": keys,
        "free_components": components, "representative_plaintext": plaintext,
        "reencrypted_ciphertext": reencrypted,
        "warning": "Representative keys and plaintext complete the stated cribs; they are not a decipherment claim.",
    }


def self_test():
    """Hand-derived tiny vectors, including contradictions and empty cribs."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    permutation = [2, 5, 0, 4, 1, 3]
    plain, key_a, key_b = "ABCDEF", "BC", "DEF"
    # Independently worked stage values are documented in layer_math.md.
    expected = {"SST": "IMEJHI", "STS": "GLGIHK", "TSS": "GLGJGK"}
    checks = 0
    for order, ciphertext in expected.items():
        assert apply_layers(plain, key_a, key_b, alphabet, order, permutation) == ciphertext
        known = dict(enumerate(plain))
        result = check_layers(ciphertext, known, alphabet, order, permutation, 2, 3)
        assert result["feasible"] and result["representative_plaintext"] == plain
        assert result["reencrypted_ciphertext"] == ciphertext
        assert result["free_components"] == 1
        assert known == dict(enumerate(plain)) and permutation == [2, 5, 0, 4, 1, 3]
        checks += 1
        bad = {**known, 5: "G"}
        rejected = check_layers(ciphertext, bad, alphabet, order, permutation, 2, 3)
        assert not rejected["feasible"]
        witness = rejected["witness"]
        assert sum(edge["coefficient"] * edge["residue"] for edge in witness["cycle_edges"]) % 26 != 0
        checks += 1
        empty = check_layers(ciphertext, {}, alphabet, order, permutation, 2, 3)
        assert empty["feasible"] and empty["free_components"] == 5
        assert empty["reencrypted_ciphertext"] == ciphertext
        checks += 1
    # A parallel-edge contradiction does not require a longer graph cycle.
    result = check_layers("HLQN", dict(enumerate("AAAA")), alphabet, "SST", [0, 1, 2, 3], 2, 2)
    assert not result["feasible"]  # duplicate phase-pairs demand 7 vs16 and 11 vs13
    checks += 1
    # A distinct hand vector catches gather/scatter and inner-phase confusion.
    permutation = [0, 2, 3, 1, 5, 4]
    known = dict(enumerate("ABCDEF"))
    assert apply_layers("ABCDEF", "BE", "CHL", alphabet, "STS", permutation) == "DKSHQQ"
    result = check_layers("DKSHQQ", known, alphabet, "STS", permutation, 2, 3)
    assert result["feasible"] and result["free_components"] == 1
    assert result["keys"] == {"a": "AD", "b": "DIM"}
    assert result["representative_plaintext"] == "ABCDEF"
    checks += 1
    wrong_inverse = [0, 3, 1, 2, 5, 4]
    assert not check_layers("DKSHQQ", known, alphabet, "STS", wrong_inverse, 2, 3)["feasible"]
    checks += 1
    for wrong_order in ("SST", "TSS"):
        assert not check_layers("DKSHQQ", known, alphabet, wrong_order, permutation, 2, 3)["feasible"]
        checks += 1
    bad = check_layers("EKSHQQ", known, alphabet, "STS", permutation, 2, 3)
    assert not bad["feasible"] and len(bad["witness"]["cycle_edges"]) == 4
    checks += 1
    return {"passed_cases": checks, "scope": "hand vectors for three orders; crib/ciphertext contradictions; gather/scatter and phase checks; empty cribs"}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
    else:
        parser.error("use --self-test; bounded scientific runs should import check_layers")
