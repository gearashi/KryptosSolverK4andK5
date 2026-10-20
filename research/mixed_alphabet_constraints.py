"""Exact finite constraints for two additive layers using different alphabets.

The first S uses alphabet/key A and the second alphabet/key B. Permutations
are gather maps: T(text)[j] = text[permutation[j]]. No Kryptos inputs, scoring,
network access, or searches are imported. Run tiny controls with --self-test.
"""

from __future__ import annotations

from collections import deque
from math import prod
import string


def _validate(text, known, alphabet_a, alphabet_b, order, permutation, period_a, period_b):
    for alphabet in (alphabet_a, alphabet_b):
        if not isinstance(alphabet, str) or len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
            raise ValueError("each alphabet must be a permutation of uppercase A-Z")
    if not isinstance(text, str) or not text or any(symbol not in alphabet_a for symbol in text):
        raise ValueError("text must be a nonempty uppercase A-Z string")
    if order not in ("SST", "STS", "TSS"):
        raise ValueError("order must be SST, STS, or TSS")
    if not isinstance(permutation, (list, tuple)) or len(permutation) != len(text):
        raise ValueError("permutation must contain one source index per output position")
    if any(isinstance(i, bool) or not isinstance(i, int) for i in permutation) or set(permutation) != set(range(len(text))):
        raise ValueError("permutation must be a bijection of zero-based positions")
    if not isinstance(known, dict):
        raise ValueError("known must map original zero-based plaintext positions to symbols")
    for i, symbol in known.items():
        if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(text):
            raise ValueError("crib position is outside the original plaintext")
        if not isinstance(symbol, str) or len(symbol) != 1 or symbol not in alphabet_a:
            raise ValueError("each crib symbol must be one uppercase A-Z letter")
    for period in (period_a, period_b):
        if isinstance(period, bool) or not isinstance(period, int) or period < 1:
            raise ValueError("declared key lengths must be positive integers")


def _phases(i, j, order, period_a, period_b):
    if order == "SST":
        return i % period_a, i % period_b
    if order == "STS":
        return i % period_a, j % period_b
    return j % period_a, j % period_b


def apply_mixed_layers(plaintext, key_a, key_b, alphabet_a, alphabet_b, order, permutation):
    """Literal stage-by-stage encryption, independent of the graph equations."""
    if not isinstance(key_a, str) or not isinstance(key_b, str):
        raise ValueError("keys must be strings")
    _validate(plaintext, {}, alphabet_a, alphabet_b, order, permutation, len(key_a), len(key_b))
    if any(symbol not in alphabet_a for symbol in key_a + key_b):
        raise ValueError("keys must contain uppercase A-Z letters")
    substitutions = iter(((alphabet_a, key_a), (alphabet_b, key_b)))
    result = plaintext
    for stage in order:
        if stage == "T":
            result = "".join(result[source] for source in permutation)
        else:
            alphabet, key = next(substitutions)
            index = {symbol: i for i, symbol in enumerate(alphabet)}
            result = "".join(alphabet[(index[symbol] + index[key[i % len(key)]]) % 26]
                             for i, symbol in enumerate(result))
    return result


def _node_description(node, period_a):
    return {"node_id": node, "key": "a" if node < period_a else "b",
            "position": node + 1 if node < period_a else node - period_a + 1}


def _path(node, parents):
    path = []
    while parents[node] is not None:
        node, edge_id = parents[node]
        path.append(edge_id)
    return list(reversed(path))


def _propagate(root, root_value, adjacency, edges, conversion, inverse_conversion):
    """Propagate actual key residues, returning one exact branch certificate."""
    values, parents = {root: root_value}, {root: None}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for edge_id in adjacency[node]:
            edge = edges[edge_id]
            left, right = edge["node_a"], edge["node_b"]
            x, c = edge["plaintext_index_a"], edge["ciphertext_index_b"]
            if node == left:
                neighbor = right
                expected = (c - conversion[(x + values[left]) % 26]) % 26
            else:
                neighbor = left
                expected = (inverse_conversion[(c - values[right]) % 26] - x) % 26
            if neighbor not in values:
                values[neighbor] = expected
                parents[neighbor] = (node, edge_id)
                queue.append(neighbor)
            elif values[neighbor] != expected:
                required_b = (c - conversion[(x + values[left]) % 26]) % 26
                assert required_b != values[right]
                return None, {
                    "edge_id": edge_id, "a_value": values[left], "b_value": values[right],
                    "required_b_value": required_b,
                    "path_to_a": _path(left, parents), "path_to_b": _path(right, parents),
                }
    return values, None


def check_mixed_layers(ciphertext, known, alphabet_a, alphabet_b, order, permutation, period_a, period_b):
    """Exactly decide this fixed mixed-alphabet model's crib consistency.

    Every connected component has at most 26 candidate assignments: choose its
    root residue and propagate bijective edge relations. A component's surviving
    root count is exact, includes isolated slots, and need not be 0 or 26.
    total_key_pairs counts key pairs, not distinct plaintexts or credible solves.
    All inputs are read-only; keys may have smaller fundamental periods than
    their declared lengths. Phase zero is the beginning of each stage.
    """
    _validate(ciphertext, known, alphabet_a, alphabet_b, order, permutation, period_a, period_b)
    index_a = {symbol: i for i, symbol in enumerate(alphabet_a)}
    index_b = {symbol: i for i, symbol in enumerate(alphabet_b)}
    conversion = [index_b[symbol] for symbol in alphabet_a]
    inverse_conversion = [index_a[symbol] for symbol in alphabet_b]
    inverse_permutation = [0] * len(permutation)
    for output, original in enumerate(permutation):
        inverse_permutation[original] = output
    count = period_a + period_b
    edges, adjacency = [], [[] for _ in range(count)]
    for i, symbol in sorted(known.items()):
        j = inverse_permutation[i]
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        edge_id = len(edges)
        edge = {
            "edge_id": edge_id, "node_a": phase_a, "node_b": period_a + phase_b,
            "plaintext_position": i + 1, "ciphertext_position": j + 1,
            "key_a_position": phase_a + 1, "key_b_position": phase_b + 1,
            "plaintext_symbol": symbol, "ciphertext_symbol": ciphertext[j],
            "plaintext_index_a": index_a[symbol], "ciphertext_index_b": index_b[ciphertext[j]],
        }
        edges.append(edge)
        adjacency[edge["node_a"]].append(edge_id)
        adjacency[edge["node_b"]].append(edge_id)
    seen, components, representative_values = set(), [], {}
    for root in range(count):
        if root in seen:
            continue
        vertices, edge_ids = [], set()
        queue = deque([root])
        seen.add(root)
        while queue:
            node = queue.popleft()
            vertices.append(node)
            for edge_id in adjacency[node]:
                edge_ids.add(edge_id)
                edge = edges[edge_id]
                neighbor = edge["node_b"] if node == edge["node_a"] else edge["node_a"]
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        vertices.sort()
        accepted, assignments, rejected = [], [], []
        for root_value in range(26):
            values, conflict = _propagate(root, root_value, adjacency, edges, conversion, inverse_conversion)
            if conflict is not None:
                rejected.append({"root_value": root_value, "conflict": conflict})
            else:
                assert set(values) == set(vertices)
                accepted.append(root_value)
                assignments.append({"root_value": root_value, "values": [[node, values[node]] for node in vertices]})
                if len(accepted) == 1:
                    representative_values.update(values)
        components.append({
            "component_id": len(components), "root": _node_description(root, period_a),
            "vertices": [_node_description(node, period_a) for node in vertices],
            "edge_ids": sorted(edge_ids), "root_option_count": len(accepted),
            "accepted_root_values": accepted, "accepted_assignments": assignments,
            "rejected_branches": rejected,
        })
    option_counts = [component["root_option_count"] for component in components]
    result = {
        "feasible": all(option_counts), "constraints": edges, "component_results": components,
        "root_option_counts": option_counts, "total_key_pairs": prod(option_counts),
        "failed_component_ids": [row["component_id"] for row in components if not row["root_option_count"]],
        "keys": None, "representative_plaintext": None, "reencrypted_ciphertext": None,
        "warning": "Counts describe arbitrary key pairs fitting the cribs; they do not measure plaintext uniqueness or solution confidence.",
    }
    if not result["feasible"]:
        return result
    a = [representative_values[node] for node in range(period_a)]
    b = [representative_values[period_a + node] for node in range(period_b)]
    keys = {"a": "".join(alphabet_a[value] for value in a),
            "b": "".join(alphabet_b[value] for value in b)}
    plaintext = []
    for i, j in enumerate(inverse_permutation):
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        intermediate = alphabet_b[(index_b[ciphertext[j]] - b[phase_b]) % 26]
        plaintext.append(alphabet_a[(index_a[intermediate] - a[phase_a]) % 26])
    plaintext = "".join(plaintext)
    if any(plaintext[i] != symbol for i, symbol in known.items()):
        raise AssertionError("representative violates the cribs")
    reencrypted = apply_mixed_layers(plaintext, keys["a"], keys["b"], alphabet_a, alphabet_b, order, permutation)
    if reencrypted != ciphertext:
        raise AssertionError("literal stage re-encryption failed")
    result.update(keys=keys, representative_plaintext=plaintext, reencrypted_ciphertext=reencrypted)
    return result


def _verify_branch_certificate(component, branch, edges, alphabet_a, alphabet_b):
    """Small-control certificate replay using direct symbol lookup, not tables."""
    root = component["root"]["node_id"]
    root_value = branch["root_value"]
    conflict = branch["conflict"]

    def trace(path):
        node, value = root, root_value
        for edge_id in path:
            edge = edges[edge_id]
            x, c = edge["plaintext_index_a"], edge["ciphertext_index_b"]
            if node == edge["node_a"]:
                intermediate = alphabet_a[(x + value) % 26]
                node, value = edge["node_b"], (c - alphabet_b.index(intermediate)) % 26
            elif node == edge["node_b"]:
                intermediate = alphabet_b[(c - value) % 26]
                node, value = edge["node_a"], (alphabet_a.index(intermediate) - x) % 26
            else:
                raise AssertionError("certificate path is not contiguous")
        return node, value

    edge = edges[conflict["edge_id"]]
    assert trace(conflict["path_to_a"]) == (edge["node_a"], conflict["a_value"])
    assert trace(conflict["path_to_b"]) == (edge["node_b"], conflict["b_value"])
    actual_intermediate = alphabet_a[(edge["plaintext_index_a"] + conflict["a_value"]) % 26]
    required_b = (edge["ciphertext_index_b"] - alphabet_b.index(actual_intermediate)) % 26
    assert required_b == conflict["required_b_value"] != conflict["b_value"]


def self_test():
    standard, swapped = string.ascii_uppercase, "BACDEFGHIJKLMNOPQRSTUVWXYZ"
    permutation = [0, 2, 3, 1, 5, 4]  # not its own inverse
    known = dict(enumerate("ABCDEF"))
    hand_vectors = {"SST": "COJMUM", "STS": "CKSHQQ", "TSS": "CNPHNT"}
    passed = certificates = 0
    for order, ciphertext in hand_vectors.items():
        assert apply_mixed_layers("ABCDEF", "BE", "CHL", standard, swapped, order, permutation) == ciphertext
        result = check_mixed_layers(ciphertext, known, standard, swapped, order, permutation, 2, 3)
        assert result["feasible"] and result["representative_plaintext"] == "ABCDEF"
        assert result["reencrypted_ciphertext"] == ciphertext
        assert len(result["component_results"]) == 1
        assert 1 in result["component_results"][0]["accepted_root_values"]
        for component in result["component_results"]:
            for branch in component["rejected_branches"]:
                _verify_branch_certificate(component, branch, result["constraints"], standard, swapped)
                certificates += 1
        passed += 1
    # Hand-derived unique-root example; nonlinear re-encoding removes the gauge.
    mixed = check_mixed_layers("CKSHQQ", known, standard, swapped, "STS", permutation, 2, 3)
    assert mixed["root_option_counts"] == [1] and mixed["total_key_pairs"] == 1
    assert mixed["component_results"][0]["accepted_root_values"] == [1]
    assert mixed["keys"] == {"a": "BE", "b": "CHL"}
    passed += 1
    # Omitting only plaintext position 3 leaves two roots and two plaintexts.
    partial_known = {i: symbol for i, symbol in known.items() if i != 2}
    partial = check_mixed_layers("CKSHQQ", partial_known, standard, swapped, "STS", permutation, 2, 3)
    assert partial["root_option_counts"] == [2] and partial["total_key_pairs"] == 2
    assert partial["component_results"][0]["accepted_root_values"] == [1, 20]
    expected_assignments = {1: ([1, 4, 2, 7, 11], "ABCDEF"),
                            20: ([20, 24, 8, 13, 18], "ABDDEF")}
    for assignment in partial["component_results"][0]["accepted_assignments"]:
        expected, expected_plaintext = expected_assignments[assignment["root_value"]]
        assert assignment["values"] == list(map(list, enumerate(expected)))
        key_a = "".join(standard[value] for value in expected[:2])
        key_b = "".join(swapped[value] for value in expected[2:])
        assert apply_mixed_layers(expected_plaintext, key_a, key_b, standard, swapped, "STS", permutation) == "CKSHQQ"
        assert all(expected_plaintext[i] == symbol for i, symbol in partial_known.items())
    for branch in partial["component_results"][0]["rejected_branches"]:
        _verify_branch_certificate(partial["component_results"][0], branch, partial["constraints"], standard, swapped)
        certificates += 1
    passed += 1
    # Same-alphabet control recovers the ordinary 26-value gauge component.
    same = check_mixed_layers("DKSHQQ", known, standard, standard, "STS", permutation, 2, 3)
    assert same["root_option_counts"] == [26] and same["total_key_pairs"] == 26
    assert same["keys"] == {"a": "AD", "b": "DIM"}
    passed += 1
    # Equal plaintexts at a repeated slot pair cannot produce unequal ciphertexts.
    impossible = check_mixed_layers("ABC", dict(enumerate("AAA")), standard, swapped,
                                    "STS", [1, 2, 0], 1, 1)
    assert not impossible["feasible"] and impossible["root_option_counts"] == [0]
    assert impossible["total_key_pairs"] == 0
    assert len(impossible["component_results"][0]["rejected_branches"]) == 26
    for branch in impossible["component_results"][0]["rejected_branches"]:
        _verify_branch_certificate(impossible["component_results"][0], branch,
                                   impossible["constraints"], standard, swapped)
        certificates += 1
    passed += 1
    isolated = check_mixed_layers("ABCDEF", {}, standard, swapped, "STS", permutation, 4, 5)
    assert isolated["root_option_counts"] == [26] * 9 and isolated["total_key_pairs"] == 26**9
    assert isolated["reencrypted_ciphertext"] == "ABCDEF"
    passed += 1
    # Determinism and input immutability, including exact branch certificates.
    assert mixed == check_mixed_layers("CKSHQQ", known, standard, swapped, "STS", permutation, 2, 3)
    assert known == dict(enumerate("ABCDEF")) and permutation == [0, 2, 3, 1, 5, 4]
    passed += 1
    return {"passed_cases": passed, "replayed_rejected_branch_certificates": certificates,
            "scope": "hand-derived different-alphabet vectors, same-alphabet gauge, unique and multiple roots, impossible component, isolated slots, deterministic repeat"}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("use --self-test; bounded research runs should import check_mixed_layers")
    print(json.dumps(self_test(), indent=2))
