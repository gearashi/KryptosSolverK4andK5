"""Exact equality constraints for arbitrary phase-indexed substitution maps.

For each crib, A_phase(plaintext) equals B_phase^{-1}(ciphertext). Equality
classes must not identify distinct arguments of the same bijection. When at
most 26 classes remain, distinct symbols construct a complete solution.
Larger collision-free instances return inconclusive, without graph coloring.
"""

from __future__ import annotations

from collections import deque
import string

ALPHABET = string.ascii_uppercase


def _validate(text, known, order, permutation, period_a, period_b):
    if not isinstance(text, str) or not text or any(symbol not in ALPHABET for symbol in text):
        raise ValueError("text must be a nonempty uppercase A-Z string")
    if order not in ("SST", "STS", "TSS"):
        raise ValueError("order must be SST, STS, or TSS")
    if not isinstance(permutation, (list, tuple)) or len(permutation) != len(text):
        raise ValueError("permutation must give one source index per output position")
    if any(isinstance(i, bool) or not isinstance(i, int) for i in permutation) or set(permutation) != set(range(len(text))):
        raise ValueError("permutation must be a bijection of zero-based positions")
    for period in (period_a, period_b):
        if isinstance(period, bool) or not isinstance(period, int) or period < 1:
            raise ValueError("declared map periods must be positive integers")
    if not isinstance(known, dict):
        raise ValueError("known must map original zero-based plaintext positions to symbols")
    for i, symbol in known.items():
        if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(text):
            raise ValueError("known position is outside the original plaintext")
        if not isinstance(symbol, str) or len(symbol) != 1 or symbol not in ALPHABET:
            raise ValueError("known values must be single uppercase A-Z symbols")


def _phases(i, j, order, period_a, period_b):
    if order == "SST":
        return i % period_a, i % period_b
    if order == "STS":
        return i % period_a, j % period_b
    return j % period_a, j % period_b


def apply_arbitrary_layers(plaintext, maps_a, maps_b, order, permutation):
    """Literal encryption; each map lists outputs for inputs A through Z."""
    if not isinstance(maps_a, (list, tuple)) or not isinstance(maps_b, (list, tuple)):
        raise ValueError("phase maps must be lists of permutation strings")
    _validate(plaintext, {}, order, permutation, len(maps_a), len(maps_b))
    if any(not isinstance(mapping, str) or len(mapping) != 26 or set(mapping) != set(ALPHABET)
           for mapping in (*maps_a, *maps_b)):
        raise ValueError("every phase map must be a permutation of A-Z")
    stages = iter((maps_a, maps_b))
    result = plaintext
    for stage in order:
        if stage == "T":
            result = "".join(result[i] for i in permutation)
        else:
            maps = next(stages)
            result = "".join(maps[i % len(maps)][ord(symbol) - 65] for i, symbol in enumerate(result))
    return result


def _equality_path(source, target, adjacency, edges):
    parents = {source: None}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        if node == target:
            break
        for edge_id in adjacency[node]:
            edge = edges[edge_id]
            neighbor = edge["variable_b"] if node == edge["variable_a"] else edge["variable_a"]
            if neighbor not in parents:
                parents[neighbor] = (node, edge_id)
                queue.append(neighbor)
    if target not in parents:
        raise AssertionError("DSU collision has no equality path")
    variable_path, edge_path = [target], []
    node = target
    while parents[node] is not None:
        node, edge_id = parents[node]
        variable_path.append(node)
        edge_path.append(edge_id)
    return list(reversed(variable_path)), list(reversed(edge_path))


def _complete(partial):
    """Extend a partial injection to a permutation deterministically."""
    assert len(set(partial.values())) == len(partial)
    remaining = iter(symbol for symbol in ALPHABET if symbol not in partial.values())
    return "".join(partial[symbol] if symbol in partial else next(remaining) for symbol in ALPHABET)


def _inverse(mapping):
    return "".join(ALPHABET[mapping.index(symbol)] for symbol in ALPHABET)


def check_arbitrary_layers(ciphertext, known, order, permutation, period_a, period_b):
    """Check arbitrary phase-indexed bijections, not just cyclic substitutions.

    known positions are original plaintext indexes, zero-based. Input objects
    are not mutated. In result variables, side a means A_phase(P); side b means
    B_phase^{-1}(C). Map, plaintext, ciphertext, and key-phase positions in
    certificates are one-based; variable and edge IDs remain zero-based.
    """
    _validate(ciphertext, known, order, permutation, period_a, period_b)
    inverse = [0] * len(permutation)
    for output, original in enumerate(permutation):
        inverse[original] = output
    variables, variable_ids, edges, adjacency, parent, rank = [], {}, [], [], [], []

    def variable(side, phase, symbol):
        key = (side, phase, symbol)
        if key not in variable_ids:
            node = len(variables)
            variable_ids[key] = node
            variables.append({"variable_id": node, "side": side, "phase": phase + 1,
                              "argument_symbol": symbol,
                              "meaning": "image" if side == "a" else "preimage"})
            adjacency.append([])
            parent.append(node)
            rank.append(0)
        return variable_ids[key]

    def find(node):
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left, right):
        left, right = find(left), find(right)
        if left == right:
            return
        if rank[left] < rank[right]:
            left, right = right, left
        parent[right] = left
        if rank[left] == rank[right]:
            rank[left] += 1

    for i, plain in sorted(known.items()):
        j = inverse[i]
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        left = variable("a", phase_a, plain)
        right = variable("b", phase_b, ciphertext[j])
        edge_id = len(edges)
        edges.append({"edge_id": edge_id, "variable_a": left, "variable_b": right,
                      "plaintext_position": i + 1, "ciphertext_position": j + 1,
                      "phase_a": phase_a + 1, "phase_b": phase_b + 1,
                      "plaintext_symbol": plain, "ciphertext_symbol": ciphertext[j]})
        adjacency[left].append(edge_id)
        adjacency[right].append(edge_id)
        union(left, right)
    groups = {}
    for node in range(len(variables)):
        groups.setdefault(find(node), []).append(node)
    classes = sorted(groups.values(), key=lambda members: members[0])
    class_of = {node: class_id for class_id, members in enumerate(classes) for node in members}
    assert len(classes) <= len(edges)  # every created variable has an incident crib edge
    result = {
        "status": None, "feasible": None, "equivalence_class_count": len(classes),
        "variables": variables, "constraints": edges,
        "equivalence_classes": [{"class_id": i, "variable_ids": members} for i, members in enumerate(classes)],
        "witness": None, "class_assignments": None, "maps": None,
        "representative_plaintext": None, "reencrypted_ciphertext": None,
        "warning": "This is arbitrary per-phase substitution feasibility, not a keyed-alphabet/cyclic-key solution or a plaintext-uniqueness claim.",
    }
    seen_slot_class = {}
    for node, description in enumerate(variables):
        key = (description["side"], description["phase"], class_of[node])
        if key in seen_slot_class:
            other = seen_slot_class[key]
            assert variables[other]["argument_symbol"] != description["argument_symbol"]
            variable_path, edge_path = _equality_path(other, node, adjacency, edges)
            result.update(status="infeasible", feasible=False, witness={
                "kind": "within_phase_injectivity_collision", "side": description["side"],
                "phase": description["phase"],
                "distinct_symbols": [variables[other]["argument_symbol"], description["argument_symbol"]],
                "variable_ids": [other, node], "variable_path": variable_path, "edge_path": edge_path,
                "interpretation": "Crib equalities force distinct arguments of the same bijection to share an intermediate symbol.",
            })
            return result
        seen_slot_class[key] = node
    if len(classes) > 26:
        result.update(status="inconclusive", reason=(
            "More than 26 equality classes without an injectivity collision. "
            "Classes may share symbols when compatible; no graph-coloring search was performed."
        ))
        return result
    # Globally distinct class labels suffice; equality between different classes
    # is allowed by the model, but not needed when at most 26 classes exist.
    labels = {class_id: ALPHABET[class_id] for class_id in range(len(classes))}
    partial_a = [{} for _ in range(period_a)]
    partial_inverse_b = [{} for _ in range(period_b)]
    for node, description in enumerate(variables):
        partials = partial_a if description["side"] == "a" else partial_inverse_b
        partials[description["phase"] - 1][description["argument_symbol"]] = labels[class_of[node]]
    maps_a = [_complete(partial) for partial in partial_a]
    inverse_b = [_complete(partial) for partial in partial_inverse_b]
    maps_b = [_inverse(mapping) for mapping in inverse_b]
    inverse_a = [_inverse(mapping) for mapping in maps_a]
    plain = []
    for i, j in enumerate(inverse):
        phase_a, phase_b = _phases(i, j, order, period_a, period_b)
        intermediate = inverse_b[phase_b][ord(ciphertext[j]) - 65]
        plain.append(inverse_a[phase_a][ord(intermediate) - 65])
    plain = "".join(plain)
    if any(plain[i] != symbol for i, symbol in known.items()):
        raise AssertionError("representative violates a supplied crib")
    reencrypted = apply_arbitrary_layers(plain, maps_a, maps_b, order, permutation)
    if reencrypted != ciphertext:
        raise AssertionError("literal stage re-encryption failed")
    result.update(status="feasible", feasible=True,
                  class_assignments=[{"class_id": i, "intermediate_symbol": labels[i]} for i in range(len(classes))],
                  maps={"a": maps_a, "b": maps_b},
                  representative_plaintext=plain, reencrypted_ciphertext=reencrypted)
    return result


def self_test():
    maps_a = ["BACDEFGHIJKLMNOPQRSTUVWXYZ", "ABDCEFGHIJKLMNOPQRSTUVWXYZ"]
    maps_b = ["ABCDFEGHIJKLMNOPQRSTUVWXYZ", "ABCDEFHGIJKLMNOPQRSTUVWXYZ"]
    permutation = [0, 2, 3, 1, 5, 4]
    known = dict(enumerate("ABCDEF"))
    passed = 0
    for order, expected in {"SST": "BCCBFF", "STS": "BCCBEE", "TSS": "BDDBEE"}.items():
        assert apply_arbitrary_layers("ABCDEF", maps_a, maps_b, order, permutation) == expected
        result = check_arbitrary_layers(expected, known, order, permutation, 2, 2)
        assert result["status"] == "feasible" and result["feasible"] is True
        assert result["representative_plaintext"] == "ABCDEF"
        assert result["reencrypted_ciphertext"] == expected
        assert all(len(set(mapping)) == 26 for mapping in (*result["maps"]["a"], *result["maps"]["b"]))
        passed += 1
    # All four phase pairs appear once, yet shared intermediate equalities fail.
    transitive = check_arbitrary_layers("XYXY", dict(enumerate("ABCB")), "STS", [0, 3, 1, 2], 2, 2)
    assert len({(edge["phase_a"], edge["phase_b"]) for edge in transitive["constraints"]}) == 4
    assert transitive["status"] == "infeasible" and transitive["feasible"] is False
    witness = transitive["witness"]
    assert witness["side"] == "a" and witness["phase"] == 1 and witness["distinct_symbols"] == ["A", "C"]
    assert witness["edge_path"] == [0, 1, 3, 2]
    for left, right, edge_id in zip(witness["variable_path"], witness["variable_path"][1:], witness["edge_path"]):
        edge = transitive["constraints"][edge_id]
        assert {left, right} == {edge["variable_a"], edge["variable_b"]}
    passed += 1
    # Symmetric inverse-B injection failure: distinct ciphertext preimages merge.
    b_collision = check_arbitrary_layers("AB", dict(enumerate("AA")), "SST", [0, 1], 1, 1)
    assert b_collision["status"] == "infeasible" and b_collision["witness"]["side"] == "b"
    passed += 1
    empty = check_arbitrary_layers("ABCDEF", {}, "STS", permutation, 2, 3)
    assert empty["status"] == "feasible" and empty["equivalence_class_count"] == 0
    assert empty["reencrypted_ciphertext"] == "ABCDEF"
    passed += 1
    boundary = check_arbitrary_layers(ALPHABET, dict(enumerate(ALPHABET)), "STS", list(range(26)), 26, 26)
    assert boundary["equivalence_class_count"] == 26 and boundary["status"] == "feasible"
    passed += 1
    text27 = ALPHABET + "A"
    larger = check_arbitrary_layers(text27, dict(enumerate(text27)), "STS", list(range(27)), 27, 27)
    assert larger["equivalence_class_count"] == 27 and larger["status"] == "inconclusive" and larger["feasible"] is None
    passed += 1
    assert transitive == check_arbitrary_layers("XYXY", dict(enumerate("ABCB")), "STS", [0, 3, 1, 2], 2, 2)
    assert known == dict(enumerate("ABCDEF")) and permutation == [0, 2, 3, 1, 5, 4]
    passed += 1
    return {"passed_cases": passed,
            "scope": "three arbitrary-permutation hand vectors, transitive four-edge conflict, inverse-B conflict, empty cribs, 26/27-class boundary, determinism"}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("use --self-test; bounded research runs should import check_arbitrary_layers")
    print(json.dumps(self_test(), indent=2))
