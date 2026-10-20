"""Independent, single-process replay of mixed-001's finite certificates.

Run: python research/audit_mixed_results.py
No solver imports or new cipher search. Original letters drive every replay.
"""
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from math import prod
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ["kryptos/data.py", "research/runs/mixed-001/results.json",
          "research/runs/mixed-001/manifest.json", "research/audit_mixed_results.py"]
OUTPUT = "research/audit_mixed_results.json"
ALPHABETS = {"standard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}
STAGES = {"SST": "ABT", "STS": "ATB", "TSS": "TAB"}


def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def reconstruct(cipher, known, permutation, order, pa, pb, A, B):
    # Track original positions and phases through actual stage order; do not
    # reuse the solver's closed-form phase-index equations.
    tokens = [{"source": i} for i in range(len(cipher))]
    for stage in STAGES[order]:
        if stage == "T":
            tokens = [tokens[i] for i in permutation]
        else:
            period = pa if stage == "A" else pb
            for position, token in enumerate(tokens):
                token[stage] = position % period
    locations = {token["source"]: (j, token) for j, token in enumerate(tokens)}
    edges = []
    for eid, (i, letter) in enumerate(sorted(known.items())):
        j, token = locations[i]
        u, v = token["A"], token["B"]
        edges.append({"edge_id": eid, "node_a": u, "node_b": pa + v,
                      "plaintext_position": i + 1, "ciphertext_position": j + 1,
                      "key_a_position": u + 1, "key_b_position": v + 1,
                      "plaintext_symbol": letter, "ciphertext_symbol": cipher[j],
                      "plaintext_index_a": A.index(letter), "ciphertext_index_b": B.index(cipher[j])})
    return edges


def cross(edge, node, value, A, B):
    p, c = edge["plaintext_symbol"], edge["ciphertext_symbol"]
    if node == edge["node_a"]:
        middle = A[(A.index(p) + value) % 26]
        return edge["node_b"], (B.index(c) - B.index(middle)) % 26
    assert node == edge["node_b"], "Discontinuous certificate path"
    middle = B[(B.index(c) - value) % 26]
    return edge["node_a"], (A.index(middle) - A.index(p)) % 26


def replay(path, root, value, target, edges, allowed_edges, A, B):
    node, seen = root, {root}
    for eid in path:
        assert type(eid) is int and eid in allowed_edges
        node, value = cross(edges[eid], node, value, A, B)
        assert node not in seen, "Root-to-endpoint path is not simple"
        seen.add(node)
    assert node == target
    return value


def main():
    started, timer = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    before = {p: digest(p) for p in INPUTS}
    data = {}
    for stmt in ast.parse((ROOT / INPUTS[0]).read_text(encoding="utf-8")).body:
        if isinstance(stmt, ast.Assign):
            for name in stmt.targets:
                if isinstance(name, ast.Name) and name.id in {"K4_CIPHERTEXT", "K4_CRIBS"}:
                    data[name.id] = ast.literal_eval(stmt.value)
    cipher = data["K4_CIPHERTEXT"]
    known = {crib["start"] - 1 + k: c for crib in data["K4_CRIBS"] for k, c in enumerate(crib["text"])}
    assert len(cipher) == 97 and len(known) == 24
    stored = json.loads((ROOT / INPUTS[1]).read_text(encoding="utf-8"))
    original_manifest = json.loads((ROOT / INPUTS[2]).read_text(encoding="utf-8"))
    pinned = {item["path"]: item["sha256"] for item in original_manifest["input_artifacts"] + original_manifest["outputs"]}
    assert before[INPUTS[0]] == pinned[INPUTS[0]] and before[INPUTS[1]] == pinned[INPUTS[1]]
    assert stored["alphabet_definitions"] == ALPHABETS
    pairs = {(3, 2), (2, 3), (10, 8), (8, 10)}
    assert {tuple(x) for x in stored["period_pairs"]} == pairs
    expected_models = {(a, b, p, q) for a in ALPHABETS for b in ALPHABETS for p, q in pairs}
    counts, root_counts, summaries, routes = Counter(models=0, fits=0, contradictions=0), Counter(), {}, {}

    for record in stored["records"]:
        assert time.perf_counter() - timer < 20, "Audit exceeded its cooperative 20-second bound"
        permutation = tuple(i - 1 for i in record["source_positions_one_based"])
        assert sorted(permutation) == list(range(97))
        order = record["order"]
        assert order in STAGES and order not in routes.setdefault(permutation, set())
        routes[permutation].add(order)
        seen_models = set()
        for model in record["models"]:
            an, bn, pa, pb = (model[k] for k in ("alphabet_a", "alphabet_b", "period_a", "period_b"))
            identity = an, bn, pa, pb
            assert identity in expected_models and identity not in seen_models
            seen_models.add(identity)
            A, B, result = ALPHABETS[an], ALPHABETS[bn], model["result"]
            edges = reconstruct(cipher, known, permutation, order, pa, pb, A, B)
            assert edges == result["constraints"], "Original-symbol/position reconstruction differs"
            counts["edges_reconstructed"] += len(edges)
            neighbors = [set() for _ in range(pa + pb)]
            for edge in edges:
                u, v = edge["node_a"], edge["node_b"]
                neighbors[u].add(v); neighbors[v].add(u)
            remaining, components = set(range(pa + pb)), set()
            while remaining:
                stack, visited = [min(remaining)], set()
                while stack:
                    u = stack.pop()
                    if u in visited: continue
                    visited.add(u); stack.extend(neighbors[u] - visited)
                remaining -= visited; components.add(frozenset(visited))

            seen_components, component_ids, option_counts, failures = set(), set(), [], []
            for component in result["component_results"]:
                cid = component["component_id"]
                assert cid not in component_ids
                component_ids.add(cid)
                vertex_ids = [item["node_id"] for item in component["vertices"]]
                vertices = frozenset(vertex_ids)
                assert len(vertex_ids) == len(vertices) and vertices in components and vertices not in seen_components
                seen_components.add(vertices)
                for item in component["vertices"] + [component["root"]]:
                    node = item["node_id"]
                    assert node in vertices and item == {"node_id": node, "key": "a" if node < pa else "b", "position": node + 1 if node < pa else node - pa + 1}
                root = component["root"]["node_id"]
                edge_ids = {e["edge_id"] for e in edges if e["node_a"] in vertices}
                assert all(edges[eid]["node_b"] in vertices for eid in edge_ids)
                assert len(component["edge_ids"]) == len(edge_ids) and set(component["edge_ids"]) == edge_ids
                accepted = component["accepted_root_values"]
                rejected = [branch["root_value"] for branch in component["rejected_branches"]]
                assert all(type(v) is int and 0 <= v < 26 for v in accepted + rejected)
                assert len(set(accepted)) == len(accepted) and len(set(rejected)) == len(rejected)
                assert set(accepted).isdisjoint(rejected) and set(accepted + rejected) == set(range(26))
                assert component["root_option_count"] == len(accepted) != 25
                assignments = component["accepted_assignments"]
                assert len(assignments) == len(accepted) and {x["root_value"] for x in assignments} == set(accepted)
                for assignment in assignments:
                    values = dict(assignment["values"])
                    assert len(values) == len(assignment["values"]) and set(values) == vertices
                    assert all(type(v) is int and 0 <= v < 26 for v in values.values())
                    assert values[root] == assignment["root_value"]
                    for eid in edge_ids:
                        e = edges[eid]
                        assert cross(e, e["node_a"], values[e["node_a"]], A, B)[1] == values[e["node_b"]]
                        counts["accepted_edge_checks"] += 1
                    counts["accepted_component_assignments"] += 1
                for branch in component["rejected_branches"]:
                    conflict = branch["conflict"]
                    eid = conflict["edge_id"]
                    assert eid in edge_ids
                    edge = edges[eid]
                    av = replay(conflict["path_to_a"], root, branch["root_value"], edge["node_a"], edges, edge_ids, A, B)
                    bv = replay(conflict["path_to_b"], root, branch["root_value"], edge["node_b"], edges, edge_ids, A, B)
                    required = cross(edge, edge["node_a"], av, A, B)[1]
                    assert (av, bv, required) == (conflict["a_value"], conflict["b_value"], conflict["required_b_value"])
                    assert required != bv
                    counts["rejected_root_certificates"] += 1
                    counts["path_edges_replayed"] += len(conflict["path_to_a"]) + len(conflict["path_to_b"])
                if len(edge_ids) == len(vertices) - 1: assert len(accepted) == 26
                root_counts[len(accepted)] += 1; option_counts.append(len(accepted))
                if not accepted: failures.append(cid)
                counts["components"] += 1
            assert seen_components == components
            assert component_ids == set(range(len(components)))
            assert option_counts == result["root_option_counts"]
            assert prod(option_counts) == result["total_key_pairs"]
            assert bool(prod(option_counts)) == result["feasible"]
            assert failures == result["failed_component_ids"]
            counts["models"] += 1
            counts["fits" if result["feasible"] else "contradictions"] += 1
            signature = f"{an}/{bn}:{order}:({pa},{pb})"
            summary = summaries.setdefault(signature, Counter(models=0, fits=0, contradictions=0))
            summary["models"] += 1; summary["fits" if result["feasible"] else "contradictions"] += 1
            if not result["feasible"]:
                assert all(result[k] is None for k in ("keys", "representative_plaintext", "reencrypted_ciphertext"))
        assert seen_models == expected_models
    assert len(routes) == 29 and all(orders == set(STAGES) for orders in routes.values())
    assert {k: dict(v) for k, v in summaries.items()} == stored["summary"]
    assert counts["models"] == stored["models"] == 1392
    assert counts["contradictions"] == stored["contradictions"] == 1392 and stored["fits"] == counts["fits"] == 0
    after = {p: digest(p) for p in INPUTS}
    assert before == after, "Audit inputs changed during execution"
    runtime = time.perf_counter() - timer
    assert runtime < 20
    output = {"checkpoint": "K4-20261012-G", "started_at": started, "runtime_seconds": runtime,
              "input_hashes_before": before, "input_hashes_after": after, "counts": dict(counts),
              "component_root_count_histogram": {str(k): v for k, v in sorted(root_counts.items())},
              "all_model_classifications_verified": True, "solver_imported_or_rerun": False,
              "method": "Literal source-position tracking through A/B/T; original-symbol edge reconstruction; independently discovered connected components; direct symbol-index certificate path replay; full accepted-assignment edge checks.",
              "conclusion": "All 1392 recorded models are infeasible under their stated alphabet/period/route/order assumptions; every rejected component root has a valid contradiction certificate.",
              "non_claims": ["No general K4 or arbitrary-alphabet exclusion.", "The stored permutations are validated as permutations; their historical construction is outside this audit.", "No claim about full-plaintext uniqueness or solution confidence.", "The original scan's separate benchmark and regression execution claims were not rerun."]}
    (ROOT / OUTPUT).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    manifest = {"schema_version": 2, "claim_id": "K4-20261012-G-independent-certificate-audit",
                "repository": {"commit": "unavailable", "dirty": True},
                "command": [sys.executable, "research/audit_mixed_results.py"],
                "environment": {"software": [{"name": "Python", "version": platform.python_version()}], "hardware": platform.machine()},
                "mathematics": {"assertion_tested": output["conclusion"], "coefficient_domain": "Exact symbol permutations and integers modulo 26", "conventions": "1-based stored positions; literal stage tracking with zero-based gather permutation; independent A/B phase namespaces.", "inputs": INPUTS, "bounds": {"models": 1392, "cribs_per_model": 24, "root_values_per_component": 26, "workers": 1, "cooperative_deadline_seconds": 20}, "non_claims": output["non_claims"]},
                "randomness": {"used": False, "generator": "none", "seed": None},
                "run": {"started_at": started, "runtime_seconds": runtime, "exit_status": 0, "status": "completed", "resource_limits": {"memory_bytes": None, "cpu_seconds": None, "max_cores": None, "max_threads": 1}, "resource_note": "Single-threaded stdlib code; cooperative 20-second deadline, no OS memory or CPU limit."},
                "input_artifacts": [{"path": p, "sha256": before[p], "sha256_after": after[p]} for p in INPUTS],
                "execution_artifacts": INPUTS, "declared_results": [OUTPUT],
                "outputs": [{"path": OUTPUT, "kind": "result", "sha256": digest(OUTPUT)}],
                "checks": ["Original-symbol and literal-position reconstruction", "Complete component partition", "Every accepted assignment satisfies every component edge", "Every rejected root's endpoint paths and closing-edge contradiction replay", "Complete 0..25 root partition", "Component counts, products and all model summaries", "No component has exactly 25 roots", "Before/after hashes unchanged"],
                "result": output["conclusion"], "residual_risks": output["non_claims"] + ["Manifest is produced by the audit process, not an external supervisor."]}
    (ROOT / "research/audit_mixed_results.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"counts": dict(counts), "component_root_count_histogram": output["component_root_count_histogram"], "runtime_seconds": runtime, "audit": OUTPUT}))


if __name__ == "__main__":
    main()
