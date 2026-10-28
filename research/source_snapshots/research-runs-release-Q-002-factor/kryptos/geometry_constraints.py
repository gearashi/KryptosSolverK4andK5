"""Finite geometric hypotheses, with explicit domains and counted exact work.

Cells are ordinal coordinates, never inferred physical measurements. A route is
a Hamiltonian path of the supplied orthogonal-neighbour graph. Optional cribs
refer to plaintext obtained by gathering ciphertext and subtracting a repeating
key. Registration offsets are subtracted before that key. Nothing here claims
that Kryptos uses any of these conventions.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json


class GeometryLimit(ValueError):
    """A declared resource bound was reached; no exhaustive verdict follows."""


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _graph(cells):
    if not isinstance(cells, (list, tuple)) or not 1 <= len(cells) <= 256:
        raise ValueError("geometry requires 1..256 explicit occupied cells")
    if any(not isinstance(c, (list, tuple)) or len(c) != 2 or
           any(type(v) is not int for v in c) for c in cells):
        raise ValueError("cells require integer row/column coordinates")
    cells = tuple(tuple(c) for c in cells)
    if len(set(cells)) != len(cells):
        raise ValueError("occupied coordinates must be distinct")
    lookup = {c: i for i, c in enumerate(cells)}
    adjacency = []
    for row, col in cells:
        adjacency.append(tuple(sorted(lookup[c] for c in
                         ((row-1, col), (row+1, col), (row, col-1), (row, col+1)) if c in lookup)))
    return cells, tuple(adjacency)


def _components(adjacency, vertices):
    remaining = set(vertices)
    count = 0
    while remaining:
        count += 1
        todo = [remaining.pop()]
        while todo:
            for nxt in adjacency[todo.pop()]:
                if nxt in remaining:
                    remaining.remove(nxt)
                    todo.append(nxt)
    return count


def _bridge_chain_possible(adjacency, vertices, head, end):
    """Every bridge must be used; its component tree must admit one path.

    Removing bridges contracts the remaining blocks to a tree. A Hamiltonian
    path crosses every tree edge once, so that tree has degree at most two and
    its specified endpoints lie in opposite leaf blocks. This is necessary,
    not sufficient, and is used only on an already connected residual graph.
    """
    entry, low, bridges = {}, {}, set()
    def walk(v, parent):
        entry[v] = low[v] = len(entry)
        for w in adjacency[v]:
            if w not in vertices or w == parent:
                continue
            if w in entry:
                low[v] = min(low[v], entry[w])
            else:
                walk(w, v); low[v] = min(low[v], low[w])
                if low[w] > entry[v]:
                    bridges.add(tuple(sorted((v, w))))
    walk(head, None)
    if len(entry) != len(vertices):
        return False
    if not bridges:
        return True
    labels = {}; label = 0
    for root in sorted(vertices):
        if root in labels:
            continue
        labels[root] = label
        todo = [root]
        while todo:
            current = todo.pop()
            for nxt in adjacency[current]:
                if nxt in vertices and nxt not in labels and tuple(sorted((current, nxt))) not in bridges:
                    labels[nxt] = label; todo.append(nxt)
        label += 1
    degree = defaultdict(int)
    for a, b in bridges:
        degree[labels[a]] += 1; degree[labels[b]] += 1
    if max(degree.values()) > 2 or degree[labels[head]] != 1:
        return False
    return end is None or labels[end] != labels[head] and degree[labels[end]] == 1


def _turn(cells, a, b, c):
    u = (cells[b][0]-cells[a][0], cells[b][1]-cells[a][1])
    v = (cells[c][0]-cells[b][0], cells[c][1]-cells[b][1])
    if u == v:
        return "S"
    if u == (-v[0], -v[1]):
        return "B"
    return "R" if u[0]*v[1]-u[1]*v[0] < 0 else "L"


def learn_turn_grammar(examples, *, source):
    """Freeze observed turns and turn pairs; applying it is a new hypothesis.

    Examples contain their own cells and complete solved routes. This bounded
    order-one grammar is not inferred to govern any other passage.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("training source is required")
    if not isinstance(examples, list) or not 1 <= len(examples) <= 64:
        raise ValueError("supply 1..64 solved training routes")
    turns, pairs, witnesses = set(), set(), []
    for example in examples:
        cells, adjacency = _graph(example["cells"])
        route = example["route"]
        replay_route(cells, route)
        tokens = [_turn(cells, *route[i:i+3]) for i in range(len(route)-2)]
        turns.update(tokens)
        pairs.update(zip(tokens, tokens[1:]))
        witnesses.append({"cells": cells, "route": route, "turns": tokens})
    payload = {"order": 1, "turns": sorted(turns), "pairs": [list(p) for p in sorted(pairs)],
               "source": source, "examples": witnesses}
    payload["sha256"] = sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    payload["interpretation"] = "Caller-selected transfer hypothesis; training fit is not evidence of K4's rule."
    return payload


def replay_route(cells, route, *, start=None, end=None):
    """Independent literal path/bijection check, without solver state."""
    cells, _ = _graph(cells)
    if not isinstance(route, (tuple, list)) or any(type(i) is not int for i in route) or sorted(route) != list(range(len(cells))):
        raise ValueError("route must cover each occupied cell exactly once")
    if start is not None and route[0] != start or end is not None and route[-1] != end:
        raise ValueError("route endpoints disagree")
    for a, b in zip(route, route[1:]):
        if sum(abs(cells[a][j]-cells[b][j]) for j in range(2)) != 1:
            raise ValueError("route crosses a non-neighbour edge")
    return {"verified": True, "full_bijection": True, "convention": "gathered[j]=ciphertext[route[j]]"}


def _automorphisms(cells, start, end, signatures):
    """D4 maps retained only after proving labels and endpoints preserved."""
    row0, col0 = min(c[0] for c in cells), min(c[1] for c in cells)
    normal = tuple((r-row0, c-col0) for r, c in cells)
    lookup = {c: i for i, c in enumerate(normal)}
    maps = set()
    for swap in (False, True):
        for sign_r in (-1, 1):
            for sign_c in (-1, 1):
                raw = [(sign_r*(c if swap else r), sign_c*(r if swap else c)) for r, c in normal]
                low_r, low_c = min(r for r, c in raw), min(c for r, c in raw)
                moved = [(r-low_r, c-low_c) for r, c in raw]
                if set(moved) != set(normal):
                    continue
                mapping = tuple(lookup[c] for c in moved)
                if mapping[start] != start or end is not None and mapping[end] != end:
                    continue
                if all(signatures[i] == signatures[mapping[i]] for i in range(len(cells))):
                    maps.add(mapping)
    return sorted(maps)


def tableau_registrations(cells, tableau, transforms, *, source, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """Compile explicit rigid ordinal registrations to per-cell shift vectors.

    A transform has a signed-permutation 2x2 matrix and integer offset. Missing
    tableau cells invalidate that transform; holes are never filled. No origin,
    measurement or orientation is inferred. Returned vectors feed search_paths.
    """
    cells, _ = _graph(cells)
    if not isinstance(source, str) or not source.strip():
        raise ValueError("registration source is required")
    if not isinstance(alphabet, str) or not 2 <= len(alphabet) <= 64 or len(set(alphabet)) != len(alphabet):
        raise ValueError("distinct registration alphabet symbols required")
    if not isinstance(tableau, list) or not 1 <= len(tableau) <= 4096:
        raise ValueError("tableau must contain 1..4096 explicit cells")
    lookup = {}
    for cell in tableau:
        if not isinstance(cell, dict) or set(cell) != {"row", "column", "symbol"} or type(cell["row"]) is not int or type(cell["column"]) is not int or not isinstance(cell["symbol"], str) or len(cell["symbol"]) != 1 or cell["symbol"] not in alphabet:
            raise ValueError("tableau cells require integer row/column and an alphabet symbol")
        point = (cell["row"], cell["column"])
        if point in lookup:
            raise ValueError("duplicate tableau coordinate")
        lookup[point] = alphabet.index(cell["symbol"])
    if not isinstance(transforms, list) or not 1 <= len(transforms) <= 64:
        raise ValueError("supply 1..64 rigid registration transforms")
    accepted, rejected, mappings = [], [], []
    ids = set()
    for transform in transforms:
        if not isinstance(transform, dict) or set(transform) != {"id", "matrix", "offset"} or not isinstance(transform["id"], str) or not transform["id"] or transform["id"] in ids:
            raise ValueError("transforms need unique id, matrix and offset")
        ids.add(transform["id"])
        matrix, offset = transform["matrix"], transform["offset"]
        if not isinstance(matrix, list) or len(matrix) != 2 or any(not isinstance(r, list) or len(r) != 2 or any(type(v) is not int or v not in (-1, 0, 1) for v in r) for r in matrix):
            raise ValueError("matrix must be a 2x2 signed permutation")
        if any(sum(abs(v) for v in r) != 1 for r in matrix) or any(sum(abs(matrix[r][c]) for r in range(2)) != 1 for c in range(2)):
            raise ValueError("matrix must be a rigid signed permutation")
        if not isinstance(offset, list) or len(offset) != 2 or any(type(v) is not int for v in offset):
            raise ValueError("registration offset must contain two integers")
        points = [(matrix[0][0]*r+matrix[0][1]*c+offset[0], matrix[1][0]*r+matrix[1][1]*c+offset[1]) for r, c in cells]
        missing = [i for i, point in enumerate(points) if point not in lookup]
        if missing:
            rejected.append({"id": transform["id"], "missing_input_indices": missing}); continue
        accepted.append({"id": transform["id"], "offsets": [lookup[p] for p in points], "source": source})
        mappings.append({"id": transform["id"], "transform": transform, "tableau_coordinates": points})
    return {"registrations": accepted, "rejected": rejected, "mappings": mappings,
            "work": {"coordinate_lookups": len(cells)*len(transforms)},
            "interpretation": "Finite rigid ordinal registrations only; source/physical correspondence is a caller-declared hypothesis."}


def search_paths(cells, *, start=0, end=None, connectivity=True, degrees=True,
                 articulation=True, symmetry=False, ciphertext=None, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                 period=1, cribs=None, registrations=None, grammar=None,
                 max_states=200000, max_routes=10000):
    """Exact bounded DFS with topology, crib/key and registration propagation.

    Symmetry returns one route per verified label-preserving geometric orbit;
    aliases are recoverable via the reported automorphisms. All other options
    preserve the labelled route set. Resource overflow raises GeometryLimit.
    """
    cells, adjacency = _graph(cells)
    n = len(cells)
    _integer(start, "start", 0, n-1)
    if end is not None:
        _integer(end, "end", 0, n-1)
        if n > 1 and end == start:
            raise ValueError("distinct endpoints required for a nontrivial path")
    _integer(max_states, "max_states", 1, 2000000)
    _integer(max_routes, "max_routes", 1, 100000)
    _integer(period, "period", 1, 256)
    for name, value in (("connectivity", connectivity), ("degrees", degrees), ("articulation", articulation), ("symmetry", symmetry)):
        if type(value) is not bool:
            raise ValueError(f"{name} must be boolean")
    if not isinstance(alphabet, str) or not 2 <= len(alphabet) <= 64 or len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must have 2..64 distinct symbols")
    if ciphertext is not None and (not isinstance(ciphertext, str) or len(ciphertext) != n or any(c not in alphabet for c in ciphertext)):
        raise ValueError("ciphertext must label every occupied cell")
    cribs = {} if cribs is None else cribs
    if not isinstance(cribs, dict):
        raise ValueError("cribs must map zero-based positions to symbols")
    known = {}
    for position, symbol in cribs.items():
        try:
            p = int(position)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid crib position") from error
        if str(p) != str(position) or not 0 <= p < n or not isinstance(symbol, str) or len(symbol) != 1 or symbol not in alphabet:
            raise ValueError("invalid crib position or symbol")
        known[p] = alphabet.index(symbol)
    if known and ciphertext is None:
        raise ValueError("crib propagation needs ciphertext")
    regs = registrations if registrations is not None else [{"id": "identity", "offsets": [0]*n, "source": "identity registration"}]
    if not isinstance(regs, list) or not 1 <= len(regs) <= 64:
        raise ValueError("registrations must contain 1..64 explicit offset vectors")
    grouped = {}
    for reg in regs:
        if not isinstance(reg, dict) or set(reg) != {"id", "offsets", "source"} or not isinstance(reg["id"], str) or not reg["id"] or not isinstance(reg["source"], str) or not reg["source"].strip():
            raise ValueError("registration requires id, offsets and source")
        offsets = reg["offsets"]
        if not isinstance(offsets, list) or len(offsets) != n or any(type(x) is not int for x in offsets):
            raise ValueError("registration offsets must be integers, one per cell")
        vector = tuple(x % len(alphabet) for x in offsets)
        grouped.setdefault(vector, []).append({"id": reg["id"], "source": reg["source"]})
    if grammar is not None:
        if not isinstance(grammar, dict) or grammar.get("order") != 1 or not isinstance(grammar.get("source"), str):
            raise ValueError("grammar must be an explicitly sourced order-one turn grammar")
        turns = set(grammar.get("turns", [])); pairs = {tuple(p) for p in grammar.get("pairs", [])}
        if not turns <= set("SLRB") or any(len(p) != 2 or not set(p) <= set("SLRB") for p in pairs):
            raise ValueError("invalid turn grammar")
    encoded = tuple(alphabet.index(c) for c in ciphertext) if ciphertext is not None else (0,)*n
    reg_vectors = tuple(grouped)
    signatures = [tuple((encoded[i]-v[i]) % len(alphabet) for v in reg_vectors) for i in range(n)]
    automorphisms = _automorphisms(cells, start, end, signatures) if symmetry and grammar is None else [tuple(range(n))]
    if symmetry and grammar is not None:
        # Reflection can exchange L/R; retaining identity is always exact.
        automorphisms = [tuple(range(n))]
    counters = dict(states=0, decisions=0, complete_routes=0, topology_checks=0,
                    crib_checks=0, registration_checks=0, symmetry_checks=0,
                    connectivity_rejections=0, degree_rejections=0, articulation_rejections=0,
                    crib_rejections=0, grammar_rejections=0, symmetry_rejections=0,
                    bridge_checks=0, bridge_rejections=0,
                    setup_registration_vectors=len(regs), setup_automorphisms=len(automorphisms))
    results = []

    def constrain(position, vertex, regstates):
        if position not in known:
            return regstates
        accepted = []
        for index, key in regstates:
            counters["registration_checks"] += 1
            counters["crib_checks"] += 1
            shift = (encoded[vertex]-reg_vectors[index][vertex]-known[position]) % len(alphabet)
            phase = position % period
            if key[phase] is not None and key[phase] != shift:
                continue
            updated = list(key); updated[phase] = shift
            accepted.append((index, tuple(updated)))
        return tuple(accepted)

    def visit(path, mask, regstates, turntokens):
        counters["states"] += 1
        if counters["states"] > max_states:
            raise GeometryLimit("path state budget reached; no exhaustive result")
        head = path[-1]
        if len(path) == n:
            if end is not None and head != end:
                return
            counters["complete_routes"] += 1
            if len(results) >= max_routes:
                raise GeometryLimit("route output budget reached; no exhaustive result")
            replay_route(cells, path, start=start, end=end)
            results.append({"route": list(path), "registrations": [
                {"aliases": grouped[reg_vectors[i]], "offsets": list(reg_vectors[i]),
                 "key_domains": [[x] if x is not None else list(range(len(alphabet))) for x in key]}
                for i, key in regstates]})
            return
        remaining = {i for i in range(n) if not mask >> i & 1}
        vertices = remaining | {head}
        if connectivity:
            counters["topology_checks"] += 1
            if _components(adjacency, vertices) != 1:
                counters["connectivity_rejections"] += 1; return
        if degrees:
            counters["topology_checks"] += len(vertices)
            deg = {v: sum(w in vertices for w in adjacency[v]) for v in vertices}
            # head is one residual endpoint; at most one other degree-one node.
            leaves = [v for v in remaining if deg[v] < 2]
            if deg[head] < 1 or any(deg[v] == 0 for v in remaining) or len(leaves) > 1 or (end is not None and leaves and leaves[0] != end):
                counters["degree_rejections"] += 1; return
        if articulation:
            for vertex in sorted(vertices):
                counters["topology_checks"] += 1
                allowed = 1 if vertex == head or vertex == end else 2
                if _components(adjacency, vertices-{vertex}) > allowed:
                    counters["articulation_rejections"] += 1; return
            counters["bridge_checks"] += 1
            if not _bridge_chain_possible(adjacency, vertices, head, end):
                counters["bridge_rejections"] += 1; return
        nexts = [i for i in adjacency[head] if i in remaining and (i != end or len(path) == n-1)]
        if len(nexts) > 1:
            counters["decisions"] += 1
        for nxt in nexts:
            newpath = path+(nxt,)
            counters["symmetry_checks"] += len(automorphisms)
            if any(tuple(mapping[i] for i in newpath) < newpath for mapping in automorphisms):
                counters["symmetry_rejections"] += 1; continue
            tokens = turntokens
            if grammar is not None and len(newpath) >= 3:
                token = _turn(cells, *newpath[-3:])
                if token not in turns or tokens and (tokens[-1], token) not in pairs:
                    counters["grammar_rejections"] += 1; continue
                tokens += (token,)
            constrained = constrain(len(path), nxt, regstates)
            if not constrained:
                counters["crib_rejections"] += 1; continue
            visit(newpath, mask | 1 << nxt, constrained, tokens)

    states = tuple((i, (None,)*period) for i in range(len(reg_vectors)))
    visit((start,), 1 << start, constrain(0, start, states), ())
    return {"schema": "kryptos.geometry-search.v1", "complete": True, "routes": results,
            "route_count": len(results), "work": counters, "automorphisms": [list(m) for m in automorphisms],
            "route_scope": "one representative per declared label-preserving orbit" if symmetry else "all labelled paths",
            "conditional_on": "orthogonal Hamiltonian gather, supplied endpoints/grammar/registration and repeating-key convention"}


def frontier_paths(cells, *, start=0, end=None, max_states=200000):
    """Exact edge-frontier transfer DP: count paths and retain one witness.

    State stores only active vertex degrees and component labels. Forgetting a
    vertex checks its final degree. Closing a component before the final edge is
    rejected, so no disconnected cycles/path components can survive.
    """
    cells, adjacency = _graph(cells)
    n = len(cells)
    _integer(start, "start", 0, n-1)
    if end is None:
        raise ValueError("frontier DP needs an explicit end")
    _integer(end, "end", 0, n-1)
    _integer(max_states, "max_states", 1, 2000000)
    if n == 1:
        return {"complete": True, "count": 1, "route": [0], "work": {"states": 1, "edge_transitions": 0}}
    if start == end:
        raise ValueError("endpoints must differ")
    edges = sorted((i, j) for i in range(n) for j in adjacency[i] if i < j)
    if any(not adjacency[i] for i in range(n)):
        return {"complete": True, "count": 0, "route": None, "work": {"states": 1, "edge_transitions": 0}}
    last = {v: max(k for k, e in enumerate(edges) if v in e) for v in range(n)}
    states = {(): (1, ())}
    work = {"states": 1, "edge_transitions": 0, "merged_states": 0, "peak_frontier_states": 1}
    for step, (a, b) in enumerate(edges):
        following = {}
        for key, (count, witness) in states.items():
            base = {v: (degree, component) for v, degree, component in key}
            nextlabel = max((p[1] for p in base.values()), default=-1)+1
            for v in (a, b):
                if v not in base:
                    base[v] = (0, nextlabel); nextlabel += 1
            for include in (False, True):
                work["edge_transitions"] += 1
                if work["edge_transitions"] > max_states:
                    raise GeometryLimit("frontier transition budget reached")
                current = dict(base)
                if include:
                    da, ca = current[a]; db, cb = current[b]
                    if da >= (1 if a in (start, end) else 2) or db >= (1 if b in (start, end) else 2) or ca == cb:
                        continue
                    for v, (degree, comp) in list(current.items()):
                        current[v] = (degree+(v in (a, b)), ca if comp == cb else comp)
                forget = [v for v in current if last[v] == step]
                if any(current[v][0] != (1 if v in (start, end) else 2) for v in forget):
                    continue
                priorcomponents = {c for d, c in current.values()}
                for v in forget:
                    del current[v]
                components = {c for d, c in current.values()}
                closed = priorcomponents-components
                if closed and (step != len(edges)-1 or len(closed) != 1 or current):
                    continue
                names = {}
                canonical = []
                for v, (degree, comp) in sorted(current.items()):
                    names.setdefault(comp, len(names))
                    canonical.append((v, degree, names[comp]))
                state = tuple(canonical)
                chosen = witness+((a, b),) if include else witness
                if state in following:
                    oldcount, oldwitness = following[state]
                    following[state] = (oldcount+count, min(oldwitness, chosen))
                    work["merged_states"] += 1
                else:
                    following[state] = (count, chosen)
        states = following
        work["states"] += len(states)
        work["peak_frontier_states"] = max(work["peak_frontier_states"], len(states))
    count, chosen = states.get((), (0, ()))
    route = None
    if count:
        graph = defaultdict(list)
        for a, b in chosen:
            graph[a].append(b); graph[b].append(a)
        route = [start]
        while len(route) < n:
            choices = [v for v in graph[route[-1]] if v not in route]
            if len(choices) != 1:
                raise AssertionError("invalid DP witness")
            route.append(choices[0])
        replay_route(cells, route, start=start, end=end)
    return {"schema": "kryptos.geometry-frontier.v1", "complete": True, "count": count, "route": route, "work": work,
            "scope": "all labelled orthogonal Hamiltonian paths with the declared endpoints; count and one witness"}


def meet_paths(cells, *, start=0, end=None, max_states=200000, max_routes=10000):
    """Meet-in-the-middle path join, keeping exact visited-cell signatures."""
    cells, adjacency = _graph(cells)
    n = len(cells)
    _integer(start, "start", 0, n-1)
    if end is None:
        raise ValueError("meet search needs an explicit end")
    _integer(end, "end", 0, n-1)
    _integer(max_states, "max_states", 1, 2000000)
    _integer(max_routes, "max_routes", 1, 100000)
    if n == 1:
        return {"complete": True, "routes": [[0]], "work": {"half_states": 1, "join_checks": 0}}
    if start == end:
        raise ValueError("endpoints must differ")
    work = {"half_states": 0, "decisions": 0, "join_checks": 0, "complete_routes": 0}
    def half(origin, forbidden, size):
        found = []
        def visit(path, mask):
            work["half_states"] += 1
            if work["half_states"] > max_states:
                raise GeometryLimit("meet path state budget reached")
            if len(path) == size:
                found.append((path, mask)); return
            choices = [nxt for nxt in adjacency[path[-1]] if nxt != forbidden and not mask >> nxt & 1]
            if len(choices) > 1:
                work["decisions"] += 1
            for nxt in choices:
                visit(path+(nxt,), mask | 1 << nxt)
        visit((origin,), 1 << origin)
        return found
    left = half(start, end, (n+1)//2)
    right = half(end, start, n//2)
    indexed = defaultdict(list)
    for path, mask in right:
        indexed[(mask, path[-1])].append(path)
    allmask = (1 << n)-1
    routes = []
    for path, mask in left:
        for other in adjacency[path[-1]]:
            work["join_checks"] += 1
            if work["join_checks"]+work["half_states"] > max_states:
                raise GeometryLimit("meet join budget reached")
            for tail in indexed.get((allmask ^ mask, other), ()):
                route = path+tail[::-1]
                replay_route(cells, route, start=start, end=end)
                routes.append(list(route)); work["complete_routes"] += 1
                if len(routes) > max_routes:
                    raise GeometryLimit("meet route budget reached")
    return {"schema": "kryptos.geometry-meet.v1", "complete": True, "routes": sorted(routes), "work": work}
