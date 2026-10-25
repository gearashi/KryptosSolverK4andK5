"""Compiled exact additive-layer constraints and gauge-free plaintext search.

T(x)[j] = x[permutation[j]]. Both S stages use the same 26-symbol alphabet.
No language assumption enters feasibility or the number of possible plaintexts.
"""
from collections import deque
from dataclasses import dataclass
from itertools import product, islice


@dataclass(frozen=True)
class LayerPlan:
    length: int
    known_positions: tuple
    order: str
    permutation: tuple
    inverse: tuple
    period_a: int
    period_b: int
    pairs: tuple
    edges: tuple
    tree_steps: tuple
    cycle_edges: tuple
    components: tuple
    component_count: int
    full_component_count: int
    free_plaintext_components: tuple

    @property
    def plaintext_dimension(self):
        return len(self.free_plaintext_components)

    def solve(self, ciphertext, known, alphabet="KRYPTOSABCDEFGHIJLMNQUVWXZ"):
        if not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26:
            raise ValueError("alphabet must contain 26 distinct symbols")
        if not isinstance(ciphertext, str) or len(ciphertext) != self.length or any(ch not in alphabet for ch in ciphertext):
            raise ValueError("ciphertext has wrong length or symbols")
        if (not isinstance(known, dict) or any(type(i) is not int for i in known)
                or set(known) != set(self.known_positions)
                or any(not isinstance(ch, str) or len(ch) != 1 or ch not in alphabet for ch in known.values())):
            raise ValueError("known symbols must match the compiled positions")
        index = {ch: i for i, ch in enumerate(alphabet)}
        residues = [(index[ciphertext[self.inverse[i]]] - index[known[i]]) % 26
                    for i in self.known_positions]
        potential = [0] * len(self.components)
        for parent, child, edge_id, sign in self.tree_steps:
            potential[child] = (potential[parent] + sign * residues[edge_id]) % 26
        for edge_id in self.cycle_edges:
            u, v = self.edges[edge_id]
            residual = (potential[u] - potential[v] - residues[edge_id]) % 26
            if residual:
                return {"feasible": False, "conflict_edge": edge_id,
                        "residual_mod_26": residual, "solution": None}
        return {"feasible": True, "conflict_edge": None, "residual_mod_26": 0,
                "solution": LayerSolution(self, ciphertext, alphabet, tuple(potential))}


@dataclass(frozen=True)
class LayerSolution:
    plan: LayerPlan
    ciphertext: str
    alphabet: str
    potential: tuple

    @property
    def distinct_plaintext_count(self):
        return 26 ** self.plan.plaintext_dimension

    def prediction_mask(self):
        representative = self.plaintext(()) if not self.plan.plaintext_dimension else self.plaintext((0,) * self.plan.plaintext_dimension)
        return "".join(ch if self.plan.components[u] == self.plan.components[v] else "?"
                       for ch, (u, v) in zip(representative, self.plan.pairs))

    def _potentials(self, values):
        if len(values) != self.plan.plaintext_dimension or any(type(v) is not int or not 0 <= v < 26 for v in values):
            raise ValueError("one residue 0..25 is required per plaintext freedom")
        shifts = dict(zip(self.plan.free_plaintext_components, values))
        return tuple((h + shifts.get(c, 0)) % 26 for h, c in zip(self.potential, self.plan.components))

    def plaintext(self, values):
        potential = self._potentials(values)
        index = {ch: i for i, ch in enumerate(self.alphabet)}
        return "".join(self.alphabet[(index[self.ciphertext[self.plan.inverse[i]]] - potential[u] + potential[v]) % 26]
                       for i, (u, v) in enumerate(self.plan.pairs))

    def keys(self, values):
        h = self._potentials(values)
        return ("".join(self.alphabet[v] for v in h[:self.plan.period_a]),
                "".join(self.alphabet[-v % 26] for v in h[self.plan.period_a:]))

    def enumerate_plaintexts(self, max_candidates=676):
        """Enumerate each distinct plaintext once, or reject the whole oversized job."""
        if type(max_candidates) is not int or max_candidates < 1:
            raise ValueError("max_candidates must be a positive integer")
        if self.distinct_plaintext_count > max_candidates:
            raise ValueError(f"requires {self.distinct_plaintext_count} candidates; limit is {max_candidates}")
        return ((values, self.plaintext(values))
                for values in product(range(26), repeat=self.plan.plaintext_dimension))


def compile_layer_plan(length, known_positions, order, permutation, period_a, period_b):
    if type(length) is not int or not 1 <= length <= 4096:
        raise ValueError("length must be 1..4096")
    if order not in ("SST", "STS", "TSS"):
        raise ValueError("order must be SST, STS, or TSS")
    if any(type(p) is not int or not 1 <= p <= 256 for p in (period_a, period_b)):
        raise ValueError("periods must be 1..256")
    permutation = tuple(islice(iter(permutation), length + 1))
    if len(permutation) != length or any(type(i) is not int for i in permutation) or sorted(permutation) != list(range(length)):
        raise ValueError("permutation must be a zero-based gather bijection")
    positions = tuple(islice(iter(known_positions), length + 1))
    if any(type(i) is not int or not 0 <= i < length for i in positions) or len(set(positions)) != len(positions):
        raise ValueError("known positions must be distinct zero-based indices")
    positions = tuple(sorted(positions))
    inverse = [0] * length
    for j, i in enumerate(permutation):
        inverse[i] = j
    pairs = tuple(((i if order != "TSS" else j) % period_a,
                   period_a + (i if order == "SST" else j) % period_b)
                  for i, j in enumerate(inverse))
    edges = tuple(pairs[i] for i in positions)
    adjacency = [[] for _ in range(period_a + period_b)]
    for edge_id, (u, v) in enumerate(edges):
        adjacency[u].append((v, edge_id, -1))
        adjacency[v].append((u, edge_id, 1))
    components = [-1] * len(adjacency)
    tree, tree_ids, count = [], set(), 0
    for root in range(len(adjacency)):
        if components[root] != -1:
            continue
        components[root] = count
        count += 1
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for other, edge_id, sign in adjacency[node]:
                if components[other] == -1:
                    components[other] = components[node]
                    tree.append((node, other, edge_id, sign))
                    tree_ids.add(edge_id)
                    queue.append(other)
    # Connect crib components by every text-position edge. A common shift
    # within each resulting component changes no plaintext, so anchor one.
    parents = list(range(count))
    def find(x):
        while parents[x] != x:
            parents[x] = parents[parents[x]]
            x = parents[x]
        return x
    for u, v in pairs:
        a, b = find(components[u]), find(components[v])
        if a != b:
            parents[max(a, b)] = min(a, b)
    anchors = {find(i) for i in range(count)}
    free = tuple(i for i in range(count) if i not in anchors)
    return LayerPlan(length, positions, order, permutation, tuple(inverse), period_a, period_b,
                     pairs, edges, tuple(tree), tuple(i for i in range(len(edges)) if i not in tree_ids),
                     tuple(components), count, len(anchors), free)
