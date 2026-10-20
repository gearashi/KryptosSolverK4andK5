# Exact constraints for two additive substitutions and one transposition

This is a conditional derivation for a precisely specified layer model. It does
not establish that the actual K1, K2, or K3 methods are represented by this model.
Those historical conventions require separate source verification. No K4 or K5
solution is claimed.

## Model and position conventions

Use one fixed 26-symbol alphabet for plaintext, intermediate strings, ciphertext,
and both keys. The first intended alphabet is
`KRYPTOSABCDEFGHIJLMNQUVWXZ`; ordinary `ABCDEFGHIJKLMNOPQRSTUVWXYZ` is another
independent model. Arithmetic on its symbol indexes is in
\(\mathbb Z/26\mathbb Z\). Both substitution layers are additive Vigenere:

\[
(S_A z)_i=z_i+a_{i\bmod p},\qquad
(S_B z)_i=z_i+b_{i\bmod q}.
\]

Indexes are zero-based. Each layer restarts its key at its own position zero.
The declared key lengths are \(p,q\ge1\); a key may have a smaller fundamental
period. Keys are arbitrary symbol strings, with no dictionary restriction or
relationship imposed between them.

Fix a length-preserving bijection of the \(n\) positions. The implementation
uses an **output-to-input** list \(\pi\):

\[
(Tz)_j=z_{\pi(j)}.
\]

Let \(r=\pi^{-1}\). Thus original position \(i\) moves to output position
\(j=r(i)\). This inverse matters: the helper receives `permutation[j] = i`,
while the crib equations below use `j = inverse_permutation[i]`.

Order strings describe encryption from left to right. The first `S` is always
\(S_A\), and the second is \(S_B\).

| Order | Encryption composition | Equation at original position \(i\), with \(j=r(i)\) |
|---|---|---|
| `SST` | first \(S_A\), then \(S_B\), then \(T\) | \(C_j=P_i+a_{i\bmod p}+b_{i\bmod q}\) |
| `STS` | first \(S_A\), then \(T\), then \(S_B\) | \(C_j=P_i+a_{i\bmod p}+b_{j\bmod q}\) |
| `TSS` | first \(T\), then \(S_A\), then \(S_B\) | \(C_j=P_i+a_{j\bmod p}+b_{j\bmod q}\) |

Adjacent substitutions commute under this same-alphabet additive model, so their
two named orders yield the same equation. For separated substitutions, swapping
the identities of the two layers is represented by swapping their declared
periods and key roles in `STS`. If different restrictions are attached to named
keys, that swap must also carry those restrictions.

An unspecified fixed phase offset of either repeating key is already covered
when its symbols are completely unrestricted: rotate that key's labels. A phase
that changes between rows, segments, or stages is a different model.

## Graph equations and a complete feasibility test

For each supplied plaintext crib symbol \(P_i\), form

\[
d_i=C_{r(i)}-P_i\pmod{26}.
\]

The applicable row of the table specifies one phase \(u\) of key A and one
phase \(v\) of key B. Add a labelled edge with equation

\[
a_u+b_v=d_i\pmod{26}.
\]

This is a bipartite multigraph with \(p\) A vertices and \(q\) B vertices.
Parallel edges are retained because different crib positions can demand
different values for the same phase pair.

Define potentials \(h(A_u)=a_u\) and \(h(B_v)=-b_v\). Every edge becomes

\[
h(A_u)-h(B_v)=d_i.
\]

Set one root potential to zero in each connected component and traverse it.
An edge from a known A potential forces \(h(B_v)=h(A_u)-d_i\); an edge from a
known B potential forces \(h(A_u)=h(B_v)+d_i\). If a previously visited vertex
would receive another value, the tree path plus the new edge is a contradiction.
The signed sum of its edge labels is nonzero modulo 26, although telescoping
potentials would require zero. A pair of unequal parallel edges is the shortest
possible witness.

This procedure only adds, subtracts, and compares residues. **It performs no
division**, so the fact that 26 is composite causes no issue.

Conversely, if every edge agrees, the constructed potentials directly give
keys satisfying every crib equation. For every remaining plaintext position,
define its symbol by subtracting the two applicable key values from
\(C_{r(i)}\). This completes the plaintext and reproduces the full ciphertext
under the stated layer composition. Therefore the check is both necessary and
sufficient for **existence of arbitrary keys and a plaintext completion matching
the supplied cribs**, conditional on this fixed permutation, alphabet, order,
and period pair. It does not establish meaningful English outside the cribs.

Every connected component has one independent additive parameter: add \(t\)
to its A key values and subtract \(t\) from its B key values. Include isolated
vertices as components. If the graph is consistent and has \(c\) components,
there are exactly \(26^c\) key pairs of the declared lengths. Each determines
one full plaintext, but multiple pairs can determine the same plaintext.
The helper reports `free_components = c`, not a count of distinct plaintexts.

The graph algorithm costs \(O(p+q+m)\) for \(m\) known plaintext positions;
constructing and re-encrypting one representative adds \(O(n)\).

## Why an arbitrary least-common-multiple key is only a relaxation

When the two substitutions are adjacent, their sum
\(k_i=a_{i\bmod p}+b_{i\bmod q}\) has period dividing
\(L=\operatorname{lcm}(p,q)\). However, an arbitrary \(L\)-periodic sequence
need not decompose into such a sum. Treating it as an unrestricted key can miss
contradictions. For example, \(p=2,q=3\) gives \(L=6\), but the complete
six-position sum sequence has only \(2+3-\gcd(2,3)=4\) independent symbols.
The graph formulation retains these decomposition constraints.

For a full least-common-multiple block, the phase graph has
\(\gcd(p,q)\) components, since a phase pair occurs exactly when the two
residues agree modulo that greatest common divisor. Hence there are
\(26^{p+q-\gcd(p,q)}\) distinct complete sum sequences. This observation is
about the full block; sparse K4 cribs produce their own, usually less connected
graph.

## Witness and representative conventions

`research/layer_constraints.py` exports:

```python
check_layers(ciphertext, known, alphabet, order, permutation, period_a, period_b)
apply_layers(plaintext, key_a, key_b, alphabet, order, permutation)
```

`known` maps zero-based original plaintext indexes to single symbols. Witnesses
report plaintext, ciphertext, and key positions as one-based values. Each
`cycle_edges` row includes its symbol pair, residue, and a coefficient of +1 or
-1. Summing coefficient times residue modulo 26 independently checks the
contradiction. On rejection no representative keys or free-component count is
reported.

On success `keys = {"a": ..., "b": ...}` and `representative_plaintext` are one
arbitrary completion obtained by fixing each graph root to zero. The helper
then encrypts that text by literal stage composition and checks exact equality
with the supplied ciphertext. These representatives must not be presented as
recovered keys or as candidate English without further evaluation.

## Independent tiny hand benchmarks

Use ordinary A-Z indexes, plaintext `ABCDEF`, key A `BC`, key B `DEF`, and
output-to-input permutation `[2, 5, 0, 4, 1, 3]`.

| Order | Hand-derived stages | Ciphertext |
|---|---|---|
| `SST` | `ABCDEF` → `BDDFFH` → `EHIIJM` → `IMEJHI` | `IMEJHI` |
| `STS` | `ABCDEF` → `BDDFFH` → `DHBFDF` → `GLGIHK` | `GLGIHK` |
| `TSS` | `ABCDEF` → `CFAEBD` → `DHBGCF` → `GLGJGK` | `GLGJGK` |

Giving all six plaintext symbols as cribs must be feasible for each row. Each
graph has one connected component. Replacing only the sixth crib `F` by `G`
must produce a nonzero cycle witness for each row. With no cribs, all five key
slots are independent and `free_components` must equal five.

An additional hand graph has edge labels
\(d_{00}=7,d_{10}=11,d_{11}=16,d_{01}=12\). Its signed cycle sum is
\(7-11+16-12=0\); one solution is
\((a_0,a_1,b_0,b_1)=(0,4,7,12)\). Changing only \(d_{01}\) to 13 makes the
sum 25 modulo 26 and is impossible.

A second, more discriminating `STS` vector uses plaintext `ABCDEF`, key A `BE`,
key B `CHL`, and gather permutation `[0, 2, 3, 1, 5, 4]`. Its stages are
`ABCDEF` → `BFDHFJ` → `BDHFJF` → `DKSHQQ`. Full cribs produce one component;
fixing A's first residue to zero gives representative keys `AD` and `DIM`.
Using the inverse permutation `[0, 3, 1, 2, 5, 4]` instead, or treating the
same ciphertext as `SST` or `TSS`, is inconsistent. Changing only the first
ciphertext symbol from `D` to `E` produces a four-edge contradiction witness.

## Boundaries of any resulting exclusion

Rejecting one graph excludes only its fixed alphabet, permutation, layer order,
period pair, and additive stage definitions. Exhausting a recorded finite list
excludes only that list. Additional substitutions, different alphabets between
stages, reverse/additive conventions, feedback keys, nulls, padding, changed
message boundaries, unknown extraction rules, or other permutations remain
outside this model.

Different stage alphabets generally make re-encoding between substitutions
nonlinear in these numeric indexes. Their effects cannot be inserted into the
same graph equations without a separate derivation. A mapping between named
letters and the selected numeric key alphabet must also be specified before
attaching dictionary-key restrictions.

This derivation and its synthetic examples are local mathematical work. The
code imports no Kryptos constants or historical source claims. A scientific run
must separately pin ciphertext, cribs, permutation construction, bounds,
alphabet convention, code version, and output provenance.
