# Factoring crib mappings through arbitrary phase-indexed bijections

This is a broader structural model than repeating additive keys, whether their
alphabets agree or differ. Each phase of each substitution may be an independent
permutation of all 26 uppercase letters. A rejection here therefore excludes
every additive-key alphabet choice inside this model with the same phase
periods, transposition, order, and original crib positions. A fit need not be
implementable by additive keys or by any historical Kryptos convention.

## Equations with correctly oriented second-stage variables

Let \(A_u\) and \(B_v\) be arbitrary bijections on the 26 letters. Stage A is
the first substitution, and stage B the second. Declared phase periods are
\(p,q\). With gather permutation \((Tz)_j=z_{\pi(j)}\), original plaintext
position \(i\) corresponds to output position \(j=\pi^{-1}(i)\).

| Encryption order | A phase \(u\) | B phase \(v\) |
|---|---|---|
| `SST` | \(i\bmod p\) | \(i\bmod q\) |
| `STS` | \(i\bmod p\) | \(j\bmod q\) |
| `TSS` | \(j\bmod p\) | \(j\bmod q\) |

A supplied crib yields

\[
A_u(P_i)=B_v^{-1}(C_j).
\]

Introduce variables \(X_{u,P}=A_u(P)\) and
\(Y_{v,C}=B_v^{-1}(C)\). Each crib asserts equality between one X variable
and one Y variable. The Y variables are **preimages under B**, not forward
B images of ciphertext letters.

For a fixed A phase, different plaintext arguments must have different X
values. For a fixed B phase, different ciphertext arguments must have different
Y values. These injection requirements are the only additional constraints on
the partial bijections.

## Necessity and constructive sufficiency with at most 26 classes

Union the two variables at every crib edge. If an equality class contains
different argument symbols from the same A phase, their required A images are
equal, contradicting injectivity. The same reasoning applies to different
ciphertext symbols in one B phase, using injectivity of \(B_v^{-1}\). An
equality path of crib edges between the two variables is a complete rejection
certificate.

Suppose no such collision occurs and there are at most 26 equality classes.
Assign a distinct alphabet symbol to each class. Within any one A phase,
distinct specified arguments then receive distinct images; within one inverse
B phase, distinct ciphertext arguments receive distinct preimages. Each is a
partial injection between equally sized finite alphabets, so map the unused
arguments bijectively to the unused values. This extends every partial A map
and inverse B map to a full permutation. Inverting the completed inverse B
maps gives the required forward B maps.

Every supplied crib now satisfies its original equation. For each unknown
plaintext position, define

\[
P_i=A_u^{-1}\!\left(B_v^{-1}(C_{\pi^{-1}(i)})\right),
\]

using the phase table. The resulting full plaintext matches the cribs and
encrypts exactly to the supplied ciphertext under literal stage composition.
Thus the collision test is necessary and sufficient **when the number of
classes is at most 26**.

Variables are created only when they occur in a crib edge. Consequently every
class has at least one edge, and the number of classes is at most the number
of supplied crib positions. For the current K4 inputs there are exactly 24
positions, so this constructive sufficiency bound is automatic. No 28-position
crib assumption is made.

When there are more than 26 classes, a collision still proves impossibility.
Without a collision, some distinct classes might safely share intermediate
symbols. Deciding that case requires an additional coloring problem: classes
which contain different arguments of the same phase cannot share a symbol.
The implementation deliberately returns `inconclusive` there rather than
mistaking the failure of the distinct-label construction for impossibility.

## A transitive obstruction missed by phase-pair checks

Take plaintext `ABCB`, ciphertext `XYXY`, gather permutation `[0,3,1,2]`, order
`STS`, and periods \(p=q=2\). All four phase pairs appear exactly once, so a
separate partial-bijection check for each phase pair has no contradiction.
Nevertheless, the four crib edges give

\[
X_{0,A}=Y_{0,X}=X_{1,B}=Y_{1,Y}=X_{0,C}.
\]

This forces A and C to have the same image under \(A_0\), which a bijection
cannot do. In original-position edge order, a certificate is edge IDs
`[0,1,3,2]`. The permutation is not its own inverse, providing a control for
the gather convention as well as the transitive reasoning.

This strengthens an independent-map test for each phase pair because the
factorized two-stage model must reuse the same A and B maps across pairs.
The distinction is structural and does not depend on English scoring or a
chosen numeric alphabet.

## Implementation and result conventions

`arbitrary_layer_constraints.py` exports:

```python
check_arbitrary_layers(ciphertext, known, order, permutation,
                       period_a, period_b)
apply_arbitrary_layers(plaintext, maps_a, maps_b, order, permutation)
self_test()
```

`known` uses zero-based original plaintext indexes. The first S uses A, the
second B. Every returned map is a 26-character string giving outputs for
inputs A through Z, and the list of maps is indexed by phase. The maps are
arbitrary permutations rather than keyword strings.

The result has `status` equal to `feasible`, `infeasible`, or `inconclusive`,
and `feasible` equal to `True`, `False`, or `None`, respectively. It reports
variables, crib constraints, equality classes, and their count. A rejection
includes the conflicting side, phase, distinct symbols, and a path of equality
edges. Variable and edge IDs are zero-based; reported text positions and phases
are one-based.

On success the result includes assigned class symbols, completed forward maps
for both substitutions, a representative plaintext, and exact re-encryption.
The helper directly re-encrypts through the completed maps and permutation and
checks every crib. A representative is a witness of feasibility, not a
candidate claim of meaningful or authentic plaintext. No count of all maps,
keys, or distinct plaintexts is inferred.

## Small hand controls and boundaries

Let A phase 0 swap A/B, A phase 1 swap C/D, B phase 0 swap E/F, and B phase 1
swap G/H, fixing all other symbols. For plaintext `ABCDEF` and gather map
`[0,2,3,1,5,4]`, direct hand composition gives:

| Order | Intermediate stages | Ciphertext |
|---|---|---|
| `SST` | `ABCDEF` → `BBCCEF` → `BBCCFF` → `BCCBFF` | `BCCBFF` |
| `STS` | `ABCDEF` → `BBCCEF` → `BCCBFE` → `BCCBEE` | `BCCBEE` |
| `TSS` | `ABCDEF` → `ACDBFE` → `BDDBFE` → `BDDBEE` | `BDDBEE` |

Full cribs for each row must be feasible. Additional controls cover the
four-edge transitive obstruction, a collision among inverse-B variables, empty
cribs, 26 distinct classes, and 27 collision-free classes. The last example is
reported inconclusive even though its identity mapping is obviously feasible;
it tests the conservative boundary of the implemented method.

The command `python research/arbitrary_layer_constraints.py --self-test`
passed nine small control cases on 2026-10-12. The four-edge path was replayed
against the recorded equality edges, and every positive representative passed
literal re-encryption. No K4 scan or application test was run for this helper
validation.

The helper does no network access, language scoring, broad search, or file
mutation. A later finite K4 scan must retain its exact route family, period
pairs, known letters, input hashes, and independent certificate-verification
scope. Unknown phases, row-dependent resets, padding, nulls, or stage definitions
outside the table remain separate hypotheses.
