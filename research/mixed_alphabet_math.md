# Exact constraints when the two substitution alphabets differ

This extends the same-alphabet derivation in `layer_math.md`. It decides only
one fixed pair of alphabet permutations, one gather permutation, one layer
order, and one pair of declared key lengths. No Kryptos source input is built
into the implementation, and a feasible model is not a decipherment claim.

## Stage definitions and transported positions

Let \(A\) and \(B\) each be a permutation of the 26 uppercase letters. The first
substitution reads and writes symbol indexes in \(A\), adding key residue
\(a_u\); the second reads and writes indexes in \(B\), adding residue \(b_v\).
Each key is unrestricted and repeats at its declared length. The letters of
key A are encoded in alphabet A, and the letters of key B in alphabet B.

The gather permutation is \((Tz)_j=z_{\pi(j)}\). Original plaintext position
\(i\) therefore reaches final ciphertext position \(j=\pi^{-1}(i)\). With
periods \(p,q\), the phases are:

| Encryption order | A phase \(u\) | B phase \(v\) |
|---|---|---|
| `SST` | \(i\bmod p\) | \(i\bmod q\) |
| `STS` | \(i\bmod p\) | \(j\bmod q\) |
| `TSS` | \(j\bmod p\) | \(j\bmod q\) |

The first `S` always uses A, the second B. Unlike the common-alphabet case,
adjacent substitutions generally do **not** commute; exchanging their identities
also exchanges alphabets, keys, periods, and associated assumptions.

## One crib is a bijective relation between two key slots

At a known plaintext symbol define

\[
x=\operatorname{idx}_A(P_i),\qquad
c=\operatorname{idx}_B(C_j),\qquad
f(t)=\operatorname{idx}_B(A[t]).
\]

The intermediate letter is \(A[(x+a_u)\bmod26]\). Consequently its second-stage
index is \(f(x+a_u)\), so the exact edge relation is

\[
b_v=c-f(x+a_u)\pmod{26}.
\]

Since \(f\) is a permutation, the reverse implication also determines a unique
value:

\[
a_u=f^{-1}(c-b_v)-x\pmod{26},\qquad
f^{-1}(s)=\operatorname{idx}_A(B[s]).
\]

All additions and arguments of \(f\) are modulo 26. This is generally a
nonlinear relation in the numeric residues. It is not valid to cancel the
alphabet conversion or replace it by a uniform shift without proving that
the chosen alphabets have that property.

## Complete component solver and exact counts

Make a bipartite graph with one vertex for every declared A key slot and every
B key slot, retaining every crib edge. Include isolated slots. In each connected
component, select a root and try its 26 possible residues. Propagate the forward
or reverse bijection across edges. A previously assigned vertex receiving a
different value rejects that root branch.

Every satisfying assignment must have one of the 26 root values. Conversely,
once a root is fixed, connectivity and edge bijectivity force every other
vertex; checking all remaining edges is sufficient. Thus the accepted root
values enumerate **all** key assignments within that component, with no
Cartesian enumeration of complete keys. An isolated slot has all 26 root
values available.

If component \(k\) has \(r_k\) accepted roots, there are exactly
\(\prod_k r_k\) key pairs of the declared lengths. A zero factor means the
specified model is impossible. The count concerns key pairs, not distinct
plaintexts. Different alphabets need not retain the common-alphabet additive
gauge, and neither a positive count nor a count of one indicates authentic
plaintext. No general plaintext-uniqueness conclusion is made.

The propagation work is \(O(26(p+q+m))\), where \(m\) is the number of crib
edges, plus preprocessing and construction of any representative plaintext.
Recording paths for individual rejected branches adds output-dependent work.
No division, primality assumption, language scoring, or numerical tolerance is
used. The caller supplies finite bounds on lengths and the family of models.

## Rejection certificates and representatives

Each rejected branch records its root residue, one inconsistent edge, its
assigned A and B residues, the B residue required by that edge, and paths of
edge IDs from the root to both endpoints. Starting with the root value, direct
symbol conversion along each path independently reproduces the endpoint
values. The closing edge then requires a different B value. If all 26 root
branches fail in a component, these certificates jointly exclude it.

Accepted branches retain all vertex values, so their edges and count can be
checked independently. The deterministic representative chooses the smallest
accepted root value in every component. Decryption at each original position
uses

\[
P_i=A\!\left[
\left(\operatorname{idx}_A\!\left(B[(c-b_v)\bmod26]\right)-a_u\right)
\bmod26\right].
\]

The implementation then re-encrypts the full representative by literal stage
composition and checks both the complete ciphertext and every supplied crib.
The returned strings remain arbitrary mathematical representatives.

## API and certificate coordinates

`mixed_alphabet_constraints.py` exports:

```python
check_mixed_layers(ciphertext, known, alphabet_a, alphabet_b,
                   order, permutation, period_a, period_b)
apply_mixed_layers(plaintext, key_a, key_b, alphabet_a, alphabet_b,
                   order, permutation)
self_test()
```

`known` uses zero-based original plaintext indexes. Key-slot, plaintext, and
ciphertext positions in result records are one-based. Graph `node_id` values
are zero-based: A slots occupy `0..period_a-1`, and B slots follow them.
`edge_id` values index the top-level `constraints` list. The component root
description explicitly includes its key name and one-based key position.

Top-level fields include `feasible`, `root_option_counts`, `total_key_pairs`,
`component_results`, `failed_component_ids`, `keys`,
`representative_plaintext`, and `reencrypted_ciphertext`. Each component stores
accepted root values, complete accepted assignments, and rejected-branch
certificates. All input objects remain unchanged; the helper performs no I/O.

## Small independent hand controls

Use alphabet A `ABCDEFGHIJKLMNOPQRSTUVWXYZ` and alphabet B
`BACDEFGHIJKLMNOPQRSTUVWXYZ`, so the conversion swaps residues 0 and 1 and
fixes the others. This conversion is not a uniform additive shift. Take
plaintext `ABCDEF`, A key `BE`, B key `CHL`, and the non-involutive gather
permutation `[0,2,3,1,5,4]`.

| Order | Hand-derived stages | Ciphertext |
|---|---|---|
| `SST` | `ABCDEF` → `BFDHFJ` → `CMOJMU` → `COJMUM` | `COJMUM` |
| `STS` | `ABCDEF` → `BFDHFJ` → `BDHFJF` → `CKSHQQ` | `CKSHQQ` |
| `TSS` | `ABCDEF` → `ACDBFE` → `BGEFGI` → `CNPHNT` | `CNPHNT` |

With all six plaintext symbols supplied, the `STS` graph has one component
and exactly one accepted root: A slot 1 has residue 1. Its keys are `BE` and
`CHL`. This differs from the same-alphabet control `DKSHQQ`, whose component
has 26 possible roots and representative keys `AD` and `DIM`.

Omitting just plaintext position 3 (zero-based index 2) from the mixed-alphabet
`STS` example leaves one connected component with **two** accepted roots. The
assignments are A residues `[1,4]`, B residues `[2,7,11]`, yielding `ABCDEF`,
and A residues `[20,24]`, B residues `[8,13,18]`, yielding `ABDDEF`. Both
re-encrypt to `CKSHQQ` and satisfy the five supplied symbols. This explicitly
shows why graph connectivity alone no longer implies a unique plaintext.

One failed mixed-alphabet branch can be checked by hand. Let A slot 1 be zero.
The first crib forces B slot 1 to 1. The second forces A slot 2 to 5; the third
forces B slot 2 to 8. The sixth instead requires B slot 2 to
\(16-f(5+5)=6\), a contradiction. The script records such a certificate for
each rejected root and replays the certificates using direct symbol indexing.

A separate impossible control uses plaintext cribs `AAA`, ciphertext `ABC`,
periods `(1,1)`, and gather permutation `[1,2,0]`. The same input letter under
the same pair of key slots cannot yield distinct output letters, so every root
must fail. A no-crib control includes nine isolated slots and must report
\(26^9\) key pairs. These controls require no sculpture data or search.

Running `python research/mixed_alphabet_constraints.py --self-test` passed nine
small control cases and replayed 123 rejected-branch certificates on 2026-10-12.
The non-involutive permutation, alphabet swap, partial crib, and impossible
component are all covered. No K4 scan, language search, or full application test
was performed as part of this implementation check.

## Scope limits

Different alphabet pairs, other permutations, other declared lengths, stage
definitions, feedback, padding, null symbols, resets between rows, or semantic
codebooks are distinct hypotheses. The solver does not authenticate any K3
adaptation to 97 letters or infer K5 material. A later finite scan must preserve
its input hashes, bounds, classifications, and independent verification scope.
