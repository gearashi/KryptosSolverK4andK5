# Alphabet-independent repeated-phase check

Base checkpoint: **K4-20261012-F**. Command: `python research/phase_pair_invariants.py`.

## Contract and proof of necessity

Let each key slot in substitution stage A or B select an arbitrary deterministic bijection of the 26 letters. Neither additive arithmetic nor a particular alphabet ordering is assumed. Each stage's rule repeats with its declared period; stages preserve length. The single fixed transposition uses `T(x)[j] = x[pi[j]]`. For plaintext position `i`, its final ciphertext position is `j = inverse_pi[i]`.

For periods `(a,b)`, the phase pair affecting this path is:

| Encryption order | Phase pair, zero-based |
|---|---|
| SST: A, B, T | `(i % a, i % b)` |
| STS: A, T, B | `(i % a, j % b)` |
| TSS: T, A, B | `(j % a, j % b)` |

If two paths share the same phase pair, they undergo the same composite bijection. Thus their plaintext letters are equal **if and only if** their ciphertext letters are equal. Either unequal outputs for equal inputs (determinism) or equal outputs for unequal inputs (injectivity) rejects that model, independently of substitution alphabets. Unknown starting offsets do not change equality of phase pairs because they relabel all slots consistently.

Only the **29 stored routes**, **three stored orders**, and period pairs **(3,2), (2,3), (10,8), (8,10)** are inspected: **348 models**. Routes come from `research/runs/layers-001/results.json`; K4 and the 24 crib letters come from `kryptos/data.py`. No route regeneration, cipher/key search, language scoring, or application test is performed. All unordered pairs of the known plaintext positions are compared; unknown letters impose no extra conditions here.

## Evidence and interpretation

The bounded run rejected **172 of 348 models** and left **176 passing only this necessary condition**:

| Periods (A, B) | SST rejected / 29 | STS rejected / 29 | TSS rejected / 29 | Total rejected / 87 |
|---|---:|---:|---:|---:|
| (3, 2) | 21 | 23 | 28 | 72 |
| (2, 3) | 21 | 29 | 28 | 78 |
| (10, 8) | 6 | 0 | 4 | 10 |
| (8, 10) | 6 | 2 | 4 | 12 |

The scientific script and the skill's manifest validator were invoked sequentially through `runpy` inside a single Python process. Validation succeeded, with the version 1 provenance limitations noted below.

`research/runs/phase-pairs-001/results.json` records counts by order and period pair, phase-group counts, compared and violating pair counts, and one direct two-position witness for every rejected model. Witnesses contain one-based plaintext/ciphertext positions, the letters, and the common zero-based phase pair. The route table makes their permutation reference explicit. Before/after hashes cover both scientific inputs and the checker itself.

For example, the identity route with SST and periods (3,2) puts plaintext positions 25 and 67 in phase pair (0,0). Their known letters are T and L, while the corresponding ciphertext letters are both V. The same composite bijection cannot map two different inputs to V, so this model is rejected without choosing an alphabet.

Verification includes five small hand cases (both failure directions, a passing case, no cribs, and a non-involutive route), independent symbolic tracking of positions through all three orders, and ungrouped pair enumeration cross-checks. Computation uses one Python process and exact comparisons. The accompanying version 1 manifest records environment, command, runtime, and output hash; it has weaker runner provenance than the existing version 2 checkpoints.

**Passing is only a necessary-condition pass.** It does not show that the phase-pair maps can be factored consistently into shared A-slot and B-slot bijections, or that they come from any fixed substitution alphabets, additive shifts, named keys, or the actual Kryptos method. Models rejected by the older additive checker can pass this weaker invariant. The finite exclusions do not cover different periods, routes, stateful rules, fractionation, or other length-changing operations.

The raw output is the authoritative count record. No interpretation of shortened ENE/BC text changes the 24 literal crib letters used here.
