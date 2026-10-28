# Independent affine-basis and coverage review

**Verdict: computationally verified only in the stated finite range.** The
mathematical invariants below pass source reconstruction, with no remaining
counterexample found on valid inputs. This review is by the models agent,
independent of the constraint/factor implementations, and uses separately
written finite-set, encryption and score calculations.

## Scope and obligations

The basis object is a valid solver-produced F2/F13 affine pair
`(plaintext_base + C*x, key_base + L*x)`. Every elementary basis operation must
act identically on C and L. The same operation is invertible, so the set of
paired plaintext/key vectors is preserved, not merely its plaintext projection.
The selected-coordinate transformation must additionally shift both bases so
the chosen plaintext positions equal the corresponding new coordinates.

The overlap object is a set of complete, explicitly bounded cipher families or
replayable finite candidate banks. Sharing a score requires the same model
bytes, score mask and plaintext length. The score depends only on plaintext,
so different ciphertexts and recipes may legitimately share it; their separate
literal encryption witnesses still have to pass. A coverage proof is a complete
region top-k certificate, not an unchecked hash or a hard contradiction.

| Obligation | Result |
| --- | --- |
| Sparse elementary basis operations preserve paired images | Passed: operations in `constraint_algebra.py:148` change plaintext columns and key lifts together. 44 paired-image set comparisons include synthetic dense bases, real solved cipher fields and zero-dimensional cases. |
| Selected plaintext coordinates equal search variables | Passed: Gauss-Jordan operations and paired base shifts at `constraint_algebra.py:185`; 2,076 literal coordinate checks. |
| Reconstructed keys encrypt the same plaintext family | Passed: 220 independent literal replays across four real S/T recipes and both basis alternatives. Full paired-field image sets are checked even where CRT replay is capped at 32 samples per alternative. |
| Inclusion/intersection matches the actual affine sets | Passed: every ordered pair of 24 families over each of F2/F13, 1,152 comparisons, including empty intersections, singleton sets and redundant generators. |
| Disjoint ownership preserves union and every alias | Passed literal finite-set ownership and alias checks over both fields. |
| Scoring-mask projection preserves all reconstruction ties | Passed: 26 coordinate vectors become two score representatives while all 26 reconstruction coordinates remain available. |
| Real-family coverage reuses only the same objective | Passed identity review at `constraint_coverage.py:54`; mismatching masks reject. Independent exact scores and ranking match all four finite banks. |
| Subtree proof covers every unpruned child | Passed source review at `constraint_cover_proof.py:74` and 19 whole/subregion/overlap reuse checks. Splits must equal the current propagated domain, and bound exclusions are strict. |
| Imported thresholds cannot be invented by copied candidates | Passed: candidates are feasible, rescored, canonically ranked, and must appear in verified proof leaves (`constraint_cover_proof.py:155`). 24 altered-score, omitted-child, false-conflict and false-bound artifacts reject. |
| Skipping covered regions cannot create false hard nogoods | Passed hook review at `constraint_lab.py:272`: reuse requires singleton assumptions implying the region and returns the non-infeasibility marker. |

For overlapping artifacts, each stores at least the new run's requested k.
Any regional candidate omitted from its regional top-k already has k distinct
better-ranked candidates in that region. The union of stored regional top-k
therefore suffices for the covered union's top-k, including canonical ties.
Uncovered regions are still searched normally. A coverage certificate can save
new decisions while costing more total work after proof reverification.

## Findings resolved before the final run

- General affine coverage originally reported one literal replay per candidate
  but actually performed candidate reconstruction, recipe conversion and final
  verification. It now records each separately and the correct total.
- Explicit candidate banks retained caller-supplied score/authentication fields.
  They now retain the plaintext/recipe inputs, recompute evidence, and explicitly
  set authentication false. The adversarial candidate in this review supplied
  a fake score and authentication flag; neither survives as trusted output.
- Raw affine helper metadata was not validated. A negative prime could produce
  a negative assignment count with an apparent completed result. The public
  helpers now require valid F2/F13 domains, common ambient dimensions, valid
  integer shapes and caps. Negative-prime, mixed-prime and negative-domain
  controls all reject. This was an input-boundary flaw, not a counterexample to
  the valid-domain affine argument.

No production or test source was edited by this reviewer.

## Finite evidence

The reproducible independent script is `research/review_Q_basis_coverage.py`.
The completed v2 record is
`research/runs/release-Q-review-basis-coverage-001/manifest.json`, with its
`result.json`. Before/after input hashes agree and current-source manifest
validation passes.

The real coverage bank contains **26 + 676 + 26 + 1 = 729** independently
enumerated family candidates. Their union contains **702** plaintexts, so **27
score evaluations** are reused. Preparation still enumerates all 729 assignments
and performs **2,185 literal replays**: 728 candidate reconstructions, 728 recipe
conversions and 729 final verifications. This is not a claim of cheaper total
work than every alternative solver.

Audited SHA-256 digests:

- `constraint_algebra.py`: `c89810dfc160b4cfe19b00760debfe6a703474be96f8ae7d5004f1cda1877994`
- `constraint_coverage.py`: `3f533617f9965e69fe2e9ab0f02724c1eb4039db1b957713a8ec1072c2092a1f`
- `constraint_cover_proof.py`: `f8bf59f8d2ac32e3bf5774128e84e46d4f3bc26fefe60283524bfcbaf3d377ce`
- `constraint_lab.py`: `7fe8993d0b8463a482561a8ecd35e8cdc694a3ea2a8be67884926217e972877c`
- `constraint_reuse.py`: `2020e704339a3f9a56397d9bdaaf90c180a8c7f5a2b4d5f37f2ca15670be37fc`

Rerun into a fresh file:

```text
python -B research/review_Q_basis_coverage.py --output research/runs/NEW-DIRECTORY/result.json
```

Use the installed computation-audit manifest validator with `--root` to verify
the saved record. This audit does not establish a globally sparsest basis,
exhaustive coverage of unknown cipher mechanisms, or a Kryptos solution.

## Separate factor boundedness finding

A read-only review found that `factor_advanced.cutset_solve` eagerly materialized
`sorted(combinations(variables, size))` before charging its planning budget.
Many irrelevant unary variables combined with several disjoint cycles could
therefore allocate a huge combination layer before reaching an operation cap.
The factor author replaced this with streaming combinations and a charged
`cutset_candidates` step before each forest check. Static inspection confirms
the eager combinatorial allocation is removed. The author's separate 50-variable,
five-triangle regression is not counted as an independent execution in this
review. Cutset choice remains an exact bounded alternative, without a claim
that the selected cutset minimizes every possible planning cost.
