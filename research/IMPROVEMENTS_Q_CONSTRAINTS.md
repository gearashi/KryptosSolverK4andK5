# Phase Q: exact constraint and recipe experiments

These changes implement 36 of the 90 numbered proposals; the recipe grammar
work for 62, 64 and 65 belongs to the separate grammar implementation. The
machine-readable mapping is `phase_Q_constraint_outcomes.json`. Every option
has an explicit finite model and a bounded interface. These are not 36
independent guarantees of better K4 searches.

## Usable cipher paths

`constraint-lab` accepts ordinary finite relation requests or a `method` plus
`parameters`. The affine adapter accepts a real `optimize-plus` request,
materializes bounded n-gram factors, reconstructs keys and literally replays
every retained result. `plaintext_coordinates` and `sparse_basis` are alternative
bases. Ties use plaintext order in this adapter, regardless of the basis.

The `autokey`, `null_padding` and `unknown_alphabet_routes` methods are explicit
conditional hypotheses. They do not infer that Kryptos uses those methods.
Unknown alphabet recovery and `smt` require the optional pinned Z3 dependency
in `requirements-sat.txt`. SMT feasibility reports never silently rank an
ignored score objective.

The existing ranked joint solver has `propagation: relational` and
`score_bound: matching`. Relational propagation retains correlations between
shared phases and route edges. The matching score bound applies to n-gram
windows wholly within individual physical columns; crossing windows keep their
separate certified upper bounds. If no windows qualify or its bounded matching
calculation cannot finish, the ordinary bound remains available.

The campaign hypothesis generator has optional `normalize_affine_families`.
It compares the exact uncribbed plaintext sets for the supplied ciphertext
before creating jobs. Identical subsequent literal cribs preserve equality;
original parameter recipes remain aliases. It does not declare their physical
encryption procedures identical.

`family_cover` evaluates each distinct plaintext once across complete bounded
affine families or explicit nonlinear banks of replayable candidates. It
requires identical model bytes, score mask and text length. Every recipe gets
its own independently replayed witness. This also handles unequal overlapping
families, not only identical family hashes.

## Cross-run proof reuse

The relation solver exports hard conflicts and separate score exclusions in
`learned`. Imported hard clauses are checked by complete literal enumeration
under their assumptions; score exclusions also have their numerical bounds
checked. No hash alone authorizes pruning.

`coverage_proof` constructs a JSON subtree artifact with assumptions, exact
region top-k and a tree of complete splits, hard contradictions and admissible
score bounds. A later relation run supplies one or more artifacts in `coverage`.
The verifier checks all candidate scores and every proof node, including omitted
branch detection, objective/hard-model identity and boundary ties. Verified
candidates seed the new run and the covered region can then be skipped. This
supports separate campaign/run reuse without arbitrary artifact file paths.
It is a bounded proof API, not a claim that all existing campaign scans now
share arbitrary optimizer frontiers.

Proof checking has a cost: `coverage_proof_reverification_nodes`,
`coverage_leaf_reverification`, `coverage_candidate_reverification`, and the
underlying relation/factor checks are recorded. Fewer newly searched decisions
does not imply fewer total complete objective evaluations after revalidation.

## Measured controls and limits

The frozen audit is `python -B research/audit_Q_constraints.py --output <fresh>`.
The canonical owned-process run at `runs/release-Q-001/constraints` completed
with **34 tests passing and none skipped**. Its version 2 manifest validates;
all 88 input hashes agreed before/after and with the immutable
snapshot `source_snapshots/release-Q-001-constraints`. The final suite includes
cross-run coverage and malformed public-affine-input regressions. The audit checks 50 random finite relation
models under four variants, 48 random affine-set pairs, 32 explicit set pairs,
and 12 independent labeled route/key oracles spanning both stage orders, all
three additive equations, and unigram/bigram scoring. The original independent
oracle enumerates literal route/key assignments, not propagated surrogate states.

Concrete development measurements:

| Control | Baseline | Optional method | Additional work |
|---|---:|---:|---|
| Four-variable correlated relation, complete evaluations | 81 | 3 | Tuple-support checks |
| Guarded inconsistent cycle, branch decisions | 38 | 35 with conflict resolution/backjump | Total counted work 843 to 994 |
| Same cycle, branch decisions | 38 | 32 with probing | Total work 843 to 1,979 |
| Same cycle, branch decisions | 38 | 36 with residual reuse | Total work 843 to 1,469 |
| Same cycle, later run with verified deductions | 38 | 30 | 32 proof-reverification assignments; total work 886 |
| Equivalent recipe bank, jobs | 39 | 2 | Symbolic algebra and family canonicalization |
| Two complete equivalent cipher families, objective evaluations | 52 | 26 | 52 final verifications plus 104 internal reconstruction/conversion replays |
| Certified key-variable swap, full candidate checks | 9 | 6 | Orbit construction; every tie reconstructed |
| Cross-run subtree coverage, new branch decisions | 21 | 3 | First proof creation requires 6 decisions; later proof validation checks 7 nodes |

The subtree-coverage control also reduces full objective work: the reference
performs 12 complete evaluations; proof creation performs 4, and the later run
performs 7 complete candidate/leaf reverifications and no newly searched full
evaluations. Total counted work is 157 for the reference versus 27 to create the
proof plus 53 in the later run. Those numbers apply only to this frozen example.

The tiny example gains are not evidence that all 90 proposals should be enabled
together, or that full K4 is tractable. Pair propagation can add many checks.
Table, symmetry, family-cover and finite-relation compilation can be unsuitable
for large domains and fail with a resource limit rather than return a negative
cipher verdict. Some algebra helpers are preparation tools with no independently
measured decision reduction. Their exactness is useful; their runtime value
depends on the subsequent model.

The independent review `review_Q_constraints.md` records a separate finite
oracle audit and an adversarial reading. That review is evidence in its stated
range, not a universal proof or an authenticated Kryptos decipherment.

After this audit, the unrelated factor-lab portfolio dispatch was disabled following its negative result. That file was part of the conservative all-module snapshot but not the exercised constraint dependency path. The canonical historical snapshot is preserved; the final packaged regression suite checks the integrated release.
