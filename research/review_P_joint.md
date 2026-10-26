# Independent P1–5 joint-search review

**Claim.** For the declared finite whole-column route/repeating-key model, the
five optional reductions preserve distinct-plaintext top-k, exact integer scores
and the least labelled route/key representative of each retained plaintext.
Finite cutoffs preserve the unresolved obligations for subsequent continuation.

**Primary verdict: conditional on a named input — an intact checkpoint produced
by the reviewed implementation, or a fresh search.** Within the input contracts
below, no unresolved correctness defect was found. This is a source-level
argument plus a separately implemented finite oracle, not a machine-checked
universal proof or evidence of a Kryptos decipherment.

The sources agent reviewed code separately from the P1–5 implementer, with shared
project context and access to the author's explanations. This is an independent
implementation review, not a blind review or an independent mathematical model.
Initial review/oracle: 2026-10-25. Saved evidence and current input hashes were
revalidated on 2026-10-26 after the interruption; the oracle was not rerun.
The proof-audit general logic, symmetry and computation obligations, and the
computation-audit finite-assertion checklist were applied.

## Objects, hypotheses and dependencies

Each plaintext position has one distinct supplied integer cell. A route orders
all occupied columns and reads each column in the declared vertical direction.
Nonconsecutive column labels and an arbitrary order of plaintext positions are
allowed. `columnar.py:35` sorts actual column labels to internal IDs and sorts
positions within a column by their row coordinate. Consequently ID order agrees
with lexical order of the reported column labels.

For route position `j` containing plaintext position `i`, ST uses key phase
`i % period`; TS uses `j % period`. The three equations are Vigenere, Beaufort and
variant over the specified 26-letter permutation alphabet. Supplied cribs are
exact plaintext constraints. The score is the product of nonnegative integer
ngram factors over unmasked windows; the implemented language model has positive
smoothing. Distinct plaintexts sort by descending score, then plaintext lexical
order; their representative sorts by actual column-label tuple, then key text.
No inference about real sculpture geometry beyond the supplied cells is needed.

The dependency chain is:

1. Input/column construction and additive equations define all labelled
   route/key assignments (`columnar.py:35`, `joint_ranked.py:158`). **Convention.**
2. Crib edge requirements, matching support and phase-domain intersection remove
   only assignments that cannot satisfy those constraints (`joint_ranked.py:188`,
   `joint_columnar.py:74`, `columnar.py:100`). **Internal argument.**
3. Partial segmentation and per-window score relaxations contain every feasible
   completion (`joint_ranked.py:226`, `joint_ranked.py:252`). **Internal argument.**
4. Guarded route symmetry selects one equivalent representative, and domain
   branches partition the remaining assignment set. **Internal argument.**
5. Atomic frontier updates and validated continuation retain unresolved work.
   **Implementation argument, conditional on intact generated state.**
6. Exact brute enumeration checks the geometry/tie corner described below.
   **Finite computation, not the premise of a universal conclusion.**

No external theorem citation is needed for these finite reductions. The review
does not re-audit the entire language trainer, recipe replay engine, Python
runtime or operating-system process containment.

## Obligations and derivation

| Obligation | Assessment |
| --- | --- |
| Fixed-point propagation (P1) | **Passed in source review.** An incompatible key/edge cannot occur in a completion. Relative to a perfect matching, an alternative usable edge lies on an alternating cycle; `columnar.py:125` retains the matched edges and SCC-supported alternatives. For each phase, every output slot and every source column must select an incident edge. Intersecting unions of their allowed residues is necessary; an unconstrained edge contributes the full residue set. Iteration is monotone and finite. |
| Unknown ragged suffix (P2) | **Passed in source review.** `prefix_feasible` uses ciphertext offsets only for the known prefix. Every remaining length gets a wildcard slot with empty key requirements. Every true suffix maps its columns bijectively to these same-length wildcard slots; rejecting this relaxation cannot reject a completion. No unknown suffix offset is invented. |
| Interleaved branching (P3) | **Passed in source review.** `joint_ranked.py:437` branches on a single non-singleton slot or key domain. Fixing each distinct value gives disjoint children whose union is the parent before sound reductions. Minimum-domain selection changes traversal, not coverage. One route may recur in different disjoint key blocks; the implementation deliberately withholds distinct-route totals in constrained mode. |
| Shared-key bound (P4) | **Passed in source review.** A fixed slot-to-column mapping supplies a ciphertext residue and phase. Each proposed plaintext symbol determines a unique residue: `c-p`, `c+p`, or `p-c`, according to the equation. `SharedKeyBound.upper` requires equal phases to agree and residues to belong to the current phase masks; unmapped positions are unconstrained. Every true window therefore survives. The largest compatible observed count, with the unseen smoothing count as fallback, is an upper bound. Taking the minimum with the independent-letter bound remains an upper bound. Multiplying window bounds remains valid for nonnegative factors. |
| Strict ties | **Passed in source review.** `joint_ranked.py:301` prunes only when the upper bound is strictly below the current kth score. Equality remains searchable, preserving plaintext and representative lexical tie-breaking. Complete keys are scored normally. A zero score is not treated as an infeasible cipher assignment. |
| Symmetry and geometry (P5) | **Passed in source review and the finite irregular-cell oracle.** `equivalent_chunks` requires equal lengths and identical full ciphertext chunks. TS additionally requires equal starting offsets modulo the key period. A swap then leaves every original plaintext position's ciphertext symbol and effective key phase unchanged for every key; ST already uses the original position's phase. Vertical direction and irregular row coordinates do not change this argument: the same column's ordered positions receive the same sequence. |
| Canonical representative | **Passed in source review.** Ascending source-column labels in each equivalent-slot group give the unique least route in that orbit, with unchanged key. Thus the least representative over all orbits is also preserved. `ordered_groups` keeps a value exactly when it exceeds the smallest feasible preceding-chain endpoint and is below the largest feasible following-chain endpoint. This is a necessary support filter when other constraints coexist. It is a sufficient symmetry rule, not a maximal equivalence detector; keys are not quotiented. |
| Bound-cache identity | **Passed in source review.** The signature includes all fixed-position bindings and the masks of every phase referenced in that window. Alphabet, equation and model are immutable for the helper instance. Unreferenced phase masks cannot affect the relaxed window. The cache is disposable and its capacity changes work only. |
| Atomic continuation | **Passed subject to the checkpoint condition.** Domain/mask reduction works on copies. Children and coverage-counter deltas are committed only after the frontier-cap check. A `_Limit` restores the original popped task. An interrupted objective has not yet retained or counted its completion. A completed leaf has no children, so cannot subsequently overflow the frontier. Repeated incomplete attempts remain work, not new coverage. |
| Completion and work labels | **Passed in source review.** `top_k_exact` requires an exhausted frontier. `enumeration_complete` additionally requires no score pruning and no symmetry reduction. Full labelled assignment totals are then withheld as appropriate. `route_completion_blocks` is not presented as distinct orders. Checkpoint objective verification is separate from newly completed search evaluations. Some work categories overlap and cannot be summed as independent operations. |

The `route_counted` fast path is valid for an implementation-generated task:
it is set only after all route slots are fixed and the associated crib residue
requirements have been imposed. Later key branches are subsets of those masks.
An unsigned JSON digest and candidate replay do **not** authenticate an externally
fabricated search history or prove that an adversary supplied the full frontier.
The result's exactness claim must not be extended to maliciously manufactured
checkpoints. This is a scope condition, not a newly discovered regression.

## Independent finite oracle and provenance

The gap targeted by this extra check was arbitrary occupied-cell order and
nonconsecutive physical column labels with all five reductions enabled. The
previous P tests mostly use a regular row-filled grid. The fixed oracle uses:

- Four positions `[(3,7),(-2,-5),(0,7),(9,-5)]`, ciphertext `ABAB`, alphabet
  `BACDEFGHIJKLMNOPQRSTUVWXYZ`, period 2, top 5, and no supplied cribs.
- Both vertical directions, both ST/TS orders and all three equations: 12 cases.
- Independent direct enumeration of both labelled column orders and all `26^2`
  keys: 1,352 assignments per case, **16,224 total**.
- Direct row ordering, additive decryption, integer score multiplication and
  canonical `(actual column labels, key text)` minimization in the review script.
  It shares the declared trained model object with the engine, not its route
  construction, decryptor, pruning, grouping or representative selection.
- All five options enabled; at most 200,000 counted engine states and 5 seconds
  per case; a 30-second outer runner cap; no randomness or external corpus.

**Outcome: implementation and finite assertion verified in this stated range.**
All 12 searches completed and matched exact top-5 plaintexts, integer scores and
canonical representatives. They also returned the intended symmetry/constrained
enumeration labels. The runner recorded `completed`, exit 0 and 0.563 seconds;
no case was censored. The run finished before the interrupted conversation and
has been preserved unchanged. Before/after hashes match, and the installed
manifest validator subsequently accepted the record against current inputs.

This oracle exercises equal-length, repeated-chunk symmetry and irregular
geometry. It does not independently test ragged-prefix rejection, crib-driven
propagation, every option combination, arbitrary periods or all possible model
counts. Those source obligations are addressed above; the existing test source
also contains ragged prefixes, restricted phase domains, a negative TS phase
guard, all 32 option combinations, lexical ties and bounded continuation. That
test suite was inspected, not rerun as part of this review.

Preserved files:

- `research/review_P_joint_oracle.py`
- `research/review-P-joint-irregular-001-contract.json`
- `research/runs/review-P-joint-irregular-001/manifest.json`
- `research/runs/review-P-joint-irregular-001/result.json`
- `research/runs/review-P-joint-irregular-001/stdout.txt`
- `research/runs/review-P-joint-irregular-001/stderr.txt`

The manifest records the exact argv, dirty repository state, Python 3.12.2,
Windows environment, input closure, bounds and output hashes. Its command ran
`research/review_P_joint_oracle.py --output` with the result path above. A future
reproduction must use fresh output/manifest paths rather than overwrite evidence.
The read-only validation used:

```powershell
.venv/Scripts/python.exe -B <installed-computation-audit>/scripts/validate_manifest.py research/runs/review-P-joint-irregular-001/manifest.json --root C:/KryptosSolverK4andK5
```

## Exact revisions

SHA-256 values below were reread after the interruption. The manifest contains
the broader package input inventory and matching before/after values. The
author's later `joint_P.py` reporting-only segmentation fields do not change the
reviewed production/helper/test bytes.

| File | SHA-256 |
| --- | --- |
| `kryptos/joint_ranked.py` | `26d550f71c12e12aa9198640c00faf8b82113943ef761967b07af21299897c1d` |
| `kryptos/joint_ranked_helpers.py` | `c53419908f9ba753439c31361ad705b55111eb63528bc29c8aaacc0763936346` |
| `kryptos/joint_columnar.py` | `1796375d58fc26970c2e727c5f0137cb1e86c97dc2acdc0e9a4e9162939d5a9d` |
| `kryptos/columnar.py` | `3a109741ebd05291a31ed04c6dbfdbbf21180ba2e53bb5309ba782c0b16c3aa4` |
| `tests/test_joint_P.py` | `a912b7999436a9cc777290949c631057142dce1981948b3509f378df5ab4088b` |
| `research/joint_P.py` | `9b7b2e278fd8ad665e046974cecb0468c58e355739890a337d328bd630befe2d` |
| `research/joint_P_protocol.json` | `ea7fa842a11c8d8a03cabf9fdf139c817e81c648170394f5ca5dfbea02f8ef62` |
| `research/joint_P_notes.md` | `bf97dc54e015a0fe6d6420b14430527799b5b1542a2f4a95e61272405323609d` |
| Review oracle script | `3b287baa1d216765351de74bd72c86c1c3d505abd71166c349b743c1944226ce` |
| Review contract | `88b3343d43b792264f7543495a2165f5f69603e340918a3a704f39ccf61149ca` |
| Review manifest | `fa81b37076965fe51e1d8ac6337e3fce77ecd9eaec7963e925c50c209e0e29c2` |
| Review result | `b7cfb97fd13363c53144ad7364bb95521c3dc5221494605ded591299fc227356` |

## Remaining scope

No concrete missing implication or production correction was identified within
this conditional algorithm claim. The finite oracle alone is not a general
proof. The source argument supplies the broader reduction justification, while
formal verification and malicious-checkpoint authentication remain outside this
review. Efficacy must come from the separate frozen P benchmark, including
unfavorable controls and overhead; this review neither reran it nor treats the
author's development counts as universal gains. No K4/K5 search, new hypothesis,
GPU run or production edit was performed here. The next required release step
is the parent's already planned canonical validation, not an expanded oracle.
