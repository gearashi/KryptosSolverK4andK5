# Iterative improvement protocol

The active user goal is to implement worthwhile, concrete improvements, review the resulting system again, then deliver a usable local CPU/GPU browser application and publish the reviewed repository. This is a persistent goal, not a scheduled automation. The machine-readable working ledger is [`research/improvement-state.json`](../research/improvement-state.json). It supplements the cryptanalytic evidence records; it does not replace them.

## Admission and acceptance

An idea enters the ledger with a demonstrated gap, a bounded proposed change, an owner, dependencies, a discriminator, and a reason it improves correctness, performance, model coverage, usability or reliability. Different parameter values or cosmetic rewrites are not automatically improvements. Avoid ranking proposals by hypothetical speedups or by a promising K4 plaintext.

The four recorded statuses are:

- `proposed`: under review, accepted for implementation, or in progress. The separate decision and stage fields say which.
- `validated`: the stated acceptance contract has evidence. Any unvalidated integration or publication obligation must be another open entry; a tiny helper test does not validate an application feature.
- `rejected`: evidence or scope rules make the proposal unsuitable. Preserve the reason and any counterexample.
- `deferred`: a named missing prerequisite prevents worthwhile implementation now. Record the trigger that would reopen it; do not use deferral to hide authorized feasible work.

An acceptance record names the exact tested range, source/input revision, reproducible command and artifact, relevant limitations, and the result. Runtime claims need measured work or time on a declared workload. Model extensions need independent literal encryption and a known-answer control. Resume/cancellation claims need interruption and recovery tests. User-facing features need browser interaction checks. Existing pinned research outputs remain unchanged when implementations evolve.

## Each review cycle

1. Select accepted entries whose prerequisites are ready; use separate ownership for independent files.
2. Implement the smallest complete change that addresses the gap. Test the intended behavior and a discriminating failure, rather than duplicating implementation assertions.
3. Run bounded evidence checks and inspect failures. Record limits and inconclusive outcomes as such; do not expand a search merely because an arbitrary first cap was reached.
4. Review the resulting system across correctness, performance, model coverage, usability and reliability. At least one reviewer should inspect a different perspective from the implementer. Add only concrete follow-ups discovered by this review.
5. Keep, revise, reject or defer each idea based on its discriminator. Record the decision in the ledger and connect accepted follow-ups to the evidence that revealed them.

The current accepted tracks are actual CPU/GPU batches, a recoverable local job service, the browser interface, exact correlated n-gram bounds, reporting-only sensitivity to letters forced by the model, and source-independent packaged geometry. Affine-family deduplication is deferred until a real multi-family scoring workflow exhibits duplication; it is not a current application requirement. Admission decisions and separate integration obligations remain explicit in the ledger.

## Closing a bounded improvement phase

Close the phase when all accepted actionable entries are validated, a complete post-integration review finds no further concrete justified implementable gap in the requested scope, and each remaining proposal has a supported rejection or a specific external prerequisite. Save the reviewed revision and the remaining limits. This means the reviewed backlog is exhausted under the current evidence; it does **not** mean that the solver is globally optimal, that every cipher family was searched, or that no future improvement exists.

Before publication, validate a fresh checkout/package, its launch command, bounded CPU behavior, available GPU behavior or explicit unavailability, restart/resume and cancellation, input validation, source attribution, and the distribution manifest. External caches omitted from publication must not silently break ordinary application startup. The user chooses any license for their project code; attribution does not grant a license to third-party content.

Neither K4 nor K5 has an authenticated decipherment in this project. No authenticated public K5 ciphertext is bundled; K5 requests require explicit input. Crib fits, high language scores, exact replay and complete finite searches are evidence about specified models, not automatic authentication.
