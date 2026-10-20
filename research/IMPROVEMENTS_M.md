# Nine improvements, checkpoint M

The user reopened the improvement goal after checkpoint L and explicitly requested all nine proposals. This phase implements that complete scope and fixes concrete issues found during integration. It does not claim that every possible improvement has been exhausted, or that K4/K5 has been deciphered.

| Improvement | Implementation | Acceptance evidence |
| --- | --- | --- |
| Persistent CPU/GPU workers | Hidden owned processes, prepared-family caches, reusable immutable GPU buffers | Worker lifecycle tests and20-page end-to-end benchmark |
| Verified scan seeds | One bounded CPU/CUDA page supplies independently checked exact-search incumbents | Same optimum/assignment, bad seed rejection, actual CUDA seed control |
| Joint factor bounds | Fixed disjoint groups bound overlapping n-grams jointly; capped enumeration falls back safely | All81 partial assignments of a fixed discriminator; unchanged exact optimum |
| Certified GPU ranking | Integer-only outward log intervals, all cutoff overlaps/ties exactly compared on CPU | Exhaustive CPU agreement, tied pages, nonstandard alphabets, offsets above2^53, integer-power enclosure tests |
| Durable recipe campaigns | Bounded matrix preview, persisted reserved child IDs, recoverable committed work, exact affine-coset deduplication |12-job matrix, pause/restart and dispatch-gap tests, equivalent recipes scanned once and independently replayed |
| Reduced-clue recovery | Fit without withheld values; mask all supplied positions; rerun model selection before assessment | Mutating withheld answers cannot change selection; censoring and actual K4 mask checks |
| Competing-model controls | Complete declared bank on authored positives and paired crib-preserving shuffles | Frozen2808-visit fast protocol with surviving alternatives for positives and nulls |
| Resource controls | Worker/idle/adaptation changes only at committed boundaries, bounded event history | Contiguous coverage, pending changes, history-cap and cancellation regressions |
| Import and letter tracing | Bounded inert JSON; separate replay; original-letter mappings through each stage | Hand-derived gather, substitution, mixed-alphabet and coordinate vectors, tampering, browser trace |

## Recursive review findings

Integration added an exact optimizer preset and public validation CLI commands so the new algorithms are reachable. Independent review also required atomic publication of exact results, preserving an event slot for queued resource changes, rejecting writes after manager shutdown, and recomputing each equivalent recipe's own clue-sensitivity report. Campaigns reserve their child run identity before dispatch and hash shared source files once per identity check.

Repeated process tests exposed a Windows virtual-environment redirector: terminating only its launcher could leave the actual worker alive. Worker ownership is therefore applied to the entire process lifetime, including cancellation, timeout and cleanup. Transient sharing failures in the private inbox protocol have bounded retries; failed cipher jobs are not retried as if their results had been committed.

Final review also fixed elapsed-time rounding when resuming a search, made process cleanup idempotent, preserved saved-state ownership when cleanup fails, and contained wide validation tables on mobile. A deterministic high-clock regression and the full clean-checkout suite cover the timing fix. Test cleanup verifies that the native Windows job contains no active descendants before retrying a transient file-sharing failure. The benchmark wrapper also owns its complete process tree, so its timeout cannot leave a virtual-environment child behind.

## Interpretation and reproduction

The fast validation controls use an artificial contiguous24-letter mask on newly authored97-letter messages. They are not the separated K4 clue layout. Public K4 holdouts are retrospective diagnostics. Exact ranking applies only to the declared family, scoring model, mask and evaluated coverage. Equal plaintext families do not establish equal physical encryption methods. Replay establishes model consistency, not authentication.

The final test counts, source hashes, actual-device measurements and browser checks are recorded in [release validation](release-validation.json) and `research/runs/release-M-002/`. The clean publication copy passed 309 tests with one optional raw-source skip; 42 browser assertions passed. On the fixed 20-page benchmark, persistent CPU execution took 5.414 seconds versus 18.539 seconds for one-shot workers; CUDA took 5.285 versus 75.974 seconds. All four rankings agreed, with 240 independent retained score and recipe checks. These timings include process startup and shutdown; caches were not flushed, and they are not a general speedup guarantee.

Historical L and M-001 evidence retains its original scope and source revision. Use the [application guide](../docs/LOCAL_APP.md), [scan documentation](../docs/ACCELERATED_SCANS.md), and [validation protocol guide](../docs/VALIDATION_PROTOCOLS.md) for controls and bounds.
