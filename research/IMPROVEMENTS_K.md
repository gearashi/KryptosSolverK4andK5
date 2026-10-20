# Checkpoint K: joint constraints and larger finite searches

All seven requested improvements are implemented and verified. The usable interface remains chat investigation with supporting Python commands. **K4 and K5 have not been deciphered.**

The frozen package passed **216 unit tests**, **eight command executions**, **19 candidate replays**, and all **eight canonical evidence manifests**. [Validation record](checkpoint-K-validation.json) pins the source, inputs, outputs and run limits. [Runnable examples](../docs/CLI_CHECKPOINT_K.md) cover each new command and checkpoint resume.

## The seven requested improvements

| Improvement | Implemented behavior | Evidence and limits |
|---|---|---|
| Joint unknown column order and substitution key | `joint_columnar.py` links column matching to repeating-key equations in ST/TS order, including ragged columns and explicit occupied coordinates. | [Joint controls and K4 bank](runs/joint-K-001/results.json): all ten controls pass. All six substitution-wrapped PK2 fixtures retain the planted answer; five are unique and one correctly has two answers. The supplied method/period/cribs remain assumptions. |
| Shared keys and relative offsets | `scheduled_layers.py` creates one variable per named key slot across stages; relative phase offsets can add, subtract or cancel contributions. | [Scheduled controls](runs/scheduled-K-001/results.json) match independent enumeration of all 676 two-letter keys. Exact counts use separate arithmetic modulo 2 and 13. |
| More stages with different known alphabets | `mixed_stages.py` composes cyclic substitution relations and gathers, with shared keys interpreted as the same letters under each alphabet. Equal alphabets dispatch to the linear solver. | Three alphabets and two gathers agree with a separate 676-key-pair enumeration. Unknown stage alphabets remain a separate research route. |
| Sculpture-coordinate key schedules | Row-reset, occupied-column and serpentine phase maps support current or transported source coordinates. The CLI records their cells, phases and offsets. | Independent ragged-grid examples verify both frames and composed routes. These rules are hypotheses, not a claim about the artist's construction. |
| Stronger safe pruning | `alphabet_propagation.py` removes alphabet assignments that belong to no perfect matching; joint recovery filters matching support and factors unconstrained components. | [Alphabet audit](runs/alphabet-K-001/results.json) checks all 66,066 square graphs of sizes 1–4 and 15 finite cipher cases. Cipher counts agree with the earlier solver. It removes 34 additional edges in the cipher controls but both versions visit 141 states: no speedup is claimed for that set. |
| Harder false-positive controls | Five real passages and five paired shuffles each retain 17,576 crib-compatible completions. Identical frozen multilingual selection applies to every input. | [Hard controls](runs/hard-controls-K-001/results.json): 175,760 literal re-encryptions; all five real texts rank uniquely first; every null survives the cipher constraints. No probability of correctness is inferred. |
| Larger-search execution | `search_runtime.py` supplies lazy exact scoring, adaptive variable order, bounded caches/frontiers and complete saved search frontiers. `parallel_search.py` runs independent hidden CPU processes with deterministic result order. | [Runtime comparison](runs/runtime-K-001/results.json), [independent bound/frontier audit](runs/runtime-audit-K-001/results.json), and [CLI checks](runs/cli-K-001/results.json). Complete serial and parallel results agree; partial progress can vary with hardware. |

## Further improvements implemented during this work

1. **Exact marginal letter domains.** Reports distinguish one, two, thirteen or twenty-six possible letters at each position, while preserving correlations between positions.
2. **Key cancellation and unused-slot diagnostics.** A unique plaintext can still leave many equivalent keys. The shared cancellation example explicitly shows one plaintext and 676 keys.
3. **Factorial/free-key shortcuts.** When column equations impose no further key restrictions, exact matching-component counts and free key multiplicities replace enumeration. A no-crib twenty-column control counts `20! × 26³` assignments without branching.
4. **Duplicate score-window merging.** Identical affine n-gram factors become one factor with a multiplicity. A 676-point control reduces ten windows to two factors, with every exact score unchanged; it avoids creating 6,760 dense score entries.
5. **Safe memory stops.** If expanding a branch would exceed the frontier limit, the complete parent remains saved. The remaining upper bound stays valid and resume preserves coverage.
6. **Checkpoint identity and integrity checks.** Resume rejects changed problems, scoring models, algorithm revisions, incompatible bound conventions, altered payloads and invalid saved bounds. These are accidental-integrity checks, not external authentication of search coverage.
7. **Consistent worker paths.** Relative checkpoint/resume paths resolve in the caller's directory in serial and parallel execution. Caller requests are not mutated; conflicting outputs are rejected before work.
8. **Per-job inconclusive budget results.** Exhausting the algebra budget returns `feasible: null` and preserves assumptions and provenance. Other batch jobs can still return their results. Exhaustion is not silently labeled a contradiction.
9. **Independent expanded-stage replay.** Complete candidates include per-stage alphabets, full effective key patterns, gather permutations and intermediate outputs. A separate literal implementation verifies them and the supplied cribs.

## What the new K4 probes found

The banks were declared before execution. No family was selected because of a promising output.

| Fixed model bank | Completed exclusions | Unresolved at its bound | Witnesses found |
|---|---:|---:|---:|
| Joint columns + repeating Vigenere; widths 7/8/10, periods 2/3/4, ST/TS, KRYPTOS alphabet | 16 | 2 | 0 |
| Shared outer key, coordinate schedules, fixed pair of geometry routes | 18 | 0 | 0 |
| Three known-alphabet substitutions, fixed routes, shared/separate outer keys | 4 | 4 | 0 |
| **Total model records** | **38** | **6** | **0** |

The two incomplete joint cases are width 10, period 3, ST and TS, each reaching 20,000 states. The four incomplete mixed-alphabet cases have independent outer keys and reach 750,000 relation checks. They are **not excluded**. These records can also overlap in their represented transformations, so the table is not a count of disjoint cipher families. Other grids, keys, alphabets, stage orders, padding, extraction rules and mechanisms remain open.

The schedule bank explicitly includes models whose outer key cancels when its phase map is transported through the gathers. The diagnostics expose this loss of effective complexity; adding visible stages need not create a new cipher.

## Language ranking and performance findings

The language test uses previously frozen two-author English, Spanish, French, Italian and Latin trigram models. The five held-out texts come from later spans of separate-author books, beyond checkpoint J's evaluated windows. Each null shuffles only the 73 unsupplied letters, preserving the exact inventory and all 24 supplied letters. Every input supplies the same SST/identity method with key periods 3 and 14.

All five real texts rank uniquely first under the same maximum-over-five-models selection used for the nulls. Every null has 17,576 valid completions, and its best score is below its paired real text's best score. The generating shuffled text itself ranks first in three null families, third in one and eighth in one. This is a useful selection stress test, not an automatic solution detector. It covers five literary windows and one known cipher family; some letters outside the explicit cribs are also fixed by the cipher. The run took about 43 seconds and does not calibrate real K4 false-positive probabilities.

Lazy exact scores match dense scoring across all 676 points of the five-stage control, preserving the same winning plaintext. On twenty fixed eight-variable finite graphs, adaptive branching uses fewer nodes in nineteen and more in one. Both strategies remain available. A looser local n-gram bound uses 302 nodes on the language fixture, compared with 110 under the default exact-local cutoff. Lazy scoring offers a memory/work tradeoff, not a universal speed guarantee.

The independent runtime audit checks 63 global and 126 local partial bounds against direct products, twenty capped searches, tied optima, six one-node resumes, source-change rejection and serial/worker agreement. The ordinary suite also tests tampering, frontier limits, awkward ragged columns, incomplete counts and budget provenance.

## Evidence and use

- [Unit suite: 216 passed, no errors/failures/skips](runs/unit-K-001/results.json)
- [Eight CLI executions and nineteen replays](runs/cli-K-001/results.json)
- [Eight validated manifests](checkpoint-K-validation.json)
- [Shared/mixed stage conventions](scheduled_layers_K_notes.md), [joint recovery conventions](joint_columnar_K_notes.md), [alphabet pruning](alphabet_propagation_K_notes.md), [hard-control protocol](hard_controls_K_notes.md)
- [Independent peer alphabet audit](manual-checks/alphabet-independent-K/result.json) and [joint peer audit record](manual-checks/joint-independent-K/recorded_result.json). The latter records the earlier inline execution; its literal script was not retained. Reproducible canonical and unit joint controls remain available.

Canonical ciphertext and crib data are unchanged. Older checkpoint-J implementation evidence refers to its recorded source revision; the modified entry point is preserved under `source_snapshots/checkpoint-J/`. Existing mathematical engines and historical results were not rewritten.

The user confirms n5_runner is inactive and will remain so during this work. Tests used bounded CPU processes; no GPU backend, BOINC server, dashboard server, persistent search or external submission was started. Batch time limits are cooperative. No authenticated K5 ciphertext is available in this project, so K5 requests still require explicit input. The work delivered here is a stronger, audited investigation toolkit, with the decipherment unresolved.
