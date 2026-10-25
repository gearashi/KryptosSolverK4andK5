# Phase O: surviving model competition, full-bank nulls, and bounded paths

The authored fixture and request were saved before any language scores were
computed. `protocol_O.json` pins both SHA256 values. The first canonical scoring
run, `release-O-001/validation`, completed on 2026-10-25 after the shared source
freeze. All recovery ranks and threshold comparisons were retained without
tuning these inputs; this run had no censored selections.

## Canonical observed outcomes

The computation-audit v2 manifest is
`research/runs/release-O-001/validation/manifest.json`; the complete result is
`result.json` beside it. The runner reports `completed`, exit 0, and 11.11 seconds.
The validator passed against current inputs. All 66 declared input files match
their before/after observations and immutable copies under
`research/source_snapshots/release-O-001-validation`; the separate
`snapshot-verification.json` records that closure. The result SHA256 is
`a3854291502e7899ff525fb6f250e2a10078a48bd38be341ae83fe73cc240a5e`.

All 20 complete bank selections visited and literally re-encrypted 14,560
candidates. Each positive retained three distinct completed plaintext families,
exceeding the declared minimum of two. Each input had 727 distinct plaintexts
after shared candidates were deduplicated; each positive therefore faced 726
wrong alternatives. The generating-text competition ranks were:

| Frozen positive | Truth rank | Equal-score texts at truth score |
| --- | ---: | ---: |
| English 1 | 1 | 1 |
| English 2 | 1 | 1 |
| French | 2 | 1 |
| Spanish | 4 | 1 |

Thus the full bank recovered the exact top text in two of four cases. The French
and Spanish misses are retained evidence of scoring limitations; complete family
enumeration and valid re-encryption do not establish the intended plaintext.

All 16 null selections completed with surviving wrong candidates. None exceeded
the frozen -9.0 threshold, while all four positive selections did. The reported
empirical frequency is 0/16 for this exact conditional randomization and complete
selection procedure. It is not an authenticity probability, population
false-positive rate, or proof that the scoring rule distinguishes real cipher
solutions. The small authored sample and clue-aware engineered families remain
material limitations.

All 20 independent generator-cipher checks passed. The grid control retained
the frozen counts: 96 parameter tuples, 81 trapped walks, 15 bijective tuples and
11 unique routes. Deduplication reduced solver calls from 15 to 11 and counted
algebra work from 303,222 to 220,966, preserving classifications and all six
known-candidate replays. Every valid parameter alias was independently replayed.

## A deliberately discriminating synthetic bank

`examples/validate-campaign-null.json` supplies four new 97-letter passages:
two English, one French and one Spanish. Full prose and normalization are in
`fixtures_O.json`. These are authored controls, not a representative literary
sample or certified native-speaker corpus. Three unchanged two-author trigram
models from checkpoint J score every positive and null.

The mask uses the actual 24 separated K4 positions. To guarantee several
surviving families, the bank is deliberately designed around that mask: a
gather moves these positions to the first 24 output positions, followed by an
unknown repeating key of length 25 or 26. A third model swaps two unsupplied
positions in the gather and uses length 25. Every model therefore has 24
independent clue equations. The remaining plaintext dimensions yield exactly
26, 676 and 26 completions. The two one-dimensional direction supports differ;
the third family differs in dimension. A zero-text structural preflight checks
the full F2/F13 spans without reading or scoring the authored messages.

This is an engineered benchmark, not a source-motivated Kryptos route. It
addresses the prior N bank's weakness: alternative models cannot all disappear
through early clue contradictions. The acceptance criterion is at least two
distinct, completely enumerated plaintext families per positive. Recovery of
the generating plaintext is an observed rank, never a pass requirement.

Family grouping uses exact equality of the completed plaintext sets. SHA256
digests identify the recorded sets but do not decide equality. Partial and
over-cap families receive no complete-family digest or equality claim. The
selection output reports family groups, model aliases, counts and whether the
entire bank completed; it never materializes an over-cap family just to hash it.
The union of all visited candidate texts is `distinct_evaluated_plaintexts`;
it can include a partially visited family. Complete-family counts and digests
remain separate and exclude partial families. The retained legacy field
`distinct_completed_plaintexts` now counts only the union of fully enumerated
families; a truncated family's candidates do not inflate it.

## Full-procedure conditional null calibration

The preset fixes seed 2026102501, four null draws per positive, and a descriptive
decision score threshold of -9.0 before observing the scores. The threshold is
an illustrative researcher choice, not a learned or validated authenticity
threshold. Each null shuffles only unsupplied letters, preserving the entire
inventory and supplied clues. Replicate zero uses the legacy seed plus case
index; later replicates add `replicate * case_count`. Repeated and identity
shuffles are retained, so the declared randomization is not conditioned on a
preferred draw.

Every positive and every null reruns the entire bank and takes the maximum over
the same three frozen language models. It does not fit one chosen model and
reuse that result for the nulls. Every supplied clue position and every touching
ngram window remains masked. Each enumerated candidate is literally re-encrypted.

The request has 20 input selections and at most 728 candidate visits each:
14,560 total. It caps each family at 676 candidates, each input at 1,500, the
whole protocol at 15,000, and cooperative protocol time at 30 seconds. The
canonical runner imposes a 60-second outer wall-time limit. Oversize
families are skipped in full; deadlines and visit limits remain visible. The
full-protocol empirical threshold-exceedance rate is available only when all
positive and null selections complete. Censored runs retain counts but no
uncensored rate. The rate describes these conditional shuffles and fixed
procedure; it is not a p-value, real-world false-positive rate, or probability
that a candidate is authentic.

`validate-controls` accepts optional `null_replicates` (1..16),
`minimum_distinct_surviving_families` (1..16), finite
`decision_score_threshold`, and `max_protocol_candidates` (1..100000).
Existing `cases[].null` remains the first draw. `null_replicates` records every
draw, while top-level `calibration` and `family_coverage` expose the comparisons.

## Parameterized ordinal grid paths

`kryptos/grid_paths.py` enumerates an explicit product of start indices,
cardinal directions, left/right turn preference and none/toroidal wrapping.
Each step tries straight and then successive quarter turns in the declared
sense. Visited cells and holes block moves. Wrap uses the occupied set's
bounding rectangle and never inserts a missing cell. A trapped prefix is
recorded as nonbijective; only complete occupied-cell permutations enter a
cipher search. Exact duplicate permutations are grouped before cipher work,
with all parameter aliases preserved.

Bounds are at most 32 starts, four directions, two turn senses, two wrap rules,
512 parameter tuples and 200,000 parameter/occupied-cell products. Excessive
requests fail before sampling. Grammar integration uses `routes: ["paths"]`
with `path_parameters`; custom text also needs an explicit width. K4 uses the
pinned normalized transcription coordinates. These are ordinal hypotheses,
not measured three-dimensional paths or an inferred historical mechanism.

The frozen path control in `grid_paths_O_protocol.json` declares 96 tuples on
the K4 occupied cells. The structural development check found 81 trapped walks,
15 bijective tuples and 11 distinct routes. It compares 15 raw-valid cipher
solver calls with 11 deduplicated calls, preserving exact classifications and
known-control plaintexts. Counted algebra work falls from 303,222 to 220,966.
Every alias gets a separate literal coordinate replay, and a separate direct
Vigenere key-consistency check verifies each classification. The mechanical
97-letter control supplies its entire plaintext deliberately; it checks route
and constraint handling, not blind message recovery. No language score is used.

## Commands and scope

```text
python -B -m unittest tests.test_grid_paths tests.test_validation_O tests.test_hypotheses tests.test_validation_protocols -v
python -B research/validation_O.py --inputs
python -B research/validation_O.py --preflight
python -B research/validation_O.py --output FRESH_RESULT.json
```

For the canonical owned-process command and preparation/snapshot behavior, see
`research/O_audit_commands.md`. Search and scan audits have separate contracts
and outputs; their results are not inferred from this validation run.

The focused suite passed 21 tests. They include independent small key
enumeration, full-bank threshold maxima, exact family aliases, shared budget
censoring, retained identity shuffles, hand path vectors, holes, wrap, complete
parameter-product counts and path provenance. Tests use separate mechanical
messages and do not score the frozen authored fixture. The `--preflight` command
also performs only structural/mechanical checks. The full command must be run
under the canonical computation-audit contract after source freeze; it records
input hashes before and after, all ranks, coverage and empirical counts.

These changes add discriminating evaluation and reduce duplicated cipher work
within a declared path set. They do not authenticate K4/K5 or claim a universal
reduction in solving steps. Historical audit files remain unchanged.
