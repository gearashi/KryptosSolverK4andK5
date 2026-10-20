# Reserved model-bank validation and refit ablations, phase N

These additions extend the completed M holdout/control tools. They do not
authenticate a Kryptos plaintext or claim a calibrated false-positive rate.

## N7: the previously missing benchmark intersection

`examples/validate-k4-shaped.json` runs through `validate-controls`. It uses six
newly authored 97-letter texts: two each in English, French and Spanish. The
complete source prose and first-97-letter normalization are in
`research/fixtures_N.json`. These synthetic passages are not a representative
language corpus or native-speaker-certified prose. They were saved before any
candidate scoring. No public K4 clue words were inserted into the messages.

The mask is exactly the 24 zero-based positions derived from canonical
`K4_CRIBS`, preserving its separated placement. All windows crossing supplied
positions are excluded. Each positive gets the same existing inventory- and
crib-preserving shuffled null. The seed is 2026101507 plus case index. Three
unchanged J two-author trigram models score every input; selection uses the same
maximum-over-model rule and lexical tie break for positives and nulls.

The six competing models cover widths 7 and 10 and orders SST, STS and TSS.
Letters fill rows without padding; each gather reads occupied columns in
ascending column order. These are declared ordinal grids, not measured
sculpture geometry. Every substitution is standard-alphabet Vigenere with an
independent repeating key. Recovery receives neither the correct bank member
nor generating keys.

The period bank was chosen using only algebraic dimensions under all-zero
plaintext/ciphertext and the fixed mask. `structure_preflight_N.json` records
all 66 possibilities: eleven declared period pairs for each width/order. The
first pair with 26 through 676 completions was selected for each width/order.
The selected counts are **26,26,26,26,676,676** when feasible; these depend on
model structure and mask, not language. `benchmark_N.py --structure` reproduces
the preflight without scores. This design step is disclosed separately from
the reserved evaluation; it is not portrayed as blind model generation.

The six generating models are assigned once each to the six cases. There are
two grid widths, three layer orders and three selected period pairs; this is a
small explicit bank, not a search over unknown arbitrary permutations. Method
and language are not fully factorially balanced. Parameterized models may
overlap; complete candidate texts are deduplicated and aliases retained.

Each family has a 676-candidate cap, each input a 1,500-visit cap, and the full
12-input protocol one 30-second cooperative deadline. The algebraic maximum
is 1,456 visits per input, or 17,472 overall. Larger families are skipped rather
than represented by a favorable subset. The wrapper retains recovery failures
and censored outcomes without changing these settings. Request and fixture
hashes were frozen in `protocol_N.json` before evaluation. Unit pipeline tests
use separate mechanical letter sequences; they do not score reserved passages.

## N8: deleting a stage and refitting

`validate-ablations` accepts the familiar target/ciphertext/cribs,
`withheld_positions`, frozen `model_paths`, bounds, and a `model_bank` with
exactly one baseline. Optional `ablation_stage_indices` selects which original
zero-based stages to change; the default includes every stage. Each variant
removes one substitution or replaces one gather with identity. Removing the
last stage yields an explicit identity gather, so a zero-stage cipher is handled.

Every variant refits all remaining key variables using training letters only.
All supplied clue positions, including withheld ones, remain masked from
language scoring. The entire series of fits finishes before withheld values
are read for assessment. A regression changes held labels and requires identical
selection outputs for all variants. The protocol shares one total candidate
visit cap across baseline and variants and one wall-clock deadline.

Scheduled models make their semantics explicit:

- `schedule_semantics="recompute"` preserves each declarative coordinate rule
  and resolves source-frame phases against the changed preceding gathers.
- `schedule_semantics="freeze"` resolves the original schedules once, then
  holds their per-position phase maps fixed while removing/replacing a stage.

Already explicit phase maps remain explicit under either policy. Output records
contain the variant model, resolved stages and phase provenance. Shared key IDs
remain shared among surviving references; keys from the original model are never
carried into refitting.

Each record reports its selection, held predictions and completion status. Only
when both searches complete does `comparison_to_baseline` compare the exact
enumerated plaintext sets: equality, lost/gained counts, and top-prediction match
difference when both sides have a candidate. Empty or censored candidate sets
have no fabricated winning prediction. Ablated families need not be nested.
These comparisons establish conditional differences between declared recipes,
not causal or historical necessity.

The preset uses an authored passage, a two-letter substitution key, and a gather
cycling three withheld positions. It is a deliberate instructional example of
route necessity, not evidence supporting a K4 route. Separate independent tests
cover a shared cancelling pair, noninvolutive scheduled position transport,
a route whose deletion loses a held prediction, exhaustive
two-letter-key refits, identity, censoring, and both scheduled frame policies.

## Verification and canonical run

```text
python -B -m unittest tests.test_ablations tests.test_validation_N -v
python -B research/benchmark_N.py --inputs
python -B research/benchmark_N.py --output FRESH_RESULT.json
```

Eleven focused tests passed before the reserved run. The first reserved scoring
run completed at [release-N-002/validation](runs/release-N-002/validation/manifest.json)
in **5.344 seconds**, with a validated manifest and all 62 input hashes unchanged.
It rechecked frozen hashes and the 66 structural dimensions, executed both
presets unchanged, and independently encrypted all 12 generated positive/null
inputs with separate literal numeric code. The computation-audit runner imposed
a 60-second outer wall-clock cap; protocol deadlines remained 30 and 10 seconds.
Production paths and test files belong in its input closure. A censored or poor
recovery result remains a valid recorded outcome, not grounds to retune fixtures.

For a separately authorized reproduction on a frozen source revision, use a new
label; the recorded N002 result must not be overwritten:

```text
python -B research/run_validation_N.py --audit-skill PATH_TO_COMPUTATION_AUDIT --label release-N-NEW
```

It creates a label-specific copy of the contract with the current explicit input
closure, runs the benchmark under an owned Windows JobObject or POSIX process
group, and validates the resulting manifest. `--prepare-only` writes only the
contract and does not score a passage. The closure includes every production
Python module, both presets, frozen fixtures/preflight/protocol, the wrapper and
contract template, relevant validation/lifetime tests and the three frozen model
files. Included test sources identify companion evidence; this benchmark does
not rerun the unit suite. Raw source books, external network data, browser assets
and unrelated performance benchmark inputs are not needed for this computation.

## Recorded outcomes and review limits

All six positive and six paired-null inputs completed the full declared bank,
performing **4,316 candidate visits and literal re-encryptions** before merging
aliases. Each input retained 26 or 676 distinct plaintexts. All six generating
positive texts ranked uniquely first. Every null retained wrong alternatives;
their generating texts ranked 3,2,2,1,2,7 in fixture order. Each best null scored
below its paired positive by between 2.297 and 3.486 mean-log units under the
frozen selection rule. These differences are descriptive, with no threshold or
probability fitted to them.

An important limit emerged: each positive retained only **one inequivalent
plaintext family**. Other fitting model records in French-1 and Spanish-2
produced duplicate families, while the remaining models were rejected by the
clues. Thus this run verifies hidden-model bank filtering plus ambiguous
within-family ranking. It does not establish discrimination among several
different surviving cipher families. No fixture or bound was changed after
observing this result.

The instructional ablation completed all three refits. The baseline had one
plaintext and predicted held letters `GAT` (3/3). Removing the substitution
contradicted training letters, so no prediction or numerical match delta was
invented. Replacing the gather with identity left one different fitting
plaintext, predicted `RCG` (0/3), and lost the baseline's three matching letters.
Independent unit controls also established cancelling-layer redundancy; this
single instructional preset does not claim necessity of a stage in K4.

A separate post-run preservation step verified every current input against both
manifest hashes before copying only those 62 files into
`source_snapshots/release-N-002-validation/`, then verified every copy. The
[portable inventory](release-N-002-validation-snapshot.json) records the manifest
digest, relative paths, file sizes and SHA256 values. The snapshot totals 753,664
bytes and includes the derived frozen language models, not raw source books.
The audited wrapper was not changed to create this snapshot. Original results,
manifest and scientific inputs remain intact.

The implementation review found no remaining concrete issue in the N7/N8 scope.
The language sample, bank coverage and inequivalent-family limitation above
remain research limitations, not evidence of a decipherment. The independent
campaign review also led to cleanup-ownership and validation-routing fixes in
root-owned code before this source revision was frozen.

K4/K5 remain undeciphered here; no authenticated public K5 cipher is added.

The unchanged protocol was reproduced on the frozen release source on
2026-10-20 as `release-N-004/validation`. All 63 current input hashes and the
portable snapshot were verified; the run completed in 4.906 seconds with the
same counts, ranks, ablation predictions and family-coverage limitation above.
See [the N004 reproduction record](release-N-004-audit-notes.md) for the fresh
manifest, source inventory and companion search/CPU-CUDA evidence. The N002
record and its source snapshot remain unchanged.
