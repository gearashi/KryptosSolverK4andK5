# P6: shared unfinished equivalent-family scans

This protocol is declared before comparing results. Its finite claim is that
compatible certified jobs in one campaign can continue a single original
managed scan sequence, with no duplicate committed coordinates, while each
recipe's retained witnesses independently re-encrypt to its own ciphertext.
It does not claim an authenticated solution, faster execution in every case,
or completeness of a partial ranking.

The option `share_incomplete_scans` is false by default. The first version
supports accelerated `optimize-plus`, certified ranking, fixed resources
(`adaptive:false`), and identical normalized run settings. An exact same-
alphabet affine coset identity over F2 and F13 must match, as must the scoring
model hash and all excluded positions. Source and model files, owner request,
and the previous job's committed run file are pinned. A cache miss falls back
to a separate run with an explicit reason. Unsupported option combinations
fail at preview. There is no sharing of imported frontiers or unfinished work
between campaigns, no coordinate conversion, and no approximate ranking reuse.

The owner run keeps its original request and enumeration basis. A later job
receives another ordinary activation of that run through the manager's
existing resume control. Shared aliases are reconstructed and literally
replayed under their own recipes. No owner assignment index is represented as
an alias's index. Historical job snapshots retain their original end offsets,
candidate lists, and partial/complete status even if the live run later grows.

Counters distinguish newly committed candidate evaluations, prefix evaluations
made available to the next recipe, and validation work (identity calls,
candidate replays, literal letters checked, elapsed validation time). Reused
prefix counts are availability counts, not an assertion that another basis's
first page would enumerate the same letters. The experiment also records the
actual unique plaintext sets and independently completed-baseline work, so
avoided duplicate work is measured rather than inferred from a prefix length.

## Frozen authored controls

- Ciphertext `BCDEFG`, no cribs, standard alphabet, a single period-one
  substitution; equations vigenere, variant, beaufort, in that order. There are
  exactly 26 distinct plaintexts. Frozen bundled English pilot trigram model.
- Two jobs, pages of 13, one page per activation: the shared campaign must visit
  owner offsets 0 and 13, finish the 26-text family, and preserve the first job's
  13-text incomplete snapshot. Compare with two independent complete 26-text
  scans, independently replay both recipes, and compare exact top 20 including
  lexical ties. Also record the default-off two partial jobs unchanged.
- The originally declared three-equation check with pages of10 correctly finds
  Beaufort is a different family for `BCDEFG`: Vigenere/variant continue one
  prefix to20, while Beaufort starts separately at0. This unfavorable initial
  fixture is preserved as a negative check; equation names alone do not prove
  equivalence.
- A positive three-job control, declared after that distinction and before its
  run, uses scheduled period-one key `k` with explicit offsets0,1,2. Every
  position has phase0 modulo1, so these recipes have identical plaintext sets.
  Pages of10 must visit offsets0,10,20 and finish without a second owner.
- A separate mask `[0,2]` check directly multiplies saved-model smoothed count
  factors for windows that do not touch the mask. It must match alias exact
  scores and must not form ngrams across removed letters.
- Pause during the second activation and restart the managers: no automatic
  work on reload; explicit resume retains the original run and coordinate
  sequence. Pause/stop may discard uncommitted work, which is not reported as
  saved candidate evaluations.
- Negative controls: approximate/adaptive/exact options rejected; different
  masks and model bytes, stale run bytes, changed resources, failed owners,
  and changed owner requests do not share. A failed owner is never silently
  restarted as part of another job. Unknown or ineligible families fall back.

Only small CPU authored controls are authorized here. No K4, GPU or full app
scan is part of this protocol. Canonical run command (after source freeze):

`python -B research/campaign_P.py --output <fresh-output-directory>`

Focused regression command:

`python -B -m unittest discover -s tests -p test_campaign_P.py -v`

Canonical provenance is supplied by the project's bounded runner. The script
also records before/after input hashes, software/runtime and exact results; a
changed input invalidates the comparison. Tests use direct CPU worker calls
to isolate the campaign algorithm; a separate production-worker check covers
dispatch without changing the mathematical oracle.
