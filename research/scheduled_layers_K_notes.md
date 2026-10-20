# Shared keys, fixed phase schedules, and known mixed alphabets

These additions implement explicitly supplied model families. They do not infer
an unknown alphabet, freely fit coordinates, assign a language, or authenticate
a Kryptos solution. Existing `general_layers.py` remains unchanged and is an
explicit pinned dependency of the new exact linear solver.

## Stage contract and public APIs

`solve_scheduled(ciphertext, known, stages, alphabet='standard', ...)` is in
`kryptos.scheduled_layers`. `known` maps zero-based **original plaintext**
positions to letters. Stages are in encryption order. A substitution is:

```python
{"operation": "substitution", "key_id": "outer", "key_length": 3,
 "cipher": "vigenere", "phase_map": [0, 2, 1, 0, 1], "offset": -1}
```

The phase map must have one entry per current stage position. Omission means
`position % key_length`; the offset is added modulo the key length. Repeated
`key_id` values identify the same entire key and must have the same length.
The cipher is Vigenere `P+K`, Beaufort `K-P`, or variant `P-K`. A gather remains
`{"operation":"gather","permutation":[...]}` with
`output[j] = input[permutation[j]]`.

The scheduled solver uses one shared known A–Z alphabet. Optional per-stage
alphabet declarations must match it exactly. The new matrix merges references
to shared key slots before solving, so repeated contributions may add, subtract
or cancel. It reuses the pinned F2/F13 solver and key-to-plaintext projection;
it never assumes all freedoms have26 values. Bounds and infeasibility certificates
have the same meaning as in the pinned generalized solver.

`ScheduledSolution` provides `summary()`, `plaintext(values2,values13)`,
`keys(values2,values13)` returning a dictionary of letter keys by ID,
`candidate(...)`, `enumerate_plaintexts(max_candidates)`, and `affine_plaintext()`.
Its exact `plaintext_domains()` contains each possible marginal letter at every
position. Each such domain has1,2,13 or26 letters. A nonzero image functional over
Fp is onto Fp; combining the two field images by CRT proves these marginal sets.
They are conditional on all supplied cribs, not independent choices between
positions. Domain strings follow the declared alphabet order.

`dependency_report()` identifies unused slots, slots referenced by stages whose
final coefficient is zero everywhere, and conditional gauge dimensions in both
prime fields. Zero final columns prove that those key slots have no effect on
the final message under this exact model. This does not say their intermediate
effects vanish, and more general gauge dependencies may involve multiple slots.

## Fixed occupied-coordinate schedules

`make_phase_map(cells, kind, key_length, frame='current',
stage_to_source=None, offset=0)` returns explicit phase indices:

- `row_reset`: rank among occupied cells sorted by column inside each row,
  restarting at zero for every row.
- `column`: rank of the occupied column label among all occupied column labels.
- `serpentine`: global occupied-cell rank in sorted rows, reversing alternate
  rows. It does not restart its phase at a row boundary.

Missing cells consume no phase. These rules depend on the stated occupied labels,
not physical distances or guessed padding. Current frame uses `cells[j]` at the
current stage position. Source frame requires an explicit bijection mapping
current positions to original source positions, and uses `cells[map[j]]`.
`stage_position_map(length, preceding_stages)` composes preceding gather maps;
substitutions preserve positions. A source map supplied with current frame is
rejected rather than silently ignored. All choices remain model assumptions.

## Known mixed alphabets

`kryptos.mixed_stages.solve_mixed_stages(ciphertext, known, stages, ...)` uses the
same stage grammar, but every substitution must explicitly provide a known
alphabet name or permutation. A shared key means the **same letter string** in
every stage. Each stage looks those letters up in its own alphabet; it never
silently reuses numeric indices between alphabets.

The finite-domain solver represents plaintext, intermediate and ciphertext
letters explicitly. Each substitution constraint enforces exactly that stage's
cyclic equation on its input, shared key slot and output. Domain propagation
keeps only letter values supported by that ternary relation. This propagation is
sound but need not decide the whole problem; the remaining search branches on
used key-letter slots. Fixed keys and ciphertext uniquely determine every
intermediate and plaintext symbol. Every accepted leaf receives separate literal
stage re-encryption. No arbitrary monoalphabetic table is substituted for a cyclic
equation, and no unknown alphabet is searched.

Completely unused key slots contribute a factor26 each without branching. Other
key symmetries are not guessed away. Exact key counts and distinct plaintext
counts are separate; plaintexts are deduplicated explicitly. Completed searches
return exact plaintext and key-letter marginal domains. Interrupted searches
withhold global domains and exact counts, returning only witnessed lower bounds.
The candidate storage cap does not restrict counting. The separate distinct-text
cap bounds deduplication storage; hitting it is a censored search, not rejection.

If all substitution alphabets are identical, exact dispatch to the scheduled
linear solver is valid under the same letter-key convention. Its counts and
marginal plaintext domains then characterize the whole family even if only one
representative is saved. No conditional key marginals are claimed by this
dispatch. Finite-domain node/relation/time caps do not apply to that branch;
the returned result explicitly states that the pinned linear matrix/work bounds
apply instead. Mixed runs are otherwise not collapsed or relaxed.

Defaults are16 stages,256 distinct key slots,4096 cyclic constraints,10000 search
nodes,2000000 tested relation pairs,10000 retained distinct texts,20 saved
candidates and5 seconds. Time is cooperative, checked during propagation and
branching. A preflight constraint/slot-budget exception is not an infeasibility
verdict. Search exhaustion is required for a definitive rejection.

## Replayable candidate evidence

Both solvers return candidates with `plaintext`, `keys_by_id`,
`reencryption_matches`, and `encryption_recipe`. Scheduled candidates also retain
the two field-coordinate tuples. The recipe schema is
`kryptos.expanded-recipe.v1`. Each substitution contains its own known alphabet,
equation and full message-length `key_pattern`; phase maps and offsets have
already been expanded at their actual stage positions. Gather permutations stay
explicit. An independent consumer can replay this without reconstructing any
solver matrices or knowing how the keys were recovered.

## Finite validation protocol

The two new unit modules have six tests each. They include exhaustive676-key
comparisons, shared-key identities across a non-affine alphabet swap, three
different supplied alphabets with two gathers, all three equations, unequal
phase offsets, exact dispatch comparisons, ragged source/current schedules,
truncation lower bounds and unused-key multiplicities. Tests do not import one
another and can be run through unittest discovery.

Two small exact controls make the new algebra especially visible. Repeating one
shared Vigenere key twice at one position gives13 possible plaintext letters;
repeating it13 times gives2. A Vigenere stage followed by a gather and a variant
stage cancels the shared key when the second phase schedule transports the first
through that gather. It leaves one plaintext but676 keys for a two-letter key.
These are controls, not proposed Kryptos mechanisms.

The root-controlled canonical command is:

```text
python -B research/scheduled_layers_K.py --output research/runs/scheduled-K-001/results.json
```

Pin every path in `SOURCE_PATHS`, including the unchanged finite-field machinery.
The script has a90-second cooperative cap and before/after hashes. Its
`--self-test` runs four tiny controls and zero K4 models.

The K4 banks are declared before execution. Both use the existing occupied-grid
surrogate and the fixed rotate90 then row-snake gather pair. The scheduled bank
has18 models: outer key lengths2/3/5, three schedule kinds, and relative offsets0/1;
the middle key has length outer+1 with column phases. The outer key is shared,
with Vigenere first and variant last. The first outer schedule uses current
coordinates; the last uses transported source coordinates. Offset zero therefore
tests a structurally cancelling outer layer.

The mixed bank has8 models: lengths1/2, alphabet triples standard/KRYPTOS/standard
or KRYPTOS/standard/KRYPTOS, and shared or separate outer keys. Its fixed schedules
are row-reset, column and transported source row-reset. Each has caps2000 nodes,
750000 relation pairs,1000 distinct texts and3 seconds, with no saved candidates
or language ranking. Incomplete cases are reported as censored. No canonical
run outcome is asserted in these notes before root executes the bank.
