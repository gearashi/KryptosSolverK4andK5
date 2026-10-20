# Checkpoint H: candidate quality and next experiments

Neither K4 nor K5 has been deciphered. This checkpoint addresses the user's
question about smart improvements. The main limitation is selecting and
testing informative cipher hypotheses, rather than raw processing throughput.

## Implemented improvements

The prototype's English score previously included the very clue letters its
description said it excluded. `kryptos/scoring.py` now accepts excluded
positions, omits every feature touching those positions, and never joins the
remaining runs across a gap. Every engine scoring path supplies the same mask.
Candidates report the number of scored characters and whether language evidence
is available; complete masking returns a finite neutral zero. Appended
clue/test-phrase features and inactive long tetragram entries were removed from
the active scoring tables. This remains an uncalibrated English heuristic.

Six targeted regression checks passed, including a one-iteration annealing
check. An independent read-only review found no remaining masking defect.
These were small unit checks, not the full application suite. Earlier exact
research checkpoints did not use this scorer and are unaffected by the bug.
The original [scoring review](scoring_review.md) documents pre-fix behavior.

The [predictive diagnostic](predictive_diagnostics.md) revisits the 1,018
already feasible shared-alphabet models. Exactly 84 force all 73 unknown
letters; 934 retain uncertainty. With either complete phrase withheld, 1,016
models predict none of its letters and two predict one. This is retrospective
coverage, not independent validation: all models were originally selected with
both phrases. A full-crib prediction is conditional on its hypothetical model,
not a new authenticated clue.

[Complete-string inspection](runs/complete-predictions-001/results.json)
groups the 84 full predictions into **46 distinct plaintexts**. All are saved
with their generating models and ranked using the same 73-character mask.
Visual inspection found no coherent English outside the forced clues. This is
a qualitative assessment, not a rejection of other languages or a further
encoded layer. Identical plaintexts do not imply equivalent cipher systems;
partial masks were not grouped because they may hide different correlations.
The [inspection manifest](runs/complete-predictions-001/manifest.json) and
[prediction manifest](runs/prediction-001/manifest.json) both passed validation.

## Prioritized next work

1. **Demonstrate recovery, not just correct decryption.** Give the search
   synthetic messages encrypted with the verified K1/K2 conventions and the
   verified equivalent K3 transform, while hiding keys/routes from it. Include
   short 97-character examples and the same sparse clue pattern as K4.
   Record recovery frequency and work performed. Known-answer re-encryption
   already verifies conventions; it does not establish that the search can
   discover an unknown key. These synthetic tasks are tests of capability,
   not evidence that K4 uses those methods.
2. **Calibrate the entire selection process.** Freeze a model family, search
   budget, score, and success rule before comparing K4 with randomized control
   ciphertexts. Use more than one stated null model, such as preserving letter
   inventory and independent uniform letters. Run the same fitting and ranking
   process on every control, including selection of its best candidate. Report
   score and recovery distributions rather than treating a crib fit or isolated
   word as evidence. Deduplicate known equivalent models where proved.
3. **Add structure to the user's layered-cipher hypothesis.** The arbitrary
   table checker is deliberately more permissive than keyed cyclic alphabets.
   A useful next exact model asks whether *some completion* of the partial
   tables can make all phase maps powers of one common 26-cycle per stage.
   Testing only the arbitrary representative currently saved would be invalid:
   another completion might work. Define the alphabet convention explicitly;
   independent input/output alphabets need a different formulation. A justified
   new transposition family also matters: all previous exclusions cover only
   the recorded 29 routes and stated period ranges. Another genuinely different
   family, such as coordinate fractionation, should be a separate experiment
   with its own conventions and positive controls.
4. **Improve language assessment without choosing a desired answer.** Replace
   the hand-selected English features with independently trained character
   models, comparing English and separately calibrated Latin-script languages.
   Keep crib positions excluded, preserve boundaries, and report each language's
   control distribution. A low English score cannot rule out another language,
   codebook, or intermediate layer. Multilingual ranking still cannot validate
   an arbitrary plaintext/cipher pairing.
5. **Make the semantic proposal predict something.** Preserve the literal
   EASTNORTHEAST and BERLINCLOCK cribs. Treat ENE/BC as a possible later operation,
   with fixed segmentation and a consistent rule for other words. Require a
   prediction beyond the phrases used to invent the rule. Directions, locations,
   initials, and NATO codewords are distinct hypotheses. No authenticated K5
   ciphertext has been located in the recorded source review; do not manufacture
   it from an unconstrained extraction.

The recommended order is recovery benchmarks, whole-pipeline controls, then one
specified new cipher family. GPU acceleration becomes useful after a measured
search identifies an expensive operation and can distinguish recoverable
examples from controls. No large CPU/GPU search or full app testing ran here;
the requested Ctrl+C interruption of Ubuntu's `n5_runner` remains unconfirmed.
