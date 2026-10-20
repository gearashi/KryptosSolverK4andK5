# What the existing additive crib fits actually predict

This diagnostic revisits only the 1,018 feasible models already saved in
checkpoint D. It searches no additional route, period, key, or cipher model.
Both substitutions use the same fixed KRYPTOS alphabet and the original 24
literal crib positions. The purpose is to distinguish conditional predictions
from degrees of freedom, without language scoring.

## Exact per-position prediction rule

For a crib edge the shared-alphabet equations are
\(a_u+b_v=d\pmod{26}\). Write \(h(A_u)=a_u\) and \(h(B_v)=-b_v\); then
\(h(A_u)-h(B_v)=d\). Within one consistent graph component, all potentials
are fixed relative to one free additive parameter \(t\).

At any original plaintext position \(i\), transport it to final ciphertext
position \(j=\pi^{-1}(i)\), obtain its two key phases from the stated layer
order, and calculate

\[
P_i=C_j-h(A_u)+h(B_v)\pmod{26}.
\]

If the phase vertices lie in the **same crib component**, their free parameter
cancels. The plaintext symbol is uniquely forced by that model and its cribs.
If they lie in **different components**, their parameters are independently
free in \(\mathbb Z/26\mathbb Z\). Their difference ranges over all 26 residues,
so every alphabet symbol is possible at that position. Isolated key slots are
included as separate components.

These are exact marginal domains: one symbol or all 26, with no intermediate
case for this shared-alphabet additive model. Different unknown positions can
depend on the same component parameters. Therefore a collection of unforced
positions does **not** imply that all their symbols vary independently, and it
does not justify counting plaintexts as 26 to the number of those positions.

Graph connectivity is sufficient but not necessary for full plaintext
determination. The correct condition is that the two phase vertices meet in
the same component at every text position, even if the overall graph has more
than one component. A fully forced plaintext is still conditional on the
selected model and need not be the sculpture's intended message.

## Recorded diagnostic result

The canonical output is [prediction-001/results.json](runs/prediction-001/results.json),
with its [validated runner manifest](runs/prediction-001/manifest.json). Of the
1,018 previously fitted parameter records, **84 already force all 73 unknown
letters**, while the other 934 leave at least one position free. These are
model counts, not counts of distinct plaintexts or independent cipher systems;
the 84 full strings still require deduplication and assessment.

For either phrase-withholding exercise, **1,016 models force none of the held
letters, and only two models force one letter**. No selected model predicts the
entire held phrase from the other phrase alone. This exposes weak cross-phrase
constraints in the existing fits; it is not an independent success/failure test
of the intended cipher. The full-crib models collectively force 27,700 unknown
position occurrences and leave 46,614 unforced, with the complete distribution
and position masks retained in JSON.

## Retrospective phrase withholding

For each of the same previously selected models, the script also reconstructs
the graph twice:

- Train on `EASTNORTHEAST` only and inspect the 11 positions of `BERLINCLOCK`.
- Train on `BERLINCLOCK` only and inspect the 13 positions of `EASTNORTHEAST`.

It records how many held positions are forced and which symbols are predicted.
This is a **retrospective coverage diagnostic**, not an independent validation
test: all 1,018 models were selected using both phrases. In particular, every
held symbol that remains forced must match, because an existing full-crib fit
already supplies a completion. Such matches cannot be used as an accuracy
estimate, independent confirmation, or probability of authenticity.

The useful distinction is how much one phrase constrains the other within the
selected model. To conduct a genuinely prospective test later, specify a model
family and selection rule without inspecting the withheld evidence, then assess
that evidence separately. This diagnostic does not retroactively achieve that.

## Implementation and reproducibility

Run:

```text
python research/predictive_diagnostics.py --output PATH
```

The script reads only the existing layer result file, its manifest, and literal
K4 constants. It hashes those inputs and its source before and after processing,
checks the old result and data-source hashes against their original manifest,
and verifies that reconstructed component counts agree with every recorded fit.
No prior result or source file is edited.

An earlier direct execution saved `research/predictive_diagnostics.json` in
approximately 0.824 seconds with identical diagnostic counts; that file is a
secondary duplicate. Use the canonical runner result and manifest above for
provenance. The input hashes remained unchanged, every reconstructed full-crib
component count matched the stored fit, and all four tiny controls passed.

The JSON includes all 1,018 model records, 97-position prediction masks, counts
of forced versus unforced unknown positions, retrospective held-phrase masks,
aggregate histograms, deterministic coverage examples, and provenance. In each
mask, `?` denotes a full 26-symbol marginal domain. The full-crib masks also
display the 24 confirmed symbols, which remain distinct from new predictions.

Small controls use the hand-derived standard-alphabet `DKSHQQ` example from the
earlier layer derivation. Keeping plaintext positions 1=`A`, 2=`B`, and 4=`D`
forces position 5=`E`, while positions 3 and 6 can each take any of 26 symbols.
Other controls cover all six cribs, empty training, and explicit enumeration of
the one free component shift in this tiny example.

This analysis measures underdetermination and conditional predictiveness. It
does not authenticate a plaintext, estimate an English score, or revive a
rejected model. It requires one process and no application tests or broad search.
