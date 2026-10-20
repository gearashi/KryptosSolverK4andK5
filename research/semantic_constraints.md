# ENE and BC: exact distinctions and a bounded audit

Base checkpoint: K4-20261012-E. The user's proposed semantic layer is recorded in
[SEMANTIC_LAYER.md](SEMANTIC_LAYER.md). Two separate interpretations are examined
here: abbreviating literal words **after** cryptographic decryption, and using
the abbreviations themselves as repeating keys **during** cryptographic
decryption. A rejection of the latter does not reject the former.

## Literal mask and variable-length replacement

The released cribs fix 24 positions in a 97-letter plaintext. They give
`EASTNORTHEAST` at positions 22–34 and `BERLINCLOCK` at positions 64–74, using
one-based inclusive coordinates. The remaining 73 positions are unknown.

Keeping every other position and replacing only these two strings with `ENE`
and `BC` gives

\[
97-13-11+3+2=78.
\]

This is a statement about an explicit local replacement rule, not a recovered
hidden message or a prediction of K5's length. Both shortened masks retain all
73 unknown positions. Replacing other words as well would require knowing those
words and the full rule; the final length would generally change again.

The first contraction removes ten positions. Consequently `BC` occupies
positions 54–55 in this particular shortened mask, not positions 64–65 or
64–74. Original ciphertext coordinates and cryptographic crib positions must
remain attached to the 97-letter literal text. Applying the shorter cribs to
the original ciphertext silently changes the model.

## Word boundaries decide the initials

| Declared segmentation or rule | First output | Second output | Length if only these replacements occur |
|---|---|---|---|
| Initials of `EAST | NORTHEAST` and `BERLIN | CLOCK` | `EN` | `BC` | 77 |
| Initials of `EAST | NORTH | EAST` and `BERLIN | CLOCK` | `ENE` | `BC` | 78 |
| Phrase mapping `EASTNORTHEAST → ENE`, plus `BERLINCLOCK → BC` | `ENE` | `BC` | 78 |

The first row takes the ordinary compound `NORTHEAST` as one word. The second
splits that compound into two components. The third is a declared phrase
mapping; it need not be an initial-letter rule. The same unspaced literal
letters support all three descriptions, so the cribs alone do not select one.

An actual discriminating input would specify which rule is intended, supply
independent word boundaries or a codebook, or recover another phrase on which
the rules give different predictions. Producing `ENE` from a chosen compass
interpretation does not by itself justify applying a different kind of
abbreviation elsewhere. A full codebook also needs phrase matching and boundary
rules, an order for overlapping matches, and a policy for unmatched text.
Without these, neither a unique transformed message nor a meaningful final
length is defined.

## Alternative reading as two repeating keys

Literal key strings `ENE` and `BC` have declared lengths three and two. The
existing checkpoint D layer results contain all arbitrary key pairs with those
declared lengths, in either assignment, under a fixed shared KRYPTOS alphabet.
They can therefore decide this narrower key interpretation without a new
cryptanalytic search.

The selection is exactly period pairs `(3,2)` and `(2,3)`, 29 already recorded
permutations, and three layer orders (`SST`, `STS`, `TSS`): 174 parameter records.
Each substitution is additive in the same alphabet; the first `S` uses key A
and the second key B. The stored permutation convention is
`T(text)[j] = text[permutation[j]]`.

The companion script reads the existing classifications and independently
checks each selected rejection certificate. It derives the transported crib
position and both key phases from the recorded permutation and layer order,
recomputes residues from the source ciphertext and crib letters, verifies that
every key-variable coefficient cancels, and verifies the nonzero signed sum
modulo 26. It imports no graph-solver code and runs no language scoring.

The tiny audit completed on 2026-10-12 in approximately 0.424 seconds: **all 174
selected records contradict the original cribs, and all 174 contradiction
certificates passed independent verification**. Each of the six order/period
assignments accounts for 29 contradictions and zero fits. Thus literal `ENE`
and `BC` cannot be the two repeating additive keys in any of these recorded
models. This excludes neither a downstream abbreviation/codebook stage nor
other alphabets, routes, or cipher conventions. No new search or app test ran.

For a small readable witness, the identity route with period pair `(3,2)` gives
the same pair of key slots at original plaintext positions 22 and 28. In the
KRYPTOS alphabet, `F − E` is 1 modulo 26 at position 22, while `P − R` is 2 at
position 28. One key-slot sum cannot equal both values. The other recorded
routes have their own checked certificates; this example alone covers only
the identity route.

## Reproduction and input integrity

`semantic_constraints.py` was written before the tiny audit run. Its command is:

```text
python research/semantic_constraints.py
```

Use `--output PATH` to retain the full JSON for a separately recorded run. The
script hashes its source, the K4 data source, the semantic note, and the previous
layer results and manifest before and after reading. It checks the previous
results against their original manifest and pins the exact ciphertext and crib
values. Its output reports any change to the data file's hash relative to the
old run separately from equality of the mathematical inputs.

The run confirmed all input hashes were unchanged, the stored results matched
their original manifest, and the current data source matched the old run's
data-source hash. The layer-results SHA-256 was
`3509d3d35eaff9440626e1871703188906a092497516a9963fb47cbed27731e9`;
the audited script SHA-256 was
`f800556a8049c8fcb9516790f491c55e3421099a260dd2834fbe495a3298239f`.
The script records all before/after hashes and Python/platform details in its
JSON output. A separately preserved runner execution may have a different
timestamp and runtime while checking the same finite assertion.

Only a destination explicitly given by `--output` is written. The script does
not modify historical results, run new layer searches, test the application,
or start worker processes. Every resulting exclusion remains restricted to the
fixed alphabet, routes, layer equations, period assignments, and unchanged
literal crib positions of the stored run.
