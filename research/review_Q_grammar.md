# Independent Q62/Q64/Q65 recipe review

**Verdict: computationally verified only in the stated finite range.** The
algebraic merge invariant passes under its declared hypotheses. No remaining
implementation counterexample was found after the corrections below. This is
an independent review by the models agent, which did not author the recipe
compiler or grammar, using independently written literal encryption/enumeration.

## Claim and dependencies

The quantified object is a finite S/T prefix on a fixed-length text in one
known 26-symbol alphabet. Every S stage has its own unrestricted key slots.
Encryption is a signed permutation of input coordinates plus a key-dependent
offset. The grammar may merge prefixes only when their signed input map and
the F2/F13 column images of their offset matrices agree. The same subsequent
gather or independent substitution must preserve that equivalence. Every
original stage-choice path must remain recoverable from the provenance DAG.

The CEGIS object is a finite explicit recipe bank with one fixed unknown key
vector per recipe, shared across all supplied example pairs. Accepted keys
must replay every pair; rejection needs an inconsistent accumulated equation
system. Changing priority may change work but not accepted recipe indices.

Dependencies are the literal S/T convention; `recipe_algebra.compile_recipe`;
row-space normalization in `family_identity.canonical_coset`; the independent
coordinatewise CRT lift; and `constraint_algebra.IncrementalField`. No external
theorem citation or unverified source is load-bearing.

| Obligation | Review outcome |
| --- | --- |
| Literal compiler agrees with signed-permutation-plus-offset formula | Passed source reconstruction and 972 literal checks. |
| Two modular images determine the same Z/26 offset subgroup | Passed: independent key residues in F2/F13 lift coordinatewise to one modulo-26 key vector. |
| Same next independent operation preserves equal prefix families | Passed: gather permutes both images; substitution multiplies by its declared sign and adds the same new independent image. |
| Merging preserves original syntax multiplicity | Passed DAG depth/edge review and exact multiset reconstruction of all 18 syntax paths, including duplicate-choice boundary controls. |
| Key witnesses remain inside supported reconstruction bounds | Passed after worst-case total key-slot preflight was added. |
| CEGIS rejects only accumulated contradictions | Passed source review and 80 comparisons against exhaustive shared-key feasibility. |
| Accepted CEGIS witnesses satisfy every pair | Passed 312 independent literal pair replays. |
| Priorities and initial example count preserve answers | Passed both modes and one/three initial examples in every finite case. |
| Resource cutoff claims remain partial | Passed node, transition and pair-check limit controls. |
| Full arithmetic work is measured | Not claimed: canonicalization calls/input coefficients are counted; elimination arithmetic and serialization costs remain explicitly unmeasured. |

## Findings and corrections

1. Initial `literal_encrypt` passed a literal alphabet to `ciphers.encrypt`,
   whose API accepted only `standard`/`kryptos`. The minimal valid example
   `AB -> BC` under a period-one Vigenere B key raised `ValueError`.
   The author replaced this call with literal index arithmetic. Current replay
   starts at `recipe_grammar.py:135` and accepted-key checks at line 219.
2. The first output named its count `distinct_transformation_families`, although
   its intentionally conservative signature requires equal signed input maps.
   The count now says `retained_transformation_classes` (line 111) and explains
   that different classes can describe equal pointwise transformation relations.
3. Slot-by-slot validation did not ensure every retained syntax path fit the
   256-key-slot reconstruction limit. The author added worst-case preflight at
   lines 69–78, so a cheaper merged representative cannot hide an unsupported
   original path.
4. Signature row reductions were absent from compilation work counters. Lines
   48–53 now count canonicalization calls and input coefficients. This is not a
   claim that total scalar arithmetic has been measured.

These line references describe the audited source digest below and may shift
after unrelated edits. No production source was modified by this reviewer.

## Finite evidence and reproduction

`research/review_Q_grammar.py` fixes the domain before execution. It checks 18
syntax paths, 108 complete literal output-image comparisons on six plaintext
probes, and 972 literal-versus-matrix computations. CEGIS checks ten recipes,
two alphabets, five generating methods, valid and perturbed example banks, both
priorities and both initial-example settings: **80 comparisons, 36,414 exhaustive
key vectors, and 312 accepted witness pair replays**. Keyless, singleton,
duplicate-syntax and bounded-stop controls are included.

The completed v2 computation record is
`research/runs/release-Q-review-grammar-003/manifest.json`; the result contains
all before/after input hashes. The audited `recipe_grammar.py` SHA-256 is
`4ea960b97e07483aa2b3c67fb97c5aa7665b8eabfe2fea46896c5afe83f8d740`.
Earlier completed runs 001 and 002 retain their original hashes. Subsequent
accounting/boundary edits changed inputs, so run 003 is the current-source
review evidence. Both its before/after hashes and manifest validation pass.

To rerun the finite checks into a fresh file:

```text
python -B research/review_Q_grammar.py --output research/runs/NEW-DIRECTORY/result.json
```

To verify the saved provenance, use the installed computation-audit
`scripts/validate_manifest.py` with the manifest path and `--root` pointing to
the project. A completed manifest is execution evidence, not a universal theorem
about all recipes. Shared alphabets, unrestricted independent stage keys,
bijective gathers and fixed text length are essential restrictions. Shared
key identities, nonlinear alphabets, guessed K4 examples and authentication of
Kryptos remain outside this review.
