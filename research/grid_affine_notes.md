# Affine coordinate shifts: a stricter grid hypothesis

The preceding row/column probe left 77 models consistent with the cribs, each allowing many plaintexts because it assigned arbitrary shifts to 35 row/column labels. This probe asks a more discriminating question: can a simple numeric-coordinate rule explain the same observations?

For every original plaintext position `i`, let `j = inverse_permutation[i]` be its final ciphertext position. The proposed shift is

```text
idx(C[j]) = idx(P[i]) + a*r + b*c + d  (mod 26),
```

where `r` and `c` are the explicitly selected physical row/column phases. Coefficients `a,b,d` independently range over all residues 0–25. Multipliers need not be invertible: they act on coordinates, while encryption still adds a known shift to each plaintext symbol. Excluding nonunits would wrongly discard legitimate instances of this model.

The family is exactly the same 59 occupied-cell gather routes, two fixed alphabets (standard and KRYPTOS), four independent source/destination choices for row and column, and three shared cyclic coordinate-lookup offsets −1, 0, +1 used by `grid_probe.py`: 1416 models total. The local K4 cells are row 0 columns 27–30, followed by rows 1–3 columns 0–30. Missing cells and earlier sculpture passages do not contribute symbols. The coordinate lookup is `cells[(selected source-or-destination index + shift) % 97]`; it is a declared stream-offset convention, not evidence that the authentic cipher wraps this way.

Unknown absolute row and column origins do not add cases here. Replacing `(r,c)` by `(r+R,c+C)` changes the constant to `d-a*R-b*C`, and every constant is already tested. This argument depends on the free constant and this affine formula; it is not a claim that origins never matter in grid ciphers.

## Exact finite algorithm

An affine key is a strict subfamily of arbitrary row/column keys: set `row_key[r]=a*r+d` and `column_key[c]=b*c` modulo 26. Therefore a contradiction in `check_grid_model` is also a contradiction for every affine triple. The new script calls that cheap graph test as a necessary-condition prefilter; it does not rerun the old grid research script or expand its route family.

For each graph-consistent model, the script enumerates all 676 ordered pairs `(a,b)`. The first known letter fixes exactly one constant,

```text
d = idx(C[j0]) - idx(P[i0]) - a*r0 - b*c0  (mod 26).
```

It then checks each remaining known position with exact integer arithmetic modulo 26, stopping a pair at its first contradiction. This tests every possible triple compatible with the first crib without division or assumptions about the modulus being prime. A rejected pair is counted under its first failing one-based plaintext position. Any survivors retain all three coefficients, full plaintext, and exact re-encryption. The re-encryption uses the separate literal stage implementation `encrypt_grid`, with row and column shifts applied on their declared sides of the gather route.

The upper bound without the prefilter is `1416*676 = 957216` coefficient pairs, each requiring at most 24 crib operations. The first crib operation derives `d`; the others are comparisons. The prefilter itself uses the 24-edge graph and has no key enumeration. The entire run is deterministic, single-process, and fixed in size; there is no statistical ranking, randomized search, bilinear extension, or automatic expansion.

## Controls and recording

Controls use plaintext `ABCDEF`, a complete 2×3 grid, gather `[0,2,3,1,5,4]`, and nonzero coefficients `(a,b,d)=(3,5,7)`. The four source/destination frame choices produce respectively `HTNNZT`, `HOXIUY`, `HTKQZT`, and `HOULUY`. A separate nonunit control `(2,13,4)` produces `EGJSLX` in the source/source frame. The earlier ciphertext `DOJJUP` passes the unrestricted row/column model but must fail this affine subfamily: its three column shifts have successive differences 5 and 4. Other checks cover an immediate graph contradiction, all 676 completions for a single crib, and translation of the coordinate origin.

```powershell
python research/grid_affine_probe.py --self-test
python research/grid_affine_probe.py --output PATH_TO_NEW_RESULT_JSON
```

The scan also runs the controls before its K4 checks. It hashes only its own script, `kryptos/grid.py`, and `kryptos/data.py` before and after execution; these are its complete non-standard-library dependencies. Output includes the precise routes and cells, per-model prefilter witnesses, coefficient work counts and first-failure histograms, any fits, environment, elapsed time, and bounds. Existing output paths are refused to preserve evidence. No earlier module, result, or pinned history is edited.

The initial local run completed in approximately 0.68 seconds. All nine controls passed. Across all 1416 K4 models, the graph prefilter rejected 1339 and passed 77. The affine check tested all `77*676 = 52052` coefficient pairs, using 106142 crib operations, and found zero fitting triples in zero models. All input hashes remained unchanged. The initial run produced console output only; a separately recorded bounded run should serve as the canonical evidence. These counts concern the K4 scan; the small preliminary controls have separate work.

A complete absence of fits would exclude only this specified affine coordinate-shift family. It would not exclude general grid scrambling, nonlinear or arbitrary row/column shifts, bilinear cross-terms, unknown alphabets, different routes, other offsets, fractionation, feedback, or dependencies on surrounding sculpture text. A fit would remain a model-consistency result requiring evidence beyond crib matching and re-encryption.
