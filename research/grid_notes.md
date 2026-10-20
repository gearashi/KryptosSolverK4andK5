# Occupied-grid coordinate hypotheses

The new grid tools make the user's position-dependent scrambling hypothesis testable. The finite probe concerns a specific surrogate: K4's 97 occupied cells, four rightmost letters in a 31-column row followed by three complete rows. It reproduces the layout in `research/check_physical_routes.py`. Local zero-based coordinates are row 0, columns 27–30, then rows 1–3, columns 0–30. The absolute sculpture row origin is not asserted. Earlier passages occupying other parts of the sculpture are outside this surrogate; they are not null characters or invented padding.

`kryptos/grid.py` supplies `k4_cells()`, `coordinate_routes(cells)`, `encrypt_grid(...)`, and `check_grid_model(...)`. It uses only the standard library. It neither modifies the existing layer plan nor applies a language score.

## Declared routes and coordinate phases

A permutation uses the encryption gather convention `T(P)[j] = P[permutation[j]]`. Consequently a plaintext letter at original position `i` reaches destination `j = inverse_permutation[i]`. Coordinates always refer to the explicitly supplied occupied-cell array.

The reading-route family contains rows, columns, diagonals `r+c`, and antidiagonals `r-c`. Each uses both major directions, both within-group directions, and either a constant within-group direction or alternating direction (boustrophedon). Diagonals order cells within a group by row. The family also includes the eight symmetries of the occupied set's rectangular bounding box: identity, three rotations, two axis reflections, and the two diagonal reflections. A quarter rotation or diagonal reflection swaps the rectangle's dimensions. After transformation, only occupied cells are read in row-major order. Every route and its inverse is included; duplicate permutations are merged with aliases. Many geometric symmetries are aliases of row/column scans and do not increase the distinct search space. No missing cell contributes a symbol.

For a fixed alphabet, the base model is the exact modular equation

```text
idx(C[j]) = idx(P[i]) + R[row(i)] + K[column(i)]  (mod 26).
```

Here `R` and `K` are unrestricted row and column shift keys, not ciphertext letters chosen by a word list. Four variants choose the row coordinate and column coordinate independently at source `i` or destination `j`. The probe also declares three shared coordinate-lookup offsets `s=-1,0,1`: before looking up a coordinate, replace the selected stream index `t` by `(t+s) mod 97`. These are cyclic shifts of the occupied-cell stream, not shifts of the full sculpture rectangle or evidence of wraparound in the authentic cipher. Row and column keys remain indexed by physical coordinate labels. The reusable API permits independently specified integer `row_shift` and `column_shift`, but the probe tests only equal shifts in the declared three-value set.

The finite family is all distinct generated permutations × two fixed alphabets (standard and KRYPTOS) × four source/destination choices × three shared offsets. At most 80 raw route labels and 1920 model records are possible before deduplication; the script has a hard maximum of 4096 tested records and explicitly reports any truncation. Every model has 24 crib edges and 35 key slots. Absolute coordinate translations merely rename these unrestricted key slots, so extra origin enumeration would be redundant. This does not justify ignoring the origin in a different model whose numeric coordinate directly sets a shift.

## Exact consistency and uncertainty

Build a bipartite graph with one vertex per occupied row label and one per occupied column label. A crib gives the edge equation `R[r]+K[c]=d`, where `d=idx(C[j])-idx(P[i]) mod 26`. Set `h(row)=R[row]` and `h(column)=-K[column]`; then an edge is the difference constraint `h(row)-h(column)=d`. A deterministic breadth-first propagation either finds an inconsistent cycle or fixes all vertex potentials relative to one free root per connected component. Rejection returns a closed-walk certificate with signed edge residues whose sum is nonzero modulo 26. Its signed vertex incidence is zero, so no key assignment can satisfy it.

For a feasible model let `c_crib` be the number of components in the crib graph, including isolated key slots, and `c_full` the number of components after adding the row/column edge for every text position. There are exactly `26**c_crib` key assignments. The roots form a free module over the integers modulo 26; no field assumption or division is used.

The number of distinct full plaintexts is exactly `26**(c_crib-c_full)`. To see this, changing the free roots preserves all cribs. Two such changes produce the same plaintext precisely when their potential differences vanish on every full-graph edge, which means they are constant on each full-graph component. That kernel has `26**c_full` elements. Hence `plaintext_dimension = c_crib-c_full` counts independent modulo-26 choices, whereas `key_assignment_dimension = c_crib` also includes choices that cancel in every plaintext position.

A plaintext position is uniquely forced if its row and column vertices lie in the same crib component. Otherwise its component-root difference can attain all 26 values and the position has all 26 possible letters marginally. Several unforced positions can be correlated; their number is not a count of independent free letters. The returned `plaintext_mask` preserves each such position as `?`. The solver also constructs one representative by choosing every component root as zero. It checks every crib and literally applies the row shift, column shift, and gather stages, with each shift on its declared side of the route, to reproduce the original ciphertext. That representative is a consistency witness, not a decipherment.

## Controls and reproducibility

Independent hand vectors use `P=ABCDEF`, the non-involutive gather permutation `[0,2,3,1,5,4]`, cells in a complete 2×3 grid, row shifts `[1,4]`, and column shifts `[2,7,11]` in the standard alphabet. Source/source, source/destination, destination/source, and destination/destination yield respectively `DOJJUP`, `DKSEQT`, `DOGMUP`, and `DKPHQT`. Moving both lookup indices forward by one yields `IIONIT` for source/source and `IOJMUH` for destination/destination. Other tests check contradiction certificates, forced but withheld letters, uncertainty, origin relabeling, ragged geometric routes, and exact plaintext counts against an independent enumeration of 676 tiny completions.

A separate read-only reviewer supplied a fresh three-cell ragged control with plaintext `DOG`, cells `[(0,1),(1,0),(1,1)]`, gather `[2,0,1]`, rows `{0:2,1:7}`, columns `{0:11,1:5}`, and unequal lookup offsets `(+1,-1)`. The four frame choices yield `TPA`, `NPG`, `YPV`, and `SPB`. The reviewer independently enumerated all `26**3` gauge-fixed keys per frame and confirmed the solver's counts, forced mask, and a contradiction certificate. These four ciphertext vectors are also included in the unit suite.

The initial complete probe took about 0.39 seconds. It generated 59 distinct permutations, containing all 27 earlier physical routes and adding 32, and tested all 1416 declared models. There were 1339 contradictions and 77 fits. Of the fits, 72 have plaintext dimension 10 and five have dimension 11, so none determines a unique full plaintext. The counts of forced letters among the 73 originally unknown positions were: 12 in two models; 13, 15, and 16 in one model each; 42 in 36 models; 43 in 22 models; and 44 in 14 models. Models can overlap, so their plaintext counts must not be added as if the families were disjoint.

Source-row/source-column and source-row/destination-column choices had no fits for any of the three offsets, either alphabet, or any route (354 models for each frame choice). Destination-row/source-column had 24 fits at each offset, and destination-row/destination-column had respectively one, two, and two fits at offsets −1, 0, and +1. In particular, all 118 models with the unshifted base source-row/source-column formula were contradicted. This is an exact, narrowly scoped exclusion of that formula under the declared routes and alphabets, not an exclusion of grid-based scrambling generally. All 77 representative re-encryptions and all input immutability checks passed. A separately recorded bounded run should be used as canonical evidence; this initial run wrote console output only.

```powershell
python -m unittest discover -s tests -p test_grid.py -v
python research/grid_probe.py --output PATH_TO_NEW_RESULT_JSON
```

The single-process probe hashes `kryptos/grid.py`, `kryptos/data.py`, its own script, `research/check_physical_routes.py`, and `research/check_classes.py` before and after execution. The latter two are read-only dependencies used to check that every earlier physical route is included. It records the exact cells, permutations, aliases, alphabets, phase conventions, per-model results, environment, elapsed time, limits, and fit/uncertainty histograms. It refuses to overwrite an existing result path. Source provenance for the letter stream and cribs remains in `kryptos/data.py`; the local layout is inherited from the earlier physical-route check.

No result from this finite family establishes the artist's grid method or an authentic K4/K5 plaintext. Fits can reflect the flexibility of arbitrary row/column keys. Rejection concerns only this precise occupied-cell geometry, additive fixed-alphabet key model, and declared routes/phase choices. Full-sculpture interactions, other origins with numerically prescribed shifts, different coordinate formulas, unknown alphabets, feedback, nulls, and fractionation remain outside the probe.
