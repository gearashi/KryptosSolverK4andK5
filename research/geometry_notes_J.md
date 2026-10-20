# Source-backed textual geometry, checkpoint J

This dataset represents the main copper screen's **transcribed rows and ordinal character columns**. It is not a measured three-dimensional reconstruction of the sculpture or its entire courtyard installation. The fixed coordinate transforms are reproducible hypotheses, not authenticated cipher instructions.

## Sources and preservation

- [Elonka Dunin's transcription](https://www.elonka.com/kryptos/transcript.html), retained as `source_snapshots/sculpture-J/dunin_transcript.html.txt`, records that she hand-verified it in October 2002. Its October 2003 comment explicitly records the extra tableau L and an unsuccessful attempt to align the displayed fonts with the sculpture. This supports retaining the character rows; it does not support interpreting HTML character spacing as physical distance.
- [CIA's Kryptos page](https://www.cia.gov/legacy/headquarters/kryptos-sculpture/), retained as `source_snapshots/sculpture-J/cia_sculpture.html.txt`, independently contains all 28 cipher rows and all 28 tableau rows. Source URLs and SHA-256 digests are in `sculpture_layout.json`, which records verification on 2026-10-13.

`sculpture_layout.json` preserves 28 cipher rows, 28 tableau rows, 865 cipher letters, four question marks, header blanks, variable row lengths, and the extra tableau L at zero-based ordinal cell `(14,31)`. The question marks occupy `(3,6)`, `(7,8)`, `(9,7)`, and `(24,26)`. K4 occupies 97 letter cells, from `(24,27)` to `(27,30)`, and extracts the pinned canonical ciphertext exactly. K2 is retained as inscribed (369 letters); the subsequently disclosed corrective S is not silently inserted into this coordinate dataset.

The upper and lower 14-row blocks are concatenated into row numbers 0 through 27. Their physical gap, curvature, distances, bearings, orientation and registration against the tableau are explicitly unknown. The file covers neither additional courtyard objects nor an authenticated K5 ciphertext.

## Implemented API and hypotheses

`kryptos.sculpture` exposes `load_layout`, `cells`, `section_cells`, `section_text`, `transform_coordinate`, `transformed_shape`, `route_mapping`, `fixed_routes`, `fixed_overlay`, and `apply_gather`.

Loading verifies retained source digests and independently re-extracts the Dunin transcript's character rows. Each cell has its panel, row, ordinal column, symbol, and applicable section/letter index. Nonletter glyphs remain available through `cells`; section routes visit only occupied letter cells.

The eight rectangular symmetries (identity, three rotations, two axial reflections, transpose, antitranspose) act on the complete 28-by-33 cipher bounding rectangle. Each is followed by row-major or row-serpentine traversal, using absolute transformed-row parity for serpentine traversal and skipping unoccupied cells. This produces 16 distinct K4 permutations. Every permutation has an explicit source/destination coordinate mapping and an inverse.

Eight fixed overlays transform cipher coordinates and register their top-left origin against the untransformed tableau's ordinal grid. Missing coordinates and blank cells remain missing. There is no wrapping, inferred physical alignment, fitted offset, or optimized overlay. Overlay letters are an exploratory output and have not been established as a key or instruction.

## Verification and reproducibility

The seven tests in `tests/test_sculpture.py` passed. They include an independently specified 2-by-3 rotation, noninvolutive gather inversion, missing-cell handling, inscription anomalies, and source validation.

The root's canonical `runs/geometry-J-001/results.json` confirms K1 and K2 literal additive roundtrips with their known alphabet/keys, the 336-letter K3 reference roundtrip, the exact K4 extraction, all 16 route inverses for each section and the full 865-letter stream, and unchanged inputs. A K4 plaintext roundtrip is intentionally not claimed.

To create a fresh verification artifact:

```text
python research/geometry_benchmarks.py --output research/runs/geometry-J-NEW/results.json
```

The runner's eight input paths are exposed as `research.geometry_benchmarks.SOURCE_PATHS`. The run records before/after SHA-256 digests, all K4 cell mappings, route permutations and overlays. This is a geometry/data regression, not a K4 search.

## PK2 source handoff

`source_snapshots/sculpture-J/pk2_fixture.json` preserves the 350-letter official challenge ciphertext, complete derived plaintext, width 7, and zero-based column read order `[1,3,4,0,5,2,6]` (keyword MARGINS). The convention is row-major fill of a 50-by-7 rectangle, then top-to-bottom reading of each column in the specified order.

The official ciphertext is retained in the existing [Paradigm challenge asset](https://www.paradigm.xyz/kryptos-ctf/_next/static/chunks/0h1ap~1.6ljs6.js) cache. The [firsthand solver result](https://raw.githubusercontent.com/benjacasas02/independent-cryptography-research/main/research/paradigm-kryptos/selected-results/02_pk2_columnar_solve/README.md) gives the order and an abbreviated plaintext. The full plaintext was reconstructed locally from the official ciphertext and published order; it matches both unabbreviated prose portions and the published plaintext hash prefix. It is not falsely attributed as a fully printed source quotation. All 350 letters pass a literal encryption/decryption roundtrip; downloaded code was not executed. The fixture contains exact source paths, URLs and hashes.

The canonical `research/runs/columnar-J-001/results.json` independently withheld the known column order. Supplying only width 7 and 21 plaintext letters (the first fourteen and last seven) uniquely recovered the published order and full 350-letter plaintext, with literal re-encryption. Those are artificial benchmark cribs, not official challenge clues. The seven-case columnar artifact records all checks passing and unchanged inputs; its broader algorithm audit belongs to the engine/interface workstream.
