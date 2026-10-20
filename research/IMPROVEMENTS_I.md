# Checkpoint I: measured recovery and new constrained hypotheses

Completed 12 October 2026 local time, after the user returned home and authorized CPU/GPU tests. Canonical K4 input is unchanged: 97 letters, 24 released plaintext positions, source SHA-256 `2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2` for `kryptos/data.py`.

**Neither K4 nor K5 has been deciphered.** This checkpoint delivers usable investigation tools and measured tests. A crib fit, high language rank, or successful re-encryption under a flexible invented model is not authentication.

## What changed

- Key recovery receives ciphertext, cribs and a declared family, rather than the answer key. It returns partial masks, exact contradictions, work counts, and deduplicated complete keys/routes.
- Compiled additive layer plans separate fixed graph structure from input values. They count distinct plaintexts after redundant key offsets cancel, enumerate only families within explicit limits, and check every candidate by literal encryption.
- Append-only journals pin configuration, materialized inputs, source hashes and job identities. Interrupted experiments resume exactly; stale or malformed records are rejected. Budgets count raw model/plaintext completions, including duplicates.
- The grid implementation distinguishes a letter's source and destination coordinates, supports ragged occupied cells, and generates 59 distinct reading routes. Numeric row/column formulas are tested as a stricter subfamily.
- Explicit-corpus language models preserve provenance and score only complete n-grams outside the clues. English, Spanish, French, Italian and Latin pilot models are saved. Semantic codebooks/initials require explicit boundaries and preserve unknown regions.
- The root CLI exposes `recover`, `layers`, `grid`, `residues`, and `doctor`. Language and semantic modules have separate CLIs. ASCII input validation preserves positions, limits are validated even for impossible models, and existing evidence files are not overwritten.
- Each root cipher result now includes its search technique, supplied assumptions, recovered values, normalized input/request hashes, source hashes, and limits. Complete candidates include an exact encryption recipe and independently replayed intermediate strings through to the ciphertext. Partial keys/plaintexts, arbitrary grid witnesses, and residue-only constraints have distinct labels. The public `replay_recipe` helper rechecks saved recipes without rerunning the search. This directly implements the user's request to show how a possible solution was obtained.

[Ten runnable examples](../docs/CLI_EXAMPLES.md) cover recovery, layered and grid models, parity, semantic contraction, and model training/scoring.

## Recovery and controls

| Experiment | Actual result | Scope |
|---|---|---|
| [Historical recovery](runs/recovery-001/results.json) | K1, K2, corrected K2 and K3 recovered within supplied families; 118 models, 1,061 crib checks | Alphabets, correct crib positions and search families are supplied. Some K2 alternatives remain. This is not unrestricted historical discovery. |
| [Synthetic matrix](runs/recovery-matrix-001/results.json) | True plaintext present in all 12 cases; first-ranked in only 3 | Two K3 adaptations, three layer orders, two key-length pairs, four authored text contexts; all 1,891 raw completions re-encrypt. |
| [K4 and controls](runs/calibration-002/results.json) | K4 has 214 distinct completed candidates; all 8 shuffled and 8 uniform controls score higher at their maxima under the old heuristic | Same 1,056 parameter records per input; at most one free plaintext parameter; identical selection and budget. No budget skips. |
| [Fixed-model rescoring](runs/rescore-recovery-002/results.json) | English trigram model improves truth rank in 6 cases, worsens none, but still puts truth first in only 3 of 12 | All saved candidates retained. Exact smoothed-count products resolve score ties; no retraining or parameter tuning on these outcomes. |
| [Published PK1/PK3 fixtures](runs/pk-benchmarks-001/results.json) | Full official ciphertexts reproduce exactly from independently published plaintexts and keys; PK1 recovers uniquely with keys withheld | Full 192/280-letter messages. Methods, periods and 24 artificial plaintext letters are supplied. The original cap of 676 correctly skips PK3's larger family. |
| [PK3 complete recovery](runs/pk3-extended-001/results.json) | All 17,576 candidates checked and re-encrypted; published plaintext ranks first with no score tie | Same model and clues; only the declared budget increases. Runtime 11.42 seconds on one CPU process. The true text is not algebraically unique. |

With the trained scorer, 5 of 8 shuffled controls and 5 of 8 uniform controls still exceed K4's best score. This is not evidence of a promising K4 decryption. Sixteen exploratory controls and related synthetic examples do not justify a calibrated solution probability. The corpus scorer remains available as an alternative; it is not promoted as a reliable solution detector.

The earlier smaller [calibration pilot](runs/calibration-001/results.json) used zero free dimensions and four controls of each type. Its historical sources are preserved under `source_snapshots/calibration-001/`; its manifest is not a freshness claim for later source revisions.

The [PK benchmark source notes](pk_benchmark_notes.md) distinguish official ciphertexts, first-person solution reports, and our own independent literal verification. No downloaded code was executed and no answer was submitted. PK recovery is method-known, with an artificial supplied crib mask; two published examples do not establish blind method discovery or general scoring reliability.

## Sculpture-grid hypothesis

The local geometry has four letters at columns 27–30 in its first occupied row, then three complete 31-letter rows. Row numbering starts locally at zero. Earlier passage cells are outside this model; they are not invented nulls.

[Grid results](runs/grid-001/results.json): 59 routes × 2 alphabets × 4 source/destination coordinate combinations × 3 shared lookup offsets = **1,416 models**. Exact modular constraints reject 1,339 and permit 77. Of the survivors, 72 permit `26^10` distinct plaintexts and 5 permit `26^11`. Even those forcing many individual unknown letters remain heavily underdetermined. They are consistency witnesses, not decipherments.

[Affine grid results](runs/grid-affine-001/results.json): restricting the shift to `a*row + b*column + d (mod 26)` leaves **zero fits** in the same model family. Graph constraints reject 1,339 before enumeration; the other 77 require 52,052 coefficient pairs, with `d` fixed by one crib. Noninvertible coefficients are included. Independent hand cases, full small coefficient enumerations, source/destination indexing and coordinate-origin changes were checked.

This does not exclude nonlinear coordinate rules, keyed column permutations, a different alignment, whole-sculpture/tableau overlays, null conventions, or substitution mixed with those operations. A further geometry search needs a fixed coordinate dataset and character-consumption rule.

## Fractionation, languages and semantics

[Fractionation results](runs/fractionation-001/results.json): no fit among 776 specified mixed-radix rectangular models (two alphabets, two orientations, 97 periods, both directions). Each transform passed literal round-trip and independent integer-formula checks. This is an explicitly defined rectangular extension, not an assertion that Sanborn used it; other fractionation methods remain open.

[Multilingual pilot](models/multilingual-001/artifacts/results.json): five models each trained on 50,000 letters from one fixed public-domain book. Each model scored 20 later, nonoverlapping 97-letter windows above all eight paired shuffles per window: 160/160 pairwise wins per model. The same 24-position mask leaves 73 letters and 67 complete trigrams in every comparison. These local ordering checks do not establish language identification or performance across genres. Introductions, one-book bias, removed diacritics and nearby held-out passages are recorded limitations. The 46 prior complete K4 strings are ranked separately within each model; raw scores do not select a winning language. See [source/split protocol](multilingual_notes.md).

The semantic API implements supplied codebooks and supplied word boundaries. `EAST|NORTHEAST` gives initials `EN`; `EAST|NORTH|EAST` gives `ENE`. Mapping the complete phrases to `ENE` and `BC` is a separate explicit rule. This supports the user's interpretation hypothesis without pretending to recover missing text or generate K5.

## Reddit hypotheses

The [bounded subreddit review](reddit_theories.md) separates posted hypotheses from verified artist statements and records indexing problems and missing rules.

[Parity results](runs/parity-001/results.json): the suggested equality `(A0(cipher_i) + i) mod 2` for repeated plaintext letters is correct across all 24 cribs: 13 agreeing pairs, representing 11 independent equalities. Under an unknown bijective alphabet, the observed letter classes leave **1,716 balanced residue partitions**. Independent small enumerations and witness checks agree.

This connects directly to the user's grid idea. In the declared K4 geometry, one-based stream position `i` satisfies `31*r + c = i + 26` with zero-based local row/column coordinates. Since 31 is odd, `i mod 2 = (r+c) mod 2`. The same observation is therefore a checkerboard constraint on those occupied cells. This is an algebraic restatement of the position pattern, not a second independent clue or proof of a grid-based cipher.

All 52 stricter constant-step substitution models (26 steps, two fixed ciphertext alphabets) fail. That does **not** reject the broader alternating-parity keystream hypothesis. None of the 46 earlier fully determined candidates passes its complete-text parity filter; they are tagged against this optional assumption, not discarded globally. No significance estimate is claimed for a pattern found after inspecting the data.

[K3 running-key inventory results](runs/running-key-001/results.json): among 2,880 fixed models, 1,829 have letter-count deficits excluding every possible following transposition, and 1,051 pass. The bank covers 240 nonwrapping 97-letter K3 plaintext windows, both directions, two alphabets and three modular equations. Passing permits an arbitrary completion and is weak evidence. All 17 hand controls passed. This first bank tests substitution **before** transposition; the reverse stage order is a separate experiment. See [the exact convention](running_key_notes.md).

[Transposition-before-substitution results](runs/running-key-after-route-001/results.json): the complementary 2,880-model bank rejects 2,258 by exact inventory deficits and permits 622. All 22 hand controls passed. Every survivor includes the fully inverted intermediate string, an explicitly arbitrary plaintext/permutation witness, its inverse, and full re-encryption. These witnesses prove feasibility only; their letter order is not inferred from the sculpture or natural language. The distinct stage orders cannot be conflated. See [the complementary convention](running_key_after_route_notes.md).

The [specific PK-thread comment review](../docs/PK_CHALLENGE_REVIEW.md) covered seven directly visible and two additional indexed comment bodies, with collapsed/later replies unverified. The live official record confirms all ten practice challenges solved; this does not establish K4's method. Reported PK5 layering motivated the reverse-order test above. A quoted 2005 interview discusses the meaning of different sculptures, not a mathematical difference between the four cipher algorithms.

Whole-panel/tableau overlays and compass geometry currently lack sufficiently verified coordinates and fixed decoding rules. A joint K3+K4 pure letter permutation preserving canonical K3 still inherits the K4 letter-inventory contradiction; adding empty cells alone cannot repair it. Inserted demonstration text in a Reddit palimpsest example is not a discovered hidden passage.

## Validation, resources and remaining work

[All 112 available unit tests passed](runs/unit-suite-002/results.json), with no failures or skips, in about 0.91 seconds. Ten original example commands and five saved explanation/replay examples succeeded. This covers the research modules and preserved search primitives; it is not a dashboard/browser, BOINC or GPU load test. Independent reviews covered graph mathematics, residue counts, literal encryption, affine/grid indexing, CLI validation and result provenance. A further 26 fresh hand cases verified the explanation recipes across cipher conventions, route directions, aliases, grid frames and partial data. All 2,880 reverse-order inventory records were independently replayed, including every rejection certificate and all 622 full consistency witnesses.

The final suite record pins the local transitive research imports and records seeded calibration controls (41 and 20261012). It supersedes the earlier 101-test record's incomplete dependency list and coarse randomness description. The earlier CLI/test sources remain in `source_snapshots/unit-suite-001/`; historical files were not overwritten.

All **14 current successful run manifests** passed final input/output hash validation. The [validation record](checkpoint-I-validation.json) identifies each checked manifest. This verifies artifact consistency and declared execution status, not the mathematical interpretation of a cipher hypothesis.

Before full testing, the read-only WSL running-distribution query returned no entries; no Ubuntu `n5_runner` process/window was exposed. There was no active window to send Ctrl+C to. The user had explicitly authorized resuming CPU/GPU tests. The machine reports 8 logical CPUs and an RTX 2060 with 6 GB VRAM. These exact probes ran in bounded CPU processes, mostly under a few seconds each. No GPU kernel, driver installation, or persistent background search was needed or launched.

The first rescore attempt failed before producing results because journal job IDs are strings while candidate route IDs are integers. Its source is preserved under `source_snapshots/rescore-recovery-001/`; run `rescore-recovery-002` is the corrected successful record. Failed attempts and previous results are retained.

Remaining promising work is conditional: structured unknown alphabets retaining cyclic shifts, independently justified full-sculpture overlays or transpositions, broader corpus validation, and explicit intermediate-language/codebook rules. These are not exhausted by finite model scans. There is still no authenticated public K5 ciphertext in the reviewed sources, so no fabricated K5 target is searched. No candidate was sent to an external verifier or paid service.
