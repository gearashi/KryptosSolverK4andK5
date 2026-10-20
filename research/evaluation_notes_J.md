# Document-separated language evaluation, checkpoint J

`evaluation_J.py` implements a frozen, bounded evaluation of five new grouped trigram models and a small complete candidate-selection pipeline. It leaves the original single-book models unchanged and does not search or score K4. The protocol was fixed before the full evaluation; results belong in a new run artifact rather than overwriting earlier experiments.

## Independent documents

Each language uses two training books by different authors and one validation book by a third author. Catalog metadata, full raw texts and their licenses are retained. The Project Gutenberg catalog's recorded rights statement is “Public domain in the USA.” No claim is made about other jurisdictions. `evaluation_corpora_J.json` records source URLs, raw/metadata SHA-256 digests, local paths, document roles, author/title/language metadata, and normalization evidence. `source_snapshots/evaluation-J/retrievals.json` records the new retrievals.

| Language | Training books | Held-out book |
| --- | --- | --- |
| English | [Austen, Pride and Prejudice (1342)](https://www.gutenberg.org/ebooks/1342); [Dickens, A Tale of Two Cities (98)](https://www.gutenberg.org/ebooks/98) | [Doyle, The Adventures of Sherlock Holmes (1661)](https://www.gutenberg.org/ebooks/1661) |
| Spanish | [Cervantes, Don Quijote (2000)](https://www.gutenberg.org/ebooks/2000); [Valera, Pepita Jiménez (17223)](https://www.gutenberg.org/ebooks/17223) | [Pérez Galdós, Marianela (17340)](https://www.gutenberg.org/ebooks/17340) |
| French | [Hugo, Les Misérables I (17489)](https://www.gutenberg.org/ebooks/17489); [Flaubert, Madame Bovary (14155)](https://www.gutenberg.org/ebooks/14155) | [Proust, Du côté de chez Swann (2650)](https://www.gutenberg.org/ebooks/2650) |
| Italian | [Collodi, Pinocchio (52484)](https://www.gutenberg.org/ebooks/52484); [Manzoni, I promessi sposi (45334)](https://www.gutenberg.org/ebooks/45334) | [De Amicis, Ricordi d'infanzia e di scuola (61885)](https://www.gutenberg.org/ebooks/61885) |
| Latin | [Caesar, De Bello Gallico I–IV (218)](https://www.gutenberg.org/ebooks/218); [Virgil, Aeneidos (227)](https://www.gutenberg.org/ebooks/227) | [Augustine, Confessiones (33849)](https://www.gutenberg.org/ebooks/33849) |

The five first-listed training books reuse existing raw copies in `research/corpora`; the other ten books and all fifteen metadata snapshots are in `research/source_snapshots/evaluation-J`. This is a historical-literature sample, including verse; it is not a broad modern-language benchmark. A book's catalog language does not certify every selected passage, which may contain prefaces or editorial material.

## Frozen scoring protocol

- Strip the exact Gutenberg boundary markers using the existing `corpus_body` routine. Decode UTF-8, apply NFKD, remove combining marks, uppercase, and retain only ASCII A–Z. Record dropped non-ASCII letters and full normalized-body hashes. Spaces are removed.
- Train each model on normalized half-open span `[5000,55000)` from each of its two books: 100,000 letters and 99,996 trigrams per language. Count documents separately so trigrams never cross the document boundary. Order 3 and additive smoothing 0.1 are fixed.
- Take twenty nonoverlapping 97-letter held-out windows per language at offsets `5000 + 1000*i`, for 100 total windows. Reject complete held-out windows appearing in either training excerpt. This is not a claim that no short n-grams overlap.
- Exclude the same 24 positions used by the K4 cribs: zero-based 21–33 and 63–73. Preserve the book's actual letters; do not insert the K4 crib phrases. Score the remaining 73 positions through the 67 trigrams fully outside the mask.
- For each held-out window, generate eight seeded controls by shuffling only unmasked letters, preserving the full letter inventory and masked letters. The 800 comparisons record both the correct-language model score and the maximum score across all five models; the controls undergo the same maximum selection.
- Record every positive/control score, language selection, source span, text hash, seed, per-language comparison totals and language-label confusion. No threshold is tuned on these targets. Model creation timestamps can vary; separate hashes of counts/settings support deterministic comparison.

The master seed is 20261013. Every other fixed setting and derived seed appears in the executable protocol and saved output. Win counts, classifications and ranks are empirical diagnostics, not calibrated language probabilities or a universal false-positive rate.

## Complete bounded selection controls

The first two held-out windows per language supply ten independently authored plaintext inputs. Each is encrypted under a declared planted model: two additive substitutions using the KRYPTOS alphabet, key periods 3 and 2, one fixed sculpture route, and one of SST/STS/TSS. The keys follow a deterministic formula independent of plaintext content. The source plaintext letters at the same 24 positions serve as artificial supplied cribs.

For each input, a paired null shuffles the whole ciphertext, preserving its inventory. Both positives and nulls undergo the identical bank of 16 fixed geometry routes × 3 orders × 4 × 4 period pairs: 768 models per input. The solver receives neither the generating route, order, periods, keys nor language. It completes only feasible models with plaintext dimension zero, records feasible higher-dimensional models as excluded, re-encrypts every completion literally, deduplicates identical plaintexts across models, scores each under all five language models, and ranks by the maximum score with a fixed lexical tie break. At most 768 raw completions occur per input.

This gives twenty input-level searches and 15,360 model checks, with exact truth ranks assessed only after recovery. The output records all ranked candidate plaintexts, representative keys/models, multiplicities, scores, null outcomes and ties. It does not certify broader period ranges or the new unknown-alphabet, unknown-column-order, fractionation, semantic or unrestricted search procedures. Since the generating family is included in the bank, successful recovery tests implementation and selection within that declared family, not identification of K4's actual method.

## Running and checking

The small self-test passed: independent document-boundary counts, mask/inventory preservation, and a literal known-answer pipeline check. A preflight confirmed all ten planted models have plaintext dimension zero and the bank contains exactly 768 models.

The parent completed the canonical run at `research/runs/evaluation-J-001/artifacts/results.json`, with the outer manifest at `research/runs/evaluation-J-001/manifest.json`. Runtime reported by the evaluation was 7.0636 seconds; all 42 tracked evaluation inputs were unchanged. Five model files accompany the result in the same `artifacts` directory.

- In each language, all 160 positive-versus-shuffle comparisons favored the held-out text, both with its own language model and after maximizing across all five models. There were no ties. All twenty held-out windows per language selected their catalog language: 100 of 100 total.
- All ten planted plaintexts were recovered at rank one. Seven cases had only one distinct completed plaintext and three had two. The rank result therefore supplies limited stress on candidate selection; it is not a large ambiguous-candidate benchmark.
- None of the ten paired null inputs produced a completed candidate. Every null model was contradicted algebraically before scoring. This exercises the declared crib/model filtering pipeline but does not estimate a score threshold's false-positive rate on surviving near-plausible candidates.

These results were inspected after the frozen run; no corpus, parameter or seed was changed in response. The nulls are deliberately simple inventory-matched controls, and the 24 supplied letters are strong constraints. More difficult accepted-null and near-family controls would be a separate future protocol, not an interpretation of this run.

```text
python research/evaluation_J.py --self-test
python research/evaluation_J.py --output research/models/evaluation-J-NEW
```

The output directory must be new. The full run writes five model JSON files and `results.json`. `research.evaluation_J.input_paths()` supplies the exact 42 input files for the canonical runner: twelve code/manifests/source records plus fifteen raw books and fifteen metadata snapshots. Before/after input hashes must match before output is written. The saved result includes all protocol settings, corpus coverage, source manifests, detailed controls and elapsed time. An outer 180-second process cap was recommended to the parent; this is a bounded run, not a persistent background job.
