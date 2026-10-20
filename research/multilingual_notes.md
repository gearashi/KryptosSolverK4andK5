# Fixed multilingual pilot: protocol and execution record

The fixed protocol below was executed successfully in [multilingual-001](models/multilingual-001/artifacts/results.json). All five models and provenance files are retained under that run's `artifacts/` directory. Each model's 20 held-out windows exceeded their eight paired shuffles, giving 160/160 pairwise wins per model under the stated limitations. The English model was subsequently evaluated, without retuning, in [fixed candidate rescoring](runs/rescore-recovery-002/results.json).

Base checkpoint: **K4-20261012-H**. `research/multilingual_pilot.py` is a bounded runner using the stable, dependency-free `kryptos.language` module. The following protocol was declared before execution; the paragraph above records its completed outcome.

## Explicit source snapshots

The parent task verified the primary Project Gutenberg metadata for language and public-domain status in the USA, and retained the complete downloaded text files, including headers and license notices. This subtask read the supplied local copies; it did not download or independently recheck external licensing metadata. The runner pins all five raw file SHA-256 hashes observed during preflight and refuses altered snapshots.

| Label | Supplied work | Primary metadata | Body letters after declared normalization |
|---|---|---|---:|
| English | Jane Austen, *Pride and Prejudice* | https://www.gutenberg.org/ebooks/1342 | 563,939 |
| Spanish | Miguel de Cervantes Saavedra, *Don Quijote* | https://www.gutenberg.org/ebooks/2000 | 1,651,320 |
| French | Victor Hugo, *Les misérables Tome I: Fantine* | https://www.gutenberg.org/ebooks/17489 | 512,877 |
| Italian | Carlo Collodi, *Le avventure di Pinocchio* | https://www.gutenberg.org/ebooks/52484 | 194,755 |
| Latin | Julius Caesar, *De Bello Gallico, I–IV* | https://www.gutenberg.org/ebooks/218 | 123,354 |

Each cached file has exactly one ordered Gutenberg START/END marker pair and enough normalized text for the fixed split. One book per language is an author/work pilot, not a representative corpus or general classifier. The English training prefix is introductory criticism, and the Spanish prefix includes contents/prologue material. Skipping a fixed 5,000 letters does **not** guarantee removal of all introductions. The protocol records this limitation without choosing a more favorable split after inspection.

## Declared preprocessing and split

Extract text between the unique START and END marker lines; retain everything else inside, including internal headings and notes. Apply Unicode NFKD, remove combining marks, uppercase, then retain only ASCII A–Z. Spaces, punctuation and remaining non-ASCII letters are removed rather than treated as boundaries. The runner records the Unicode version, normalized-body hash, body character span and counts of residual non-ASCII letters dropped. NFKD is not a complete transliteration system. These transformations are an explicit assumption for comparison with uninterrupted sculpture text, not an inference about its plaintext language or spelling.

In the resulting letter string, use zero-based half-open positions `[5000:55000]` for training: exactly 50,000 letters for every model. Skip the next 1,000 letters. Take 20 disjoint adjacent 97-letter windows starting at position 56,000, ending at 57,940. The later windows do not overlap training by position; same-book repetitions, editorial language, nearby passage dependence and genre bias remain possible. Do not treat the 20 windows as independent draws from an entire language.

All five models use the same 26-symbol alphabet, identity normalization after external preprocessing, joint trigrams and additive smoothing `alpha=0.1`. Each model has 49,998 training windows. Every held-out, control, and K4 candidate score uses the same canonical 24-letter crib mask. Thus every sample has 73 eligible characters and 67 complete unmasked trigram windows. Features never cross the mask gaps.

## Controls and candidate ranking

For each of the 20 held-out windows, shuffle only its 73 eligible letters eight times, preserving the masked positions. Each control therefore preserves that positive window's eligible monogram inventory. Seed `20261012 + 8*window_index + shuffle_index` is reused across the five language branches so the permutation-generation rule is identical. The runner records Python/Unicode versions and control hashes/source identifiers. It refuses accidental exact duplication rather than silently resampling.

Each model gets its own 160-control calibration. Report the 160 paired positive-versus-shuffle comparisons, ties, score differences, and the number of the 20 positive windows exceeding their paired shuffle mean. These are diagnostics of local letter ordering on these particular later passages. They are not a language-identification success rate or statistical significance for Kryptos.

Read the 46 distinct, fully specified strings already stored in `research/runs/complete-predictions-001/results.json`. Verify their length, alphabet, canonical cribs and mask. Rank these strings **separately within each model**, breaking score ties by plaintext. Preserve original record identifiers, generating-model counts, masks and plaintext hashes. No new key, route, codebook or candidate selection runs. No score is compared across language models to choose a winning language.

Assessments against each book's shuffled controls are stored for transparency, together with exact duplicate flags. Those controls have different character inventories from most K4 candidates, so these assessments mix ordering and monogram effects. They do not repeat the cipher-fitting process that selected the 46 strings. Neither their standardized scores nor smoothed control exceedances are solution probabilities, valid automatic p-values, or evidence excluding other languages/intermediate encodings. The previous masked English heuristic's candidate order is not used as a new selection criterion; all 46 strings are retained in every branch.

## Execution and output

Only the standard library and the local stable modules `kryptos.language` and `kryptos.data` are dependencies. Run from the repository root:

```text
C:\Python314\python.exe -B research/multilingual_pilot.py --output research/models/my-fresh-multilingual-run
```

The output must be a new directory inside `research/models`. Existing output is never overwritten. The runner preflights every corpus, computes all five models and reports in memory, then checks before/after hashes of the script, stable modules, source snapshots and prior candidate file before writing:

- Five `pg<ID>-<language>-trigram.json` models with serialized corpus provenance and content hashes.
- `results.json` with declared settings, source/split metadata, all held-out diagnostics/control calibrations and five separate 46-string rankings.
- `provenance.json` with input hashes and hashes of the preceding six output files. The provenance file intentionally does not hash itself.

The algorithm and sampling are fixed. Training timestamps, model identities derived from those timestamps, and runtime fields vary across executions; the saved run is the artifact to audit. A later experiment with different books, normalization, order, split, controls or masking requires a new declared protocol, not reinterpretation of this run. This pilot supplies no K5 ciphertext or recovered semantic message.
