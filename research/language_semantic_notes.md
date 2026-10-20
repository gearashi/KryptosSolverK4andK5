# Explicit-corpus scoring and fixed semantic extraction

Base: **K4-20261012-H**. These additions supply reusable tools, not a new K4 or K5 result. They do not alter historical evidence or the current engine's English heuristic. No language corpus is bundled or downloaded. No K5 ciphertext, segmentation, or codebook is assumed.

## Character n-grams

`kryptos/language.py` is dependency-free. Supply actual corpus text and a source/split identifier for each `CorpusDocument`, then call `train_ngram_model`. A model records its label, alphabet, n-gram order, smoothing, normalization, UTC training time, exact counts, and each supplied document's UTF-8 SHA-256, length, coverage, source identifier, and optional license. `to_json()` and `CharacterNgramModel.from_json()` round-trip this record and validate its content hash, count totals, settings, UTC timestamp, and coverage bounds. The JSON reader rejects duplicate keys and nonfinite numbers; it loads only data, without pickle or executable imports. Corpus text is not embedded; retain authorized source copies separately. Hashes identify the supplied strings and detect changed artifacts; they do not authenticate a source, license, language label, or honest train/validation split. A hash-correct but structurally invalid model is still rejected.

```python
from kryptos.language import CorpusDocument, train_ngram_model

# corpus_text must come from an explicitly selected, authorized local source.
model = train_ngram_model(
    [CorpusDocument(corpus_text, "local-source/train-split", license=license_note)],
    label="declared corpus and language label", order=3,
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", normalization="upper-single",
)
score = model.score(candidate, excluded_positions=crib_positions_zero_based)
record = score.to_dict()
serialized_model = model.to_json()
```

For an alphabet of size `m`, order `n`, training count `c(g)` and total window count `N`, a window receives `log((c(g) + alpha) / (N + alpha * m**n))`. The reported score averages these log values over complete eligible windows. This is a joint n-gram ranking model, not a normalized probability for a whole string. Overlapping windows are dependent. Computation uses log-space addition so large finite smoothing values do not overflow the denominator.

Every window must lie inside one contiguous unmasked, in-alphabet run. Crib masks refer to zero-based positions in the original text. Gaps, unsupported characters, and document boundaries are never joined. Both eligible positions and positions covered by a complete n-gram are reported; short fragments can be eligible but unscored. No windows gives `mean_log_probability=None` and `available=False`, rather than evidence from a neutral number. Scores alone never determine a language or solution.

Default normalization uppercases one input character only if it becomes one alphabet symbol. An expansion such as `ß -> SS` is a boundary. `normalization="identity"` permits an explicitly declared Unicode alphabet. There is no transliteration or accent stripping. Corpus spaces/punctuation are boundaries as well; if a ciphertext hypothesis requires space-stripped training, the caller must explicitly prepare that corpus and record the preprocessing in its source manifest. Compare models using compatible alphabets, normalization, order, and an identical candidate mask/layout. Training corpus size, genre, preprocessing, and smoothing still affect ranks.

## Separate control calibration

`calibrate_controls(model, controls, description=..., excluded_positions=...)` scores at least two distinct caller-supplied `CorpusDocument` controls. It stores control hashes/source records and all control scores, and reports their mean and population standard deviation. `.assess(model, candidate, excluded_positions=...)` requires the same model identity and exact input length, mask, and eligible-position layout. It returns:

- A standardized score relative to that model's controls, or `None` when control scores have zero variance.
- `(1 + number of control scores >= candidate score) / (1 + control count)`, explicitly called **smoothed control exceedance**, not a solution probability or an automatically valid p-value.
- Flags for an exact candidate duplicate of a training or control document.

Controls that exactly duplicate a training string/source or one another are rejected. This detects only whole-document duplicates, not shared passages, sampling dependence, hidden preprocessing, or post-selection leakage. Use a separately computed calibration for every language model with the same suitably matched controls, document the control generator and split, and inspect known-language held-out examples as well. There is deliberately no automatic cross-language winner or raw-score sorting API. A model-specific standardized score is not evidence that two reference distributions are equally valid. Search-selected candidates require controls that repeat the **entire selection procedure**, including route/key fitting, candidate selection, and any later semantic choice; fixed-text calibration cannot supply that correction.

## Fixed semantic interpretation

`kryptos/semantic.py` exposes `apply_codebook` and `extract_initials`. Both require a complete, ordered partition into zero-based half-open spans. Unknown regions must appear explicitly as spans. Bounds default to 100,000 input/output/codebook characters and 10,000 segments; a caller can choose smaller explicit limits. There is no search over partitions or mappings.

```python
from kryptos.semantic import apply_codebook, extract_initials

text = "EASTNORTHEAST"
two_words = extract_initials(text, [(0, 4), (4, 13)],
                            rule_source="hypothesis: EAST|NORTHEAST")  # EN
three_words = extract_initials(text, [(0, 4), (4, 9), (9, 13)],
                              rule_source="hypothesis: EAST|NORTH|EAST")  # ENE
result = apply_codebook("???BERLINCLOCK??", [(0, 3), (3, 14), (14, 16)],
                        {"BERLINCLOCK": "BC"},
                        rule_source="explicit user hypothesis; not authenticated")
assert result.transformed_text == "???BC??"
artifact = result.to_dict()
```

Codebook matching is exact and case-sensitive. It neither splits a token nor finds partial matches. Unknown tokens retain their original characters and offsets; results report token and character coverage separately. The initialism rule treats every all-alphabet segment as a supplied word and takes its first symbol; it cannot know whether an alphabetic span is actually unresolved text. Use `apply_codebook` when alphabetic unknown spans must remain intact.

The serializable result records original token text/offsets, replacements, unknown flags, transformed output, unused entries, rule source, mapping/parameters, and SHA-256 hashes of the input, partition, and rule. For initialisms, the stored codebook is the mapping observed on this fixed partition, and the alphabet parameter records the general rule. Output is named `transformed_text` because retained unknowns and hypothesis-driven replacements are not a decipherment. Applying ENE/BC after decryption remains different from proposing those strings as encryption keys. An externally justified rule must predict more than the phrases used to choose it.

## Command-line entry points

All commands use only the standard library and return JSON. They create output files exclusively by default; `--force` explicitly permits replacement. Omit `--output`, or use `--output -`, for standard output. UTF-8 BOMs are accepted in JSON inputs. Unknown fields, duplicate JSON keys, conflicting options, and method-incompatible semantic settings are rejected rather than silently ignored.

```text
python -m kryptos.language --help
python -m kryptos.language train --corpus path/to/authorized-corpus.txt --label "declared source and language" --order 3 --output model.json
python -m kryptos.language train --input training-request.json --output model.json
python -m kryptos.language score --model model.json --input score-request.json --output score.json
python -m kryptos.semantic --input semantic-request.json --output semantic-result.json
```

Repeat `--corpus` for separate files. File training records each resolved path and the hash of its exact UTF-8-decoded text; CRLF line endings are preserved. Optional `--license` records the caller's provenance note. The alternative training JSON contains `documents` (objects with `text`, `source`, optional `license`), `label`, and optional `order`, `alphabet`, `alpha`, `normalization`. When using this JSON form, all model settings belong inside the file.

A score request is an object with `text` and optional `excluded_positions`. To add a separately calibrated comparison, also supply `controls` (the same document-record shape) and a nonempty `control_description`. The JSON result includes input/request hashes, model identity, complete scoring coverage, and, when supplied, the calibration and assessment. This command never fetches corpus text or chooses a language.

A semantic request contains `method` (`codebook` or `initials`), `text`, `segments`, and `rule_source`. A codebook request must include the explicit `codebook` object. An initials request may include `alphabet`. Either may supply `max_characters` and `max_segments`. Example request data for the user-declared phrase hypothesis:

```json
{"method":"codebook","text":"???BERLINCLOCK??","segments":[[0,3],[3,14],[14,16]],"codebook":{"BERLINCLOCK":"BC"},"rule_source":"explicit hypothesis; not authenticated"}
```

## Bounded validation

Only the two new, tiny unit-test modules were executed:

```text
C:\Python314\python.exe -B -m unittest tests.test_language tests.test_semantic -v
```

The initial run passed 16 tests in 0.010 seconds. After the CLI and deserialization audit, the final focused run passed **21 tests in 0.111 seconds**. The first CLI-fixture run encountered a Windows default temporary-directory ACL issue; disposable fixtures now use an explicitly created workspace sibling with inherited permissions, and clean up their own direct files. No product change was needed for that environment issue.

The fixtures are explicitly synthetic patterns, with separate source identifiers and different held-out strings. They establish exact counts/smoothing, gap and Unicode-boundary behavior, unavailable-score reporting, provenance round-trip/tamper detection, rejection of hash-correct invalid models, immutable counts, calibration layout/overlap guards, explicit segmentation differences, unknown preservation, reproducible rule hashes, bounded input validation, CLI round-trips, and refusal to overwrite output by default. They are **not authentic language training**, a language-identification benchmark, a hidden-key recovery experiment, or evidence for any Kryptos interpretation.

No engine/UI integration, app process, full application test suite, corpus acquisition, or heavy CPU/GPU run was performed by this subtask. The user subsequently reauthorized CPU/GPU testing; coordination of the `n5_runner` pause and broader application tests belongs to the parent task.
