# Checkpoint J: all six planned improvements implemented

Completed 13 October 2026. **Neither K4 nor K5 has been deciphered.** This checkpoint implements all six improvements left in checkpoint I, adds several correctness and search improvements, and tests them through usable commands. Canonical ciphertext and cribs are unchanged; `kryptos/data.py` retains SHA-256 `2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2`.

## Delivered capabilities

| Planned improvement | Implementation and interface | Evidence and limits |
| --- | --- | --- |
| Unknown keyed column order | `kryptos/columnar.py`; `python -m kryptos columns` | Ragged occupied cells, both vertical directions, crib compatibility, exact matching and ambiguity counts. PK2's full 350-letter plaintext and order recovered uniquely from 21 supplied letters with the order withheld. Pure transposition only; surrounding unknown substitutions are not inferred jointly. |
| General cipher layering | `kryptos/general_layers.py`; `python -m kryptos general` | Up to 16 explicit stages, including Vigenère, Beaufort, variant and multiple supplied gathers. Uses separate systems modulo 2 and 13, removes key freedoms that do not alter plaintext, and lifts every plaintext back to valid keys. One known shared alphabet; unknown stage orders, routes and mixed alphabets require separate hypotheses. |
| Smarter bounded search | `kryptos/factor_search.py`; `python -m kryptos optimize` | Precomputed n-gram factors, cached local maxima and exact integer bounds. A 676-plaintext control agrees with exhaustive scoring; search visits 110 nodes and one completed leaf. Optimum, exhausted search and resolved ties have separate flags. Dense factor tables can hit their explicit size limit. |
| Unknown cyclic alphabet | `kryptos/keyed_alphabet.py`; `python -m kryptos alphabet` | Solves distinct letter indices and shared repeating key phases using actual cipher equations. Modular domain propagation, perfect-matching checks, smallest-domain branching and rejected-state caching. Alphabet rotation is removed only when no absolute indices are supplied. Counts describe alphabet/used-key-phase assignments, not distinct texts. |
| Verified sculpture geometry | `kryptos/sculpture.py`, `research/sculpture_layout.json`; `python -m kryptos layout` | All K1–K4 inscription letters, punctuation, tableau headers and extra L preserved. Two source transcriptions agree. Sixteen fixed K4 routes and eight explicitly aligned overlays include coordinate mappings and missing cells. Coordinates are transcription ordinals, not physical measurements. |
| Stronger evaluation | `research/evaluation_J.py` and five new saved models | Fifteen books: two training authors and one separate validation author per language. Tests include 100 held-out windows, 800 matched shuffles and ten planted cipher searches paired with ten null searches. Frozen choices and identical selection for controls; no calibrated solution probability is claimed. |

Additional implemented improvements include supported-edge propagation and memoized component counting for column assignments; a factorial shortcut that counts 20! equivalent column orders without enumerating them; field-specific contradiction certificates; exact lower/upper bounds when optimization stops; replay of up to 16 encryption stages; safe hexadecimal encoding for enormous exact scores; and a corrected default that uses K4's verified ragged cells. Custom/K5 column requests require explicit geometry.

Every new cipher command records the method, supplied assumptions, bounds and input/source hashes. Complete returned candidates include an encryption recipe and intermediate strings, independently replayed to the ciphertext. An arbitrary consistent witness remains labeled as such. New commands reject unknown request fields, require a new output path, and require explicit ciphertext for K5.

## Actual results

| Saved experiment | Result |
| --- | --- |
| [Column-order recovery](runs/columnar-J-001/results.json) | Seven controls passed; 25 segmentations and 3,433 charged states. PK2 and two ragged controls recover uniquely; weak clues retain two answers; a symmetry control has 20! orders but one plaintext. K4's existing E-inventory contradiction rejects pure transposition before search. |
| [General layers and optimization](runs/general-J-002/results.json) | All 17,576 PK3 plaintexts match the earlier solver's family and re-encrypt. Six other two-layer comparisons agree. A five-stage control has exactly two plaintexts, catching an incorrect assumption that every freedom contributes 26 choices. Exact optimization agrees with brute force on 1,024-assignment and 676-plaintext controls. |
| [Unknown alphabet bank](runs/alphabet-J-001/results.json) | All 24 parameter records reject: periods 1–8 × Vigenère/Beaufort/variant, one shared unknown cyclic alphabet, no transposition. Every run exhausts its declared family; none is censored. Vigenère and variant describe equivalent feasible families after key negation, so these are not 24 independent exclusions. |
| [General K4 bank](runs/general-J-002/results.json) | Eight specified three-substitution/two-gather models reject. Four period triples `(2,3,5)`, `(3,5,7)`, `(5,7,11)`, `(7,8,9)` and two fixed route orders are tested with the shared KRYPTOS alphabet. This is not a general exclusion of layered encryption. |
| [Geometry](runs/geometry-J-001/results.json) | 865 inscription letters, four question marks, 28 cipher rows and 28 tableau rows retained. K1/K2/K3 known answers round-trip; K4 matches the canonical 97 letters. All fixed routes pass inverse checks. |
| [Document-separated evaluation](runs/evaluation-J-001/artifacts/results.json) | All 800 text-versus-shuffle comparisons favor the real held-out text, both within the intended language and after selecting among five models. All 100 windows receive the catalog language label. All ten planted plaintexts are recovered and rank first; none of ten nulls produces a completed candidate. |

The evaluation remains narrow. It uses five held-out books, not 100 independent books. Seven planted searches have one distinct completion and three have two, so ranking is only lightly challenged. All ten nulls are rejected by the cipher constraints before scoring: this does **not** measure the score false-positive rate among surviving, plausible-looking decryptions. It also does not erase checkpoint I's negative K4 calibration results. See the [full evaluation protocol and qualifications](evaluation_notes_J.md).

The five new models are saved under `research/runs/evaluation-J-001/artifacts/`, named `<language>-two-author-trigram.json`. The earlier models remain unchanged. [Geometry/source notes](geometry_notes_J.md) distinguish verified transcription from hypothetical alignment and document PK2 provenance.

## Verification and reproducibility

**164 unit tests passed**, with no failures, errors or skips: [saved suite](runs/unit-J-001/results.json). Six new command examples passed, and all 16 saved complete candidates replayed correctly: [CLI records](runs/cli-J-001/results.json).

Independent checks also passed: 48 exhaustive column-order cases, 192 budget checks (including 168 truncated runs), ten general/optimization interface checks, and five unknown-alphabet cases. The latter include a fully unknown cyclic alphabet with exactly 12 valid indexings. [Audit script and results](independent_audit_J.json), [alphabet audit](keyed_alphabet_audit_J.json).

[Seven successful canonical manifests](checkpoint-J-validation.json) validate against current input/output hashes. Each has a separate contract, log, bounded command and result. General run `general-J-001` failed before computation because its benchmark used a nonexistent model-loader method. The corrected run is `general-J-002`; both modified source files from the failed attempt are preserved under `source_snapshots/general-J-001/`. Earlier checkpoint-I CLI, explanation and documentation sources were also preserved before edits.

Before substantial testing, the running-WSL query returned no distributions and no Ubuntu/n5_runner window was present to receive Ctrl+C. Tests used bounded CPU processes. No GPU workload or persistent background search was launched.

## Remaining research limits

The six implementation tasks are complete within their stated interfaces. There is no exhaustive list of every useful future improvement. Joint recovery of unknown route, unknown alphabet and several unknown keys remains much larger than these individual tools; choosing historically justified models matters as much as accelerating them. The grid data cannot supply unmeasured three-dimensional geometry. No authenticated K5 ciphertext was found in the source review, so K5 remains an explicit input dependency.

Use [the runnable command examples](../docs/CLI_EXAMPLES.md) to inspect results and replay a candidate. No result is submitted to an external verifier automatically.
