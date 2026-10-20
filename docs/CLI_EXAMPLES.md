# Runnable CLI examples

Run these commands from the repository root with Python. Inputs live in `examples/`; no answer key is supplied to recovery. The examples on this page use one CPU process. [Checkpoint K examples](CLI_CHECKPOINT_K.md) add joint recovery, shared/coordinate keys, mixed alphabets, stronger pruning, saved search frontiers and independent CPU batches. `python -m kryptos doctor` reports the environment and available GPU query information; it does not claim a GPU solver backend.

Create a fresh result directory, or choose another name if you have already run these examples. The commands refuse existing output files by default.

```powershell
New-Item -ItemType Directory -Force research/manual-checks/cli-examples
```

## Every result explains its technique

The root `recover`, `layers`, `grid`, and `residues` commands automatically include an `explanation`. It records the normalized ciphertext and cribs, supplied or default model assumptions, the search algorithm, bounds and work, and hashes of the input request and source revision. Candidate explanations separate recovered values from arbitrary choices such as redundant key offsets. These records are deterministic for the same inputs, source revision, and result; no external verification is performed.

A complete recovery or layered candidate contains `candidate.explanation.encryption_recipe` and `candidate.explanation.verification`. The recipe specifies the alphabet, key, exact gather permutation, and ordered encryption stages. Verification lists each intermediate output, the reconstructed ciphertext, and exact crib/re-encryption checks. For the layered example below, the outputs are `AECGEI`, `ACGEIE`, and `DKSHQQ`. Search limits and language ranking appear separately from this encryption recipe.

Partial masks stay partial: their report says `partial_candidate` and does not claim full re-encryption. A complete finite plaintext with unused unknown key slots is labeled `complete_plaintext_with_partial_key`. Grid output is always labeled a `consistency_witness`, with arbitrary representative choices distinguished from forced mask letters. A residue check is `constraint_only` and supplies no recovered encryption recipe. These labels never establish an authenticated solution.

Recipes survive JSON serialization and can be replayed locally without another search. For example, after running the layered command:

```powershell
python -c "import json; from pathlib import Path; from kryptos.explanations import replay_recipe; r=json.loads(Path('research/manual-checks/cli-examples/layers.json').read_text()); c=r['candidates'][0]; print(replay_recipe(c['plaintext'],c['explanation']['encryption_recipe'])['ciphertext'])"
```

This prints `DKSHQQ`. Replaying a recipe verifies its mechanics; it does not verify the artist's intended plaintext or method.

## Recover a repeating key

```powershell
python -m kryptos recover --request examples/recover-lemon.json --output research/manual-checks/cli-examples/recover.json
```

This independent standard-alphabet Vigenere vector supplies ciphertext `LXFOPVEFRNHR`, crib `ATTACK` at position 1, and periods 1–5. It recovers key `LEMON` and full plaintext `ATTACKATDAWN`; `reencryption_matches` is true. The five-model/100-crib-check budget is explicit. In other requests, `?` in key or plaintext masks means unresolved data, not an arbitrary completion. A `truncated` result covers only the tested models and cannot exclude the remainder.

Recovery accepts `standard`, `kryptos`, or an explicit alphabet permutation. Crib starts are one-based original-plaintext positions; whitespace is removed, and letters are uppercased. ASCII validation rejects symbols that would expand or change positions under Unicode case conversion. Route permutations, when supplied, use zero-based encryption gather indices: `T(text)[j] = text[permutation[j]]`.

## Two substitutions with a route between them

```powershell
python -m kryptos layers --request examples/layers-small.json --output research/manual-checks/cli-examples/layers.json
```

The six-letter fixture supplies only the first four plaintext letters, `ABCD`, and tests one `STS` model with key periods 2 and 3 and the non-involutive route `[0,2,3,1,5,4]`. It has one distinct plaintext, `ABCDEF`; the returned representative keys are `AD` and `DIM`. Literal encryption gives:

```text
ABCDEF -- additive AD --> AECGEI -- gather --> ACGEIE -- additive DIM --> DKSHQQ
```

Every enumerated candidate is checked by the CLI's literal stage encryption before it is returned. The original fixture also encrypts with `BE` and `CHL`: adding a constant to one key and subtracting it from the other can preserve the plaintext/ciphertext pair. Representative keys therefore need not be unique. The alphabet and both cipher stages are fixed assumptions; this CLI currently supports additive Vigenere for layered models.

`plaintext_dimension` and `distinct_plaintext_count` describe unresolved choices after redundant key offsets are removed. If the whole family exceeds `max_candidates`, the CLI ranks none of it and reports a candidate-limit stop. A time-limit stop is incomplete. The built-in English score excludes crib positions and is only a ranking heuristic; `authenticated_solution` remains false. The newer `general` and `optimize` commands below support more stages and explicit trained models with the same model-consistency limits.

## The canonical K4 occupied grid

```powershell
python -m kryptos grid --request examples/grid-k4.json --output research/manual-checks/cli-examples/grid-k4.json
python -m kryptos grid --request examples/grid-small.json --output research/manual-checks/cli-examples/grid-small.json
```

The K4 request selects the repository's canonical 97-letter ciphertext and 24 known plaintext letters. Omitted cells mean the explicit local layout: four rightmost occupied cells in a 31-column row, followed by three full rows. Omitted permutation means identity. This particular KRYPTOS-alphabet source-row/source-column shift model is contradicted; expect `feasible: false` with a signed modular-cycle witness. It is one model check, not the entire 59-route research probe.

The small positive control returns mask `AB?DE?`, exact re-encryption, and 26 distinct possible plaintexts. One previously unknown letter is forced, but two unresolved letters remain correlated. Its representative plaintext is a consistency witness. No grid fit is presented as an authenticated K4 solution.

## Check an optional position-residue hypothesis

```powershell
python -m kryptos residues --request examples/residues-k4-parity.json --output research/manual-checks/cli-examples/residues-k4-parity.json
```

This checks the necessary modulo-2 condition for `idx(C[i]) = F(P[i]) + i (mod 26)`, using one-based positions and the standard alphabet. Here `F` is an unknown bijective substitution. The canonical K4 cribs satisfy the parity condition and leave 1716 balanced alphabet-partition completions. These are residue partitions, not 1716 recovered full substitutions or plaintexts.

The condition is weaker than the full modulo-26 equation: a parity fit does not establish that full model. Treat this as an optional, explicitly selected hypothesis. Do not apply it as a global filter to unrelated cipher families or call it a decryption. `authenticated_solution` remains false. Omitting `--request` selects the same canonical default check; moduli 13 and 26 require their own explicit checks.

## Apply the explicit ENE/BC hypothesis

```powershell
python -m kryptos.semantic --input examples/semantic-ene-bc.json --output research/manual-checks/cli-examples/semantic-codebook.json
python -m kryptos.semantic --input examples/semantic-initials-en.json --output research/manual-checks/cli-examples/semantic-en.json
python -m kryptos.semantic --input examples/semantic-initials-ene.json --output research/manual-checks/cli-examples/semantic-ene.json
```

The codebook example maps the supplied phrase tokens to `ENE` and `BC`, preserving the unmatched `?`, so the output is `ENE?BC`. It is a short constructed demonstration string, not a recovered K4 passage, K5 ciphertext, or prediction of K5's length. The program does not infer phrase boundaries or a codebook.

Semantic spans use **zero-based, half-open** indices and must partition the whole input, including unknown regions. The two initials examples deliberately produce different results: `EAST|NORTHEAST` gives `EN`; `EAST|NORTH|EAST` gives `ENE`. The boundary choice is an explicit hypothesis. Literal codebook abbreviation and word initials are separate operations.

## Train, save, and use an explicit language model

```powershell
python -m kryptos.language train --input examples/language-train.json --output research/manual-checks/cli-examples/language-model.json
python -m kryptos.language score --model research/manual-checks/cli-examples/language-model.json --input examples/language-score.json --output research/manual-checks/cli-examples/language-score.json
```

The saved model contains counts, settings, provenance, and a content-derived model identifier. It uses a tiny original prose sample purely to demonstrate the API; it is unsuitable as evidence about a cipher candidate's authenticity or natural-language recovery performance. Supply your own suitable corpus for actual experiments, with separate evaluation data.

The score request masks zero-based positions 0–3 and supplies two explicit synthetic controls of the same length and mask. N-grams crossing a masked or unsupported symbol are omitted, and gaps are not joined. Read `score.available`, `score.windows`, and the coverage fields before comparing numbers. Control exceedance and standardized scores describe the chosen reference controls, not the probability of a solution. These two toy controls do not validate the model. Comparing differently selected models or candidates requires a documented evaluation and selection procedure.

The semantic and language modules expose their own `--input` CLIs; their JSON schemas are distinct from the root CLI's `--request` schema. Root `recover`, `layers`, and `grid` requests accept `target: "k5"` only with explicit ciphertext, and no K4 cribs are silently transferred to it. No example submits a candidate to an external verifier.

The nine recovery, layer, grid, semantic, and language example commands were executed successfully on 12 October 2026. Their outputs and SHA-256 verification summary are in `research/manual-checks/cli-examples-20261012/`. The layered fixture was also re-encrypted independently from its returned keys, and the saved language model produced 15 scored windows under the declared mask. The subsequent residue example was checked separately and its output is saved in the same directory. These are small interface checks, not new Kryptos research claims.

## Recover an unknown column order

```powershell
python -m kryptos columns --request examples/columns-ragged.json --output research/local-J-columns.json
```

The ciphertext `CGAEIDHBFJ`, four plaintext letters `ABCD`, and width4 uniquely give plaintext `ABCDEFGHIJ` and column order `[2,0,3,1]`. The order is recovered, not supplied. A width means row-filled source cells with no padding. Alternatively supply `cells`, a list of `[row,column]` pairs in plaintext order. Supply either width or cells, never both. `column_direction` accepts `top_to_bottom` or `bottom_to_top`.

Without a request, this command uses K4's **verified occupied cells**: global row24 columns27–30, then three full31-letter rows. It returns the existing inventory contradiction for pure transposition. Custom/K5 inputs require explicit geometry. This command does not simultaneously recover surrounding substitution keys.

`total_column_orders`, supported domains and `forced_plaintext_mask` are global claims only when `complete` is true. Different orders may yield the same plaintext. `max_candidates` caps stored witnesses without stopping exact counting; `max_states`, `max_segmentations` and `time_limit_seconds` bound the search. A truncated no-witness run returns unknown feasibility, not an exclusion.

## Solve three substitutions and two transpositions

```powershell
python -m kryptos general --request examples/general-five-stages.json --output research/local-J-general.json
```

The fixture has five explicit encryption stages and four supplied plaintext letters. It returns exactly two texts, `ABCDEFGH` and `AOPDRFGU`, with keys and all five intermediate strings for each. This is a useful check: plaintext dimension is1 modulo2 and0 modulo13, so the answer count is2, not26.

`stages` contains one to16 operations in encryption order:

```json
{"operation":"substitution","period":8,"cipher":"beaufort"}
```

or

```json
{"operation":"gather","permutation":[0,2,1,3]}
```

The full permutation must match the message length and be a bijection. Substitution rules are `vigenere`, `beaufort` and `variant`; each stage has its own unknown key. One known shared `alphabet` is supplied at the request level. The solver does not infer stage order, periods, gathers, or mixed alphabets.

Read `dimensions_mod2`, `dimensions_mod13`, `distinct_plaintext_count`, `prediction_mask` and `conflicts`. Contradictions include weighted equations whose key terms cancel but right-hand side is nonzero. Representative keys need not equal original keys because redundant key freedoms may cancel.

`max_key_slots`, `max_matrix_cells` and `max_operations` bound the algebra. `max_candidates` bounds complete enumeration; if the family exceeds it, no arbitrary subset is enumerated. `top` only limits storage in deterministic coordinate order; this command does not rank language. An algebra-budget stop has `feasible: null`.

## Optimize unresolved letters with a supplied language model

```powershell
python -m kryptos optimize --request examples/optimize-small.json --output research/local-J-optimize.json
```

This uses the same explicit stage schema as `general`, plus `model_path`. The example selects the existing English pilot model. Five newer two-author models are available under `research/runs/evaluation-J-001/artifacts/`, for example `english-two-author-trigram.json` or `latin-two-author-trigram.json`.

The optimizer excludes known positions and every n-gram touching them, without closing gaps. It maximizes the exact integer product corresponding to the saved model's smoothed counts. It never prunes by rounded floating-point scores. `max_factor_entries` bounds construction, `max_nodes` bounds search, and `max_cache_entries` bounds the cache.

Read `optimization.search.lower_bound`, `upper_bound`, `optimal`, `complete` and `tie_break_proven`. An interrupted run can retain a verified candidate and an unresolved score gap. An optimal language score is optimal only within that supplied family/model/mask and is not authentication. No available scoring windows means no language evidence. Extremely large exact integers use `{"encoding":"exact_integer_hex","value":"0x..."}`; recover them with `int(value,16)`.

## Recover an unknown cyclic alphabet

```powershell
python -m kryptos alphabet --request examples/alphabet-cycle.json --output research/local-J-alphabet.json
```

This constructed26-letter cycle supplies all plaintext letters while withholding the entire alphabet and key. It returns12 alphabet/key assignments, illustrating genuine ambiguity. The solver preserves Vigenère/Beaufort/variant arithmetic and the requirement that all26letter indices differ; it cannot invent an arbitrary phase substitution table.

Supply `period`, optionally `cipher`, and optional `fixed_indices`, such as `{"A":0,"B":1}`. Supplied indices are assumptions. With none supplied, fixing A's index to0 removes rotation only. Multiplicative symmetries remain. Counts include message-used key phases only; unused phases are marked `?`. Limits are `max_states`, `max_candidates` for storage, and `time_limit_seconds`. No language score is assigned to arbitrary alphabet completions.

## Inspect the verified sculpture rows and overlays

```powershell
python -m kryptos layout --output research/local-J-layout.json
```

The default K4 result includes text, original ordinal cells,16 fixed route permutations and an identity-aligned tableau overlay. Requests accept `section` (`K1`, `K2`, `K3`, `K4` or `ALL`) and `transform` (`identity`, `rotate90`, `rotate180`, `rotate270`, `reflect_columns`, `reflect_rows`, `transpose` or `antitranspose`). Every overlay states its alignment and reports missing/nonletter cells explicitly. Ordinal positions are not measured physical distances or a three-dimensional model. Source and dataset hashes accompany the output.

All six new example invocations passed on13October2026, with16complete candidate recipes replayed: [saved command records](../research/runs/cli-J-001/results.json). Candidate recipes use `encryption_recipe`; replay them with the same `kryptos.explanations.replay_recipe` function shown above. No K4/K5 decipherment follows from these interface checks.
