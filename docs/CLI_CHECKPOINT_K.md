# Joint recovery, shared keys and resumable CPU searches

Run from `C:\KryptosSolverK4andK5`. These are bounded examples with known generating texts, not Kryptos solutions. Crib starts are one-based original plaintext positions; gather indices are zero-based. Choose fresh output filenames.

```powershell
python -m kryptos joint --request examples/joint-ragged.json
python -m kryptos scheduled --request examples/scheduled-shared.json
python -m kryptos mixed --request examples/mixed-shared.json
python -m kryptos alphabet-plus --request examples/alphabet-cycle.json
python -m kryptos optimize-plus --request examples/optimize-lazy.json
python -m kryptos batch --request examples/batch-lazy.json
```

`joint` searches the column order and repeating substitution key together. Select `order: "ST"` or `"TS"`, an explicit key `period`, and either a regular `width` or explicit occupied `cells`. Omitting geometry for canonical K4 uses the verified sculpture coordinates. Short final columns and the selected column direction are part of the model. Partial key/text masks remain partial. Exact counts require completed search; truncated counts are lower bounds.

`scheduled` supports named shared keys and explicit phase maps. Every substitution declares `key_id` and `key_length`; repeating an ID shares the same letter key. `offset` adds a relative phase modulo that length. A stage can specify `schedule: {"kind":"row_reset","frame":"source"}` instead of `phase_map`. Other kinds are `column` and `serpentine`; the frame is `source` or `current`. Missing cells consume no phase. Source schedules follow original cell identities through earlier gathers. Current schedules use the current stage positions. These are declared hypotheses about the sculpture.

The shared example deliberately cancels a key across a gather. It returns the unique plaintext `ABCDE` but 676 possible two-letter keys. Exact marginal letter domains and cancellation diagnostics explain this difference. Marginal letter choices can be correlated; they cannot be combined independently.

`mixed` supports multiple substitutions with different known alphabets and interleaved gathers. Each substitution must explicitly give its alphabet. A shared key means the same **letters**, looked up separately in each stage's alphabet. Equal-alphabet models dispatch to the exact linear solver. General mixed models use finite constraint propagation and bounded branching. Completed counts and interrupted lower bounds are labeled separately. This command does not infer unknown alphabets; `alphabet-plus` handles the separate unknown single cyclic-alphabet model with stronger matching support pruning.

`optimize-plus` ranks a general-layer family with a frozen `model_path`. Set `layer_model: "scheduled"` to use shared keys and coordinate schedules. It uses exact integer products, excludes every n-gram touching a crib, creates score factors lazily, and merges identical factors. `ordering` is `impact` or `natural`. Search returns an incumbent, a rigorous remaining upper bound, and separate objective-optimality and tie-completion flags. A high score is conditional on the supplied model, family and mask; it is not authentication or a probability of correctness.

## Stop and resume an unfinished search

This creates a zero-node checkpoint, then resumes it without changing the problem or scoring model:

```powershell
$request = Get-Content examples/optimize-lazy.json -Raw | ConvertFrom-Json
$request.max_nodes = 0
$request | Add-Member checkpoint_path "research/frontier-K-demo-1.json"
$request | ConvertTo-Json -Depth 20 | Set-Content research/stop-K-demo.json
python -m kryptos optimize-plus --request research/stop-K-demo.json --output research/stopped-K-demo.json
$request.max_nodes = 10000
$request | Add-Member resume_path "research/frontier-K-demo-1.json"
$request.checkpoint_path = "research/frontier-K-demo-2.json"
$request | ConvertTo-Json -Depth 20 | Set-Content research/resume-K-demo.json
python -m kryptos optimize-plus --request research/resume-K-demo.json --output research/resumed-K-demo.json
```

The saved state contains every unfinished branch. Hitting `max_frontier` restores the unexpanded parent rather than dropping children. Resume checks the problem, scoring model, algorithm revision, bound convention, payload checksum, incumbent and frontier bounds. Work and memory limits may increase; a changed problem, source revision or ordering requires a fresh search. Output checkpoints must be new files. The integrity checks detect accidental changes; they do not establish externally authenticated search coverage.

`max_nodes`, `time_limit_seconds`, `max_frontier`, `max_cache_entries`, and `local_exact_limit` bound work and storage. Time checks are cooperative between expansions and can overshoot during an expensive bound calculation. `max_key_slots`, `max_matrix_cells`, and `max_operations` bound the preceding algebra. An algebra-budget stop reports `feasible: null`, not a contradiction.

## Independent CPU jobs

`batch` accepts up to 32 `{id, request}` optimization jobs and 1–4 `workers`. The example runs natural and adaptive ordering in separate hidden Python processes. Results return in job-ID order and completed answers use the same original-coordinate lexical tie rule as serial searches. Relative checkpoint paths resolve against the caller's directory. Workers cannot share checkpoint outputs or overwrite resume inputs.

Each batch search has a cooperative limit of at most 30 seconds; this is not an operating-system CPU quota. Source revision and time-limited progress are recorded. A job that exhausts its algebra budget remains an explicit unresolved record while other jobs finish. Jobs may overlap in cipher hypotheses; their counts must not be added as if the families were disjoint. No GPU worker or persistent service is started.

## Inspect how a candidate was found

Every command records its supplied request, model assumptions, work limits, recovered values, input/source hashes and authentication status. Complete candidates contain `encryption_recipe` and `evidence.stage_outputs`, with literal crib and re-encryption checks. Expanded recipes record the alphabet and full key pattern at every substitution stage, so source/current phase schedules can be replayed without reconstructing the solver.

```python
from kryptos.replay_expanded import replay_expanded
result = replay_expanded(candidate["plaintext"], candidate["encryption_recipe"])
print(result["ciphertext"])
print(result["stages"])
```

Use `kryptos.explanations.replay_recipe` for the earlier `kryptos.encryption-recipe.v1` schema. The `schema` field identifies which replay function applies. K5 requires explicit authenticated input or a justified extraction; the program does not invent its ciphertext.
