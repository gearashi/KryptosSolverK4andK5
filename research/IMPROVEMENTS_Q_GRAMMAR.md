# Q62, Q64 and Q65: fixed work controls

The completed, current-input-validated work run is
`research/runs/release-Q-grammar-001/manifest.json`. Independent finite
correctness evidence is separately preserved in
`research/runs/release-Q-review-grammar-003/manifest.json` and interpreted in
`research/review_Q_grammar.md`. The work controls use the previously frozen
`phase_Q_grammar_contract.json`; their arithmetic is exact and deterministic.

| Item | Fixed comparison | Interpretation |
| --- | --- | --- |
| Q62 symbolic grammar | All 64 syntax paths in a six-slot binary grammar need 12 symbolic edges rather than 126 literal tree edges. | Retain conditionally. Signature merging preserves families under the stated independent-key assumptions. The run also performs 1,064 counted compiler scalar operations, 24 canonicalization calls and 336 canonicalization input coefficients; this is not a total arithmetic-cost comparison. |
| Q64 counterexample guidance | The same accepted recipes `[0,2]`; equations 72 to 36 and solver operations 180 to 102, but key proposals 2 to 3 and literal pair checks 6 to 8. | Retain as selectable: an explicit mixed outcome. Neither mode eliminates a recipe without contradiction. No unconditional fewer-step claim. |
| Q65 shorter explanation priority | The same first valid recipe requires 1 rather than 3 candidates; proposed keys 2 to 1, literal pair checks 5 to 3. | Retain as ordering only. Both first-witness runs correctly report incomplete bank coverage; another bank can favor a different order. |

The 126-edge comparator is the full binary prefix tree:
`2 + 4 + 8 + 16 + 32 + 64`. It measures search transitions, not all arithmetic.
Symbol prevalidation, serialization, RREF arithmetic and sorting work are not
fully counted. Q65 additionally evaluates three description priorities before
sorting, even though that preparation is outside its synthesis work counters.
No result identifies the actual K4/K5 cipher or an authenticated solution.

Reproduce into a new run directory with:

```powershell
.\.venv\Scripts\python.exe -B research/run_Q_grammar_audit.py --runner C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/4.0.0/skills/computation-audit/scripts/run_experiment.py --output research/runs/release-Q-grammar-002
```

The wrapper pins the contract, authored control script, wrapper, grammar,
compiler, canonicalizer, modular equation solver, exception definition, stage
normalizers and alphabet conventions. It enforces a 60-second wall cap and
1 MiB log cap on the owned single Python computation. No child processes are
created by that computation. The wrapper refuses to overwrite prior evidence.
