# Surviving ambiguous controls, checkpoint K

Checkpoint J's ten null ciphertexts all failed the algebraic constraints before language scoring. This new frozen experiment supplies deliberately crib-compatible nulls, so every positive and null has a large set of fully valid cipher completions. It tests candidate selection under ambiguity, while retaining a narrow, explicit model family.

## Frozen contract

The single declared cipher model is two additive substitutions in the KRYPTOS alphabet, order SST, identity transposition, and key periods 3 and 14. Under the fixed 24-position mask, its crib graph has plaintext dimension three: **17,576 distinct completions for every feasible input**, including 17,575 alternatives to the generating plaintext. This is a method-known benchmark; route, order, periods and alphabet are supplied equally for every input. No hidden search over additional families is implied.

Five positive 97-letter texts come from normalized half-open span `[50000,50097)` of the independently authored validation books already retained for checkpoint J: Doyle, Pérez Galdós, Proust, De Amicis and Augustine. These spans lie beyond J's twenty validation windows. The five frozen two-author J trigram models are loaded from `research/runs/evaluation-J-001/artifacts`; they are not retrained or modified. Source-book hashes, normalization evidence, model provenance/settings and model content hashes are checked.

Each positive gets one paired null by shuffling only the 73 letters outside the supplied positions. The null preserves the exact plaintext inventory and all 24 actual supplied letters. Both are encrypted under the same deterministic keys, and recovery receives only the ciphertext, supplied letters, declared cipher model and scoring models. Therefore all ten inputs necessarily have 17,576 surviving candidates; nulls cannot vanish through a mismatched crib or alphabetic rejection. The seed is 2026101306, incremented by language index. The key formula, offsets, model family and score settings were fixed before any full run.

The full run performs **175,760 literal re-encryptions** and verifies every completion's supplied letters. Scoring uses the same 67 unmasked trigram windows and ordered floating-point additions as the frozen J models. A small acceleration reuses the models' existing probability tables and fixed window indices; its output is checked against the public model scorer on the input texts, preflight samples and retained top candidates. No trigram crosses a supplied position.

The selection procedure maximizes across all five frozen language models for both positives and nulls, with the same lexical tie break. The output records the actual generating plaintext's competition rank, lexical rank and score ties under each individual model and after selection, the five best selected candidates with replayable representative keys, every input's full ordered candidate-family digest, and null-best versus positive-best score differences. The whole family can be regenerated from the recorded ciphertext, mask, model and source hashes. Full candidate texts are not all duplicated in the artifact.

## Bounds and interpretation

```text
python -B research/hard_controls_K.py --preflight
python -B research/hard_controls_K.py --output research/runs/hard-controls-K-NEW/results.json
```

Use a new output file. The executable `input_paths()` lists the exact 21 source/model/book inputs; before/after digests must match. No network access, K4/K5 target search or scoring, threshold fitting, corpus tuning, or output-driven model selection occurs.

The bounded preflight scored and re-encrypted exactly 100 candidate completions, taking 0.04224 seconds for that candidate loop. Linear extrapolation gives about 74.24 seconds for all ten families, excluding loading, final assessment/sorting and output. This is an estimate, not a promised runtime; an outer 180-second cap is recommended. The parent performs the canonical full run after source freeze. The preflight does not constitute full experimental results.

These are five historical-literature samples and five artificial inventory-preserving shuffles under one supplied cipher family. The resulting ranks and maxima measure this conditional benchmark, not the probability that a real K4 candidate is false or true. Some unsupplied letters may also be fixed indirectly by the cipher constraints; masking the explicit cribs does not remove all family-implied information. A good rank here does not establish that the model family describes K4. Exact ties use the existing floating-point score convention; no rounded score is silently substituted.
