# Scoring review

Read-only source review of `kryptos/scoring.py`, its callers in `kryptos/engine.py`, the scoring regression, and research imports. Findings describe the implementation inspected before the planned masking correction; they do not verify later changes. No application tests, search, or source edits were performed.

## Actual behavior and impact

The scorer's claim that cribs are excluded is inaccurate. `english_score(text)` accepts no crib positions and scores every character, every adjacent 2/3/4-character window, and both spelling penalties throughout the complete plaintext. `engine.py:106` passes full text for dictionary/route candidates; lines 251 and 259 do so for initial and trial annealing states. Supplying a cached `best_score` does not change its origin.

Crib match counts are reported separately and are not added numerically to the score. That narrower statement is true. However, known letters still contribute monograms and n-gram features. Features spanning a crib boundary also use those known letters to reward or penalize neighboring unknown letters.

When every retained candidate satisfies identical cribs at a fixed length, contributions wholly inside the cribs are constant and cannot change their ordering. They still inflate apparent language evidence and hinder comparisons with unconstrained searches. Boundary-spanning features vary with unknown neighbors and can change both rankings and annealing decisions. With `require_cribs=False`, even internal crib-position contributions can vary across candidates. This is contamination of an intended score of unknown text, not evidence that exact crib constraints are incorrect.

Active hand-selected features include BER/ERL/RLI/LIN, CLO/LOC/OCK, EAS/AST, NOR/ORT/RTH and BERL/ERLI/RLIN/EAST/NORT/ORTH. Some are common English fragments, but their conspicuous collection follows Kryptos clues and favors that vocabulary even outside known positions. Conversely, literal CLOCK, HELLO, WORLD, SHADOW and other entries longer than four letters in `_TETRAGRAMS` never match: the code examines only four-character slices. Do not describe those dead entries as active whole-word bonuses.

`tests/test_engine.py:148` currently requires the same candidate score with and without cribs. It tests absence of an explicit crib-match bonus, and actively enforces the current full-text scoring semantics. It does not test exclusion of known letters and must change if masking is implemented.

## Minimal recommended change

Use a position-based API:

```python
english_score(text: str, *, excluded_positions: Collection[int] = ()) -> float
```

Positions are zero-based. Deduplicate all validated crib positions, regardless of whether the candidate matches them or whether `require_cribs` is true. Mask monograms at those positions and **every n-gram or penalty window touching any masked position**. Keep the original text indices: deleting masked characters and concatenating the remaining runs invents adjacencies.

Divide the retained numerator by the number of unmasked characters, rather than the original length. Specify a finite neutral result, preferably 0.0, when none remain, and report `scored_characters=0` so it is understood as no language evidence. Returning negative infinity here risks NaN score differences during annealing and nonstandard JSON values. Scores remain heuristic and should not be treated as probabilities or directly compared across different masks, coverage, or languages.

Strict masking prevents known plaintext from contributing directly to the language objective, including context at crib boundaries. Its cost is that useful linguistic context crossing those boundaries is discarded too. This is a deliberate separation of known and unknown letters, not statistical independence or a calibrated held-out likelihood. The feature list is English-specific; a low score cannot exclude another language or an encoded intermediate layer.

Concrete call-site changes:

1. Add an engine helper deriving `frozenset(start - 1 + offset)` from normalized cribs. Compute the mask once per batch for annealing.
2. Pass the mask to `_candidate`'s fallback scoring and to **both** annealing calls. Its cached `best_score` must come from the same masked objective. Dictionary and route paths must use the same rule.
3. Update both scorer descriptions and the misleading regression name/assertion. Keep crib matches and hard-constraint behavior separate. Remove dead long entries and obvious appended Kryptos/test-phrase features, recording the feature-list revision as a scoring-model change. That cleanup does not by itself turn the remaining hand-selected features into a trained or unbiased language model.

Three small regression cases suffice for this fix:

| Case | Required behavior |
|---|---|
| Masked-content invariance | Mask positions 3..13 in `THEBERLINCLOCKAND`. Replacing those eleven letters with eleven X's must leave the score unchanged. Repeat through `_candidate` with the same crib positions: match counts can change while the masked score does not. |
| Gap is a hard boundary | `score("TXHE", excluded_positions={1})` must equal `(score("T") + 2*score("HE"))/3`, not `score("THE")`. Include `QXU` with the middle position masked to catch both a manufactured QU bonus and improperly retained Q-without-U penalty. |
| No unknown letters | A fully masked nonempty text returns the documented finite neutral score and zero scored characters. A candidate built with a cached masked annealing score agrees with fallback scoring for the same plaintext and mask. |

No changes to annealing temperature are required to implement correctness. Because the denominator changes from total length to unknown length, score differences may change scale; any later temperature tuning should be recorded separately.

## Research-checkpoint scope

A search across current `research/**/*.py` found no `english_score`, scoring-module import, or engine import. The recorded checkpoint programs use exact crib equations, inventories, permutations, graph constraints, and certificate replay. This scoring issue therefore does not invalidate their exclusions or finite consistency counts. `research/STATUS.md` records a qualitative assessment of some completed text as non-English, explicitly distinguishes it from an exclusion, and states that no multilingual classifier was run; that assessment is not an invocation of this scorer.
