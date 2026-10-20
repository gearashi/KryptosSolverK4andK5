# Ranked column order and periodic key search

`joint-ranked` enumerates crib-compatible combinations of a whole-column readout and a repeating key. It scores every visited completion, rather than ranking only the first routes retained by the counting solver. The existing `joint` command and its behavior are unchanged.

Run the small synthetic example with:

```powershell
.\.venv\Scripts\python.exe -m kryptos joint-ranked --request examples/joint-ranked.json
```

The example is a controlled ten-letter input, not Kryptos evidence. The app supplies the same command as a preset. A saved model must be provided explicitly; the app permits its bundled model catalog only.

## Declared family

`rank_joint_columnar(ciphertext, cribs, *, model, period, ...)` accepts the same one-based crib list and occupied-cell geometry as `joint`. Geometry is either `width` or explicit `[row, column]` cells. Columns are read in an unknown order, each top-to-bottom or bottom-to-top. `order: "ST"` encrypts by substitution then gather; `"TS"` gathers then substitutes. Substitution can be Vigenère, Beaufort, or variant Beaufort in a supplied known alphabet.

For each permutation of the multiset of column lengths, the solver builds exact column-slot key constraints. A perfect matching is a necessary prefilter only. Route branching enforces shared key values, and every surviving route enumerates all values of its unconstrained key phases. No language-score cutoff excludes routes or keys. Key phases unused by the finite message are recorded separately and are not multiplied into assignment counts.

## Ranking and evidence

Every supplied crib position is excluded from scoring. An optional zero-based `score_mask` can exclude more positions; it must contain every crib. Each n-gram touching a masked position is removed, and gaps are never concatenated. With saved IEEE floating-point smoothing parameter `alpha = p/q`, ranking compares the integer product `∏(count(ngram)·q+p)`. Window count, smoothing denominator and model are constant within the run. Displayed mean log probabilities do not decide ties.

Candidates are distinct plaintexts, ordered by descending exact product then plaintext lexical order. Multiple recipes producing the same plaintext use the smallest labelled column order, then the smallest used-key string. The retained recipe is independently re-encrypted by the literal recipe interpreter. A checked replay demonstrates consistency with this family, not an authenticated solution. With no surviving scoring windows, all products are one, ordering is lexical, and `score_available` is false.

## Bounds and interpretation

The request supports `max_segmentations`, `max_states`, `max_orders`, `max_evaluations`, and `time_limit_seconds`. State checks also bound matching and n-gram scoring. `top` controls retained distinct plaintexts, not the amount searched. The app further caps a launch at 5,000 compatible orders and 100,000 evaluated completions.

Only `complete: true` / `top_k_exact: true` certifies the top-k over the entire declared family. On interruption, the retained list is exactly ranked over fully evaluated completions, but no upper bound on unseen scores is claimed. `feasible` is false only after an exhausted search finds no completion; it is null if a bound was reached before a fit was evaluated. Exact total order and assignment counts are withheld on truncation. The compatible-assignment lower bound includes all completions of each route reached, even when a budget stops partway through its keys.

`run_joint_ranked(request, target_fn)` is the CLI adapter. It validates request fields, loads the model through `CharacterNgramModel.from_json`, records the model file hash, and checks that the model file did not change during the search. The result schema is `kryptos.joint-ranked.v1`; each candidate includes `plaintext`, `column_order`, `key_pattern`, `permutation`, `score_exact`, and `encryption_recipe`.

## Verification scope

The targeted tests use an independent literal oracle over every four-column permutation and all 26² two-letter keys. They cover both stage orders and all three equations, ragged geometry, a non-affine alphabet, bottom-to-top reads, exact ties, mask gaps, unused phases, agreement with the existing counting solver, and separate censoring bounds. Their language model is explicitly synthetic; these controls establish implementation behavior, not natural-language accuracy or a claim about K4.
