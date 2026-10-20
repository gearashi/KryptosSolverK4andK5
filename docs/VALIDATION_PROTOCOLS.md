# Search quality and validation protocols

These additions preserve the existing cipher assumptions and frozen historical results. They improve how bounded hypotheses are tested; they do not authenticate a Kryptos solution.

## Verified scanner seeds for exact search

An `optimize-plus` request may include `seed_scan` with `backend` (`cpu`, `cuda`, or `auto`), `batch_size` (1–8192; default 256), `offset` (nonnegative; default 0), and `top` (1–10; default 1). Exactly one bounded page is requested. Every retained seed is reconstructed from the same solution's field coordinates, independently re-encrypted, checked against supplied letters, and scored again with the exact CPU integer objective. A different model hash or mismatched plaintext/score is rejected. No scanner claim of optimality is used to prune the exact search.

The best verified seed only improves the incumbent. The optimizer still proves its upper bound and original-coordinate lexical tie rule. Preparation and seeding time count toward the reported optimizer budget; a page already running can exceed a cooperative time budget and remains subject to the application's outer worker deadline. `seed_scan` is currently an `optimize-plus` option and is explicitly rejected by the older `batch` command.

`score_mask` is an optional list of distinct zero-based plaintext positions, separate from the letters used as constraints. It must include all constrained positions; its default is exactly those positions. Every n-gram crossing the mask is excluded. Scanner and exact objectives use the same mask.

## Joint factor bounds

Set `factor_group_size` to 2–8 to enable a deterministic partition of overlapping factors (0 is the default, disabled). `group_exact_limit` caps the Cartesian size of the group's unresolved variables (default 4096, maximum 100000). Within that cap, the bound is the exact maximum of the product for the entire group, including factor powers. Otherwise the existing product of safe individual bounds is used. Groups are disjoint, cover every factor, and are fixed before branching. Their membership and cap are included in checkpoint identity.

For every full assignment, a group's product is bounded by that group's maximum. Multiplying these nonnegative maxima over disjoint factor groups therefore bounds the complete objective even when variables cross group boundaries. Grouping can tighten incompatible individual maxima; it cannot justify a stronger cryptanalytic conclusion. Exhaustive small tests include all partial assignments, fallback paths, zero entries, powers, ties and checkpoint changes.

## Clue holdouts

`validate-holdout` takes a normal `target`/`ciphertext`/`cribs` input plus `withheld_positions`, a nonempty proper subset of supplied zero-based clue positions. The selection function receives only ciphertext, training letters, mask positions, the explicit model bank and scoring models. Withheld answer letters are accessed after selection. All supplied clue positions, including the withheld positions, are masked from ranking. A regression test changes only withheld answer labels and requires byte-equivalent selection results.

The retained candidates report predicted withheld letters and match counts. A public K4 holdout remains retrospective because researchers already know the clues and may have selected hypotheses using them. The implementation prevents algorithmic label leakage, not that historical selection bias. [The authored preset](../examples/validate-holdout.json) supplies two small competing models with a synthetic message.

## Competing-family positive and null controls

`validate-controls` accepts caller-supplied independent `cases`: each has `id`, uppercase `plaintext`, `source`, `generating_model_id`, and an explicit `keys` list. The generator must be a general-layer model from the declared bank. All cases have the same length and `crib_positions`. Each positive is paired with a deterministic shuffle of only unsupplied plaintext positions, preserving both the supplied letters and full plaintext inventory. Both are encrypted under the same generator and keys. The fitting boundary receives no generating keys or answer text.

Every input goes through the entire bank and every frozen scoring model. Complete plaintexts are deduplicated while retaining model aliases. Selection is maximum frozen-model mean log score, then plaintext lexical order; these are descriptive scores, not comparable probabilities of cipher methods. Every enumerated candidate is literally re-encrypted. Reports include per-family exact counts, completed visits, retained candidate recipes, truth ranks/ties within the evaluated set, wrong alternatives, and null-best versus positive-best comparisons.

The [frozen fast preset](../examples/validate-controls.json) has two newly authored 97-letter passages, two families (periods 25 and 26), and a contiguous artificial 24-position mask. This deliberately differs from K4's separated clue positions. Each input has 26 and 676 compatible completions across the two families; four inputs require 2,808 candidate visits. Fixture text and settings were saved before observing ranking outcomes. This is an implementation/selection benchmark, not representative language sampling.

## Request bounds and censoring

Checkpoint N adds a frozen separated-clue control bank and `validate-ablations` with explicit refitted variants. [The N validation notes](../research/validation_N_notes.md) specify the authored multilingual fixtures, algebra-only period selection, all66 structural checks, withheld-label boundary and scheduled-frame semantics. The new presets are `examples/validate-k4-shaped.json` and `examples/validate-ablations.json`. `research/run_validation_N.py` provides the bounded owned-process audit and portable input snapshot.

Both commands require `model_paths` (1–5 explicit frozen models sharing order and normalization) and `model_bank` (1–16 unique records). Each bank record contains `id`, `layer_model` (`general` or `scheduled`), `alphabet`, `stages`, and optional scheduled `cells`. Controls require at least two bank records and 2–8 cases. Invalid inputs fail explicitly.

`max_candidates_per_family` is 1–17576. `max_total_candidates` is 1–100000 per input, counting model visits before cross-family deduplication. `top` is 1–20. `time_limit_seconds` is a shared cooperative protocol limit up to 30 seconds, with separate algebra work/memory caps. Families larger than a candidate cap are not arbitrarily sampled. An exhausted wall-clock budget can censor later inputs; incomplete paired comparisons report `null`, not a reassuring score difference. No empirical p-value or solution probability is produced.

## Reproduction

Focused regressions: `python -B -m unittest tests.test_search_enhancements tests.test_validation_protocols -v`. Set `KRYPTOS_TEST_CUDA=1` to add the actual CUDA-seed replay test. `research/search_quality_M.py --inputs` lists the canonical audit inputs. After freezing shared sources, run it with `--backend cpu` or `--backend cuda` and a fresh `--output` under the project's bounded audit wrapper. It checks all 81 partial assignments of a fixed four-variable grouping discriminator, same-answer seeded search, and both complete authored protocols. Historical source snapshots and results are unchanged.
