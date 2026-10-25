# Phase O engine methods and evidence

The new switches default off. The success metric is fewer search decisions,
complete objective evaluations or factor evaluations for the same verified
result, with added bound work reported separately. This is not a universal
speedup or a claim that a Kryptos passage has been solved.

## Coordinated guided moves

`guided_seed.block_size=2` checks pairs of coordinates sharing a factor after a
single-coordinate sweep stalls. It evaluates the union of adjacent factors and
replaces their exact nonzero product and zero count. It remains inside the
declared affine coordinate domains. Every trial counts as one objective
evaluation and every affected factor is counted separately. At most 4096 pair
memberships are inspected, then at most `max_blocks` pairs are retained; pairs
with Cartesian size above `max_block_completions` are skipped and reported.
This bounded discovery is heuristic, not an exhaustive local-optimum proof.

## Relaxed elimination bound

`elimination_bound="mini_bucket"` splits an elimination bucket when its joined
Cartesian table would exceed `elimination_bucket_entries`. At each separator
assignment, nonnegativity gives

`max_x product_g F_g(x) <= product_g max_x F_g(x)`.

Repeating this relaxation yields a rigorous integer upper bound. Factors include
their powers; empty scopes, zero values and partially fixed coordinates preserve
the inequality. The optimizer takes the minimum of this bound and its existing
bound. It never treats the relaxed result as a feasible assignment. Deterministic
per-bound entry/operation caps return no new bound on exhaustion; the old bound
then remains in force. This option is independent of exact decomposition and can
still help when exact residual elimination is disabled or over budget.

## Joint route/key pruning and continuation

`pruning="admissible"` derives a superset of each plaintext position's possible
letters from the current column domains, matching-compatible edges and shared
key requirements. It maximizes each unmasked ngram over these independent letter
sets. Ignoring cross-window/key/column correlations can only increase a
nonnegative product. A branch is pruned only if its upper bound is strictly less
than the current kth distinct-text score. Equality remains searchable for
plaintext and representative-recipe ties. Complete keys are always fully scored
and counted; bound-scored leaves are not hidden as unevaluated candidates.

An explicit stack contains segmentation, route-prefix and key-prefix tasks.
An interrupted task is restored before saving; only completed task transitions
advance `frontier_progress_nodes`. `evaluated` and `states_total` are cumulative;
`evaluated_this_run` and `states_this_run` describe an invocation. Repeated setup
and interrupted bound work remain in the state counters. Invocation limits may
change on resume; family/model/mask/top/pruning semantics may not. Extremely
small limits can interrupt the same atomic task repeatedly; this reports no
frontier progress and requires a larger declared limit, not a false exclusion.
Checkpoint preparation additionally reports `checkpoint_candidate_verifications`
and `checkpoint_score_window_evaluations` in cumulative `work` and per-invocation
`work_this_run`. These retained-row objective rechecks are not new search
assignments and do not advance `evaluated` or the search-state budget. Each load
is bounded by `top` retained rows and the number of unmasked score windows.

Checkpoints are fresh, data-only JSON envelopes with strict duplicate-key and
size validation, normalized input/model/source identity and a payload SHA256.
Retained candidates are independently decrypted and rescored on load and
literally re-encrypted for output. Hashes detect corruption; they are not
signatures authenticating an externally fabricated proof history. The app owns
its checkpoint paths and verifies the saved file digest before resuming.

An exhausted frontier proves the distinct-plaintext top-k even when strict-score
pruning occurred. `enumeration_complete` then stays false and full order/key
counts are null; visited compatible-route lower bounds are explicitly separate.
Only unpruned exhaustive enumeration supplies full assignment counts.

## Fixed development controls

The contract is `research/search_O_acceptance.md`; the reproducible runner is
`python -B research/search_O.py --output <fresh-result.json>`. The parent supplies
a canonical computation-audit manifest after source freeze. Development output
is secondary evidence and does not replace a source-pinned release audit.

The first development run found the six-bit coupled barrier optimum in 11
objective/factor evaluations versus 49 contiguous evaluations to the same known
optimum; the unfavorable two-bit twin took 11 versus 4. A contradictory triangle
needed 5 baseline search nodes versus 1 with bucket sizes 4 or 8, adding 100 or 47
elimination operations respectively. The runner also retains the bucket-size-1
fallback control and checks 576 independently enumerated residual upper bounds.

On the fixed period-2 joint control, identical exact top text and recipe required
4056 versus 156 complete objective evaluations and 28678 versus 4202 total
counted states. The period-1 control had no evaluation reduction (156 each) and
added work (1222 versus 1566 states). Thirty-two bounded continuation slices
retained the same 156 completed candidates and final top-k as uninterrupted work;
1624 versus 1566 states disclose repeated preparation. These authored controls
are discriminators, not representative cryptanalytic performance estimates.
The revised runner also reports retained-candidate verification separately;
state counts alone are not the entire cost of resuming.
