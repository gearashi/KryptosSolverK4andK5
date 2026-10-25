# Phase O bound and continuation proof review

Reviewed 2026-10-25 by the sources agent, independently of the engine code's
implementer, with shared project context. This is a mathematical source review,
not formal verification. No new experiment was run for this record.

**Claim.** For validated finite domains and nonnegative integer factors, the
mini-bucket result bounds every residual completion from above. The joint
route/key window relaxation does likewise for its declared score. The stated
pruning and tie rules therefore preserve the required optimum or distinct-text
top-k. Continuation preserves outstanding obligations when its checkpoint was
produced by this implementation and remains intact.

**Verdict: conditional on the validated finite inputs and an intact,
implementation-generated frontier.** The bound and tie implications passed;
no concrete defect was found in the reviewed scope. This is not a claim about
Kryptos's actual cipher family, an authenticated solution, or arbitrary externally
fabricated checkpoint histories.

## Decisive implications

1. **Mini-buckets — passed.** In `kryptos/factor_decomposition.py:17`, fixed
   coordinates are substituted first and every powered factor enters exactly
   one table/group. For a fixed separator assignment, nonnegativity gives
   `max_x product_g F_g(x) <= product_g max_x F_g(x)`. Repeating the relaxation
   preserves the upper-bound direction. Constants, zero factors, positive
   powers and unused coordinates do not reverse it; the empty product is 1.
   Allocation/operation exhaustion returns `bound_available=false`, not zero
   or an exclusion. No feasible witness follows from this relaxed bound.

2. **Optimizer integration — passed.** `kryptos/search_runtime.py:289` takes
   the minimum of independently admissible bounds and retains the prior bound
   on fallback. Saved bounds are recomputed when loading. At lines 448 and
   491, a strictly smaller upper bound can be discarded. Equality is discarded
   only when the branch's original-coordinate lexical minimum cannot improve
   the incumbent's tie break. Thus the equality test is stronger than a score
   comparison alone.

3. **Joint window relaxation — passed.** In
   `kryptos/joint_ranked.py:189`, the union of allowed column/key choices at
   each position contains every actual completion letter. Ignoring shared-key,
   matching and cross-window correlations enlarges the allowed set. Each
   window's maximum count therefore bounds its actual count; multiplying the
   nonnegative `count*q+p` maxima bounds the exact score. The sorted-known-gram
   path also covers absent grams through the zero-count default. Empty-window
   scores are 1. The strict `upper < threshold` test at line 227 retains equal
   scores, preserving plaintext and representative-recipe lexical ties.

4. **Frontier and honest coverage — passed under the stated condition.**
   Children and route/pruning counters are committed only after an atomic task
   completes; a cutoff restores its original task (`joint_ranked.py:361`).
   Complete key leaves are fully scored rather than relabeled as bound-pruned
   candidates. Exhausting the frontier establishes the requested top-k, while
   score-pruned assignments remain unenumerated: `enumeration_complete` and
   full counts are withheld when pruning occurred (lines 373 and 408).
   Repeated interrupted bound work remains in reported work counters.

The dependency chain is: validated finite domains/factors and gather/phase
conventions → local upper-bound inequalities → sound branch exclusion and tie
handling → intact frontier transitions → completion conclusion. These are
internal algebraic arguments and implementation conventions; no external theorem
or finite experiment substitutes for the implication.

## Checkpoint and accounting limits

Hash, shape, model/source identity, candidate decoding and exact-score checks
detect many corruptions. They do not authenticate a history or prove that an
attacker did not delete pending tasks and recompute an unsigned checksum.
Completeness is conditional on an intact implementation-generated checkpoint;
arbitrary imported proof histories are outside this review.

The original joint review used SHA256
`801ca47adf5de6fe5e96bc0bad7dbd1c6d995b9b0b8cf9e1828d77b24ce3d909`.
The subsequent joint change adds accounting for already-existing retained-row
reverification: `checkpoint_candidate_verifications` and
`checkpoint_score_window_evaluations` (current lines 103–104 and 282–283).
It does not change candidate selection, pruning, or frontier transitions.
Those relevant paths were reread for this record. The unique search-completion
counter excludes these repeated checks; total objective work must include them.
The other two reviewed source hashes are unchanged.

## Exact current source revisions and evidence

| File | SHA256 |
| --- | --- |
| `kryptos/factor_decomposition.py` | `9bed97de6e0a5261d6f13ddfc6992f891c8ea02a8c258c9a5957d0cdb4161266` |
| `kryptos/search_runtime.py` | `479c33ed5fdb2cc046b49c058778d04f0c4dfbf1798812845be6ca10f730edba` |
| `kryptos/joint_ranked.py` | `79877e3b4bf4eafe6b979e39f0c1ecd05e6ce92808703374f25368a10cafc6a7` |

Finite implementation controls are recorded separately in
`research/runs/release-O-001/search/manifest.json` and `result.json`, with the
canonical source snapshot. CUDA scan evidence is separate under
`research/runs/release-O-001/scan`; it does not prove these branch bounds.
Reproduction commands are in `research/O_audit_commands.md` and require a fresh
label. This review performed source reads/hash checks only and did not rerun
either protocol. No remaining mathematical gap was identified within the stated
conditions; changes to domains, factor signs, tie rules or frontier serialization
require renewed review.
