# Guided incumbents and exact factor decomposition

## Additional search reductions in version0.5

All eight phase P features are optional. Use **Additional search reductions**
in a ranked joint recipe, the optimizer controls, or the campaign sharing
selector. Candidate cards identify the techniques saved with that run.
The [phase P evidence](../research/IMPROVEMENTS_P.md) compares decisions,
complete candidates and additional work separately; no option is universally
better and the small authored controls do not establish K4 performance.

Ranked joint requests accept:

```json
{
  "propagation": "fixed_point",
  "early_segmentation": true,
  "branching": "constrained",
  "pruning": "admissible",
  "score_bound": "shared_key",
  "max_bound_cache_entries": 2048,
  "symmetry": "identical_chunks"
}
```

These fields extend an existing `joint-ranked` request. Defaults are respectively
`off`, `false`, `prefix`, `off`, `independent`, 2048 and `off`. Fixed-point
propagation combines matching supports and shared-key clue constraints. Partial
ragged-grid checks leave unknown suffix positions unconstrained. Constrained
branching chooses the smallest remaining route/key domain. Shared-key bounds
require admissible pruning and enforce repeated key phases within each ngram;
different ngram maxima remain an upper bound rather than a complete witness.

Equivalent-route suppression requires identical ciphertext chunks of the same
length; TS also requires equal offsets modulo the key period. It preserves the
canonical labelled recipe and records how equivalent routes can be reconstructed.
Symmetry representatives and score exclusions do not count as full enumeration.
With interleaved branching, `route_completion_blocks` can revisit one route under
disjoint key domains; distinct order counts are withheld. The `max_orders` limit
then caps those blocks per activation. Search identity includes the five strategy
choices; changing those requires a new run. The disposable bound-cache capacity
can change in standalone continuation; caches are rebuilt on resume. Dashboard
resume preserves the saved request and resource caps.

Exact optimizer requests also accept:

```json
{
  "residual_cache": "components",
  "residual_cache_max_entries": 256,
  "residual_cache_max_assignments": 256,
  "residual_cache_max_operations": 200000,
  "cheap_bound_first": true
}
```

Both strategies default off. Component reuse solves sufficiently small connected
residual factor problems and reuses only identical immutable contexts. Every
witness is checked against original factors. Zero score remains feasible and
uses the global lexical tie rule. This is solved-subproblem reuse, not general
cipher contradiction learning. Oversized or interrupted solves fall back to the
ordinary search; no external or cross-invocation cache is trusted.

The cheap gate attempts a valid rejection before stronger grouped or mini-bucket
bounds. Retained frontier entries always use the full deterministic bound so
checkpoint reconstruction remains valid. The dashboard caps cache entries at1024,
component assignments at4096 and operations at200000. Exact component solving,
cache verification, preparation and bound work are separately reported.

These optional `optimize-plus` strategies operate on the same finite affine
plaintext family and frozen ngram objective as the ordinary exact optimizer.
They do not change the supplied cipher assumptions, score mask, or recipe.

```json
{
  "guided_seed": {
    "seed": 19,
    "restarts": 8,
    "max_evaluations": 2048,
    "max_sweeps": 8,
    "top": 4,
    "max_factor_evaluations": 200000
  },
  "decomposition": "auto",
  "decomposition_max_entries": 20000,
  "decomposition_max_operations": 200000
}
```

Add these fields to an otherwise valid request with ciphertext, cribs, stages,
alphabet, and an explicit `model_path`. Omit `guided_seed` to disable guidance.
`decomposition` defaults to `off`, preserving the previous search strategy.
These are different algorithms, not expanded key-period or route ranges.

## Guided search

`kryptos.guided_search.guided_seeds(problem, ...)` performs deterministic seeded
multistart coordinate ascent in the exact factor domains. For general and
scheduled cipher families those are the independent F2 coordinates followed by
F13 coordinates. Every in-range point belongs to the crib-compatible family.

One coordinate move recalculates only its incident factors. The maintained
product of positive factors and count of zero factors allow exact integer
division/multiplication, including zero objectives and factor powers. No
floating score difference decides a move. Equal scores prefer the smaller
coordinate; retained candidates use the original full-coordinate lexical tie.
Every evaluated point can enter the retained list, not just final local optima.

The first restart uses the first supplied scanner seed, or zero coordinates if
none is available. Further supplied scanner seeds come next, followed by points
from Python `random.Random` with the recorded seed. Each sweep visits active
coordinates in a seeded shuffled order and considers every alternative value.
An ascent can stop at a local optimum. There is no claim that it samples the
family uniformly, finds its global optimum, or outperforms a contiguous scan.

The standalone API also accepts `time_limit_seconds` and `initial_assignments`.
The CLI takes the remaining overall time budget and scanner hints internally.
Its retained points are checked again with a complete independent objective
evaluation and literal CPU encryption replay before entering the exact search.
`optimization.search.guided_seed` records the seed, caps, work, stop reason,
retained coordinates/objectives, and verified replay count. The guidance work
counts exclude this separately reported final verification. Guidance uses CPU;
an optional existing `seed_scan` can still use certified CUDA.

Caps are 100 restarts, 100,000 objective evaluations, 1,000 sweeps per restart,
100 retained hints, and 2,000,000 factor evaluations. Caps are checked before a
trial; an interrupted trial is never retained. Objective counts include the
initial score of each restart. All factor values actually computed are counted,
including work in an interrupted trial. The reported avoided factor evaluations
compare completed coordinate trials with recomputing every factor each time.
Elapsed-time cutoffs are cooperative and can vary across machines.

Guidance only supplies incumbents. The exact frontier and admissible bounds
retain all remaining proof obligations. On checkpoint resume, the CLI skips
both scanner and guided seeding and keeps the saved incumbent.

## Exact decomposition

`kryptos.factor_decomposition.exact_decomposition(problem, assignment, ...)`
tries exact max-product variable elimination on a residual domain. Fixed
coordinates are substituted first. Disconnected factor components separate
naturally; within each component the planner chooses the smallest current
Cartesian bucket, using separator width and original index to break ties.
This greedy order is deterministic, but is not claimed to minimize treewidth.

Each elimination message maps separator values to an exact best product and a
mixed-radix lexical cost for eliminated coordinates. A coordinate contributes
its value times its place value in the original full assignment. Eliminated
subtrees are disjoint, so their costs add. For positive products, maximizing
the conditional message and minimizing its tied cost preserves the original
lexical optimum, regardless of elimination order.

Nonnegative factors require special treatment when the optimum is zero. In
that case every completion scores zero, so the correct answer is the original
residual domain's lexical minimum, including unscored coordinates. A constant
zero factor proves this immediately. The implementation also handles empty
factor sets, powers, fixed coordinates, and multiple independent components.

Before allocating nonconstant tables, the planner bounds cumulative original
and intermediate table entries. `decomposition_max_entries` limits that total
per attempt, up to 1,000,000. `decomposition_max_operations` is shared across all
decomposition attempts in one optimizer invocation, up to 10,000,000. Operations
count inspected planning memberships, evaluated original factors, and bucket
product multiplications. Input validation, integer bit complexity, and the
ordinary optimizer's bound/replay work are outside this scalar count. The
ordinary cooperative time limit remains active.

An attempt either returns a proven exact residual optimum or returns no
assignment/score. Entry or operation limits fall back to normal exact
branching. A time cutoff restores the unexpanded parent to the saved frontier.
Dense scopes can make decomposition unhelpful, and a failed attempt still
consumes its recorded work. A completed residual witness is rescored against
the original factors before its frontier node is removed.

The optimizer's `decomposition` report gives attempts, solved residuals,
fallback reasons, work, component count and maximum separator width. `nodes`
still counts processed frontier nodes; eliminating a whole residual family
does not pretend that its individual assignments were enumerated. When the
remaining frontier is empty, existing `complete`, `optimal` and
`tie_break_proven` fields describe the same exact objective and original-space
tie convention as before.

`requeued_nodes` counts processed parents restored after a cutoff; their work
remains included in `nodes` and `nodes_total`. `frontier_progress_nodes` excludes
those restored parents. The browser records both work and committed frontier
advancements. If a timed slice leaves the frontier unchanged, its next slice may
grow within the user's declared time cap, including when decomposition consumed
the slice before restoring its parent. This does not grant a larger node budget
or count the repeated attempt as additional proof coverage.

## Checkpoints and validation

The `resume_path` / `checkpoint_path` API and frontier payload format are
unchanged. Source identity now includes both helpers and decomposition options.
An older-source checkpoint is rejected rather than silently reinterpreted.
Resource counters remain per invocation except the existing cumulative
`nodes_total`. The browser service separately owns its slice paths and atomic
committed checkpoint pointer; callers cannot submit arbitrary app paths.

Focused development controls:

```powershell
.venv/Scripts/python.exe -m unittest tests.test_guided_search tests.test_factor_decomposition tests.test_search_strategies_cli -v
```

These include 60 small residual-graph exhaustive oracles; zeros, powers,
constants and unscored variables; a nonstandard-alphabet ngram oracle; dense
fallbacks; timeout parent restoration; checkpoint continuation; and general /
scheduled recipe replay. Two explicit equal-evaluation examples demonstrate
both outcomes: guidance reaches a high leading-coordinate score before a
contiguous prefix does, and a local-optimum trap favors a contiguous page.
They test mechanisms, not natural-language generalization. A separate declared
benchmark must establish any recovery-rate or runtime benefit on hidden
synthetic cipher fixtures. No K4/K5 authenticity claim follows from a high score,
a completed finite optimization, or a matching encryption replay.

The reserved benchmark is `research/search_N.py`, with its pre-score plan in
`research/search_N_protocol.json`. It combines eight independent 97-letter
synthetic guidance comparisons, 60 residual-graph exhaustive checks, a sparse
graph discriminator, and 24 independent column/key ranking controls. The
separately reserved multilingual K4-shaped validation passages are not used.
`research/run_search_N_audit.py --audit-skill PATH --label FRESH_LABEL` snapshots
all package sources, tests, benchmark inputs and the model, applies a60-second
experiment limit with a75-second owned-process watchdog, and validates the
result manifest. Run it only after shared sources are frozen; it preserves
unfavorable guidance outcomes as evidence rather than tuning them away.

The current manifest-backed record, `research/runs/release-N-003/search/`, passed
against its portable snapshot at `research/source_snapshots/release-N-003-search/`
in3.547seconds. Guidance obtained higher objectives in all eight192-evaluation
comparisons and retained the generating text in all eight; the contiguous
prefix retained it in none. This is a quality-per-evaluation result, not a speed
result: guidance took0.156–0.235seconds per case versus0.078–0.141seconds for the
baseline. Sixty-four retained objectives and literal recipes were checked.

The60 residual cases agreed on all1,164 exhaustively enumerated completions.
The sparse discriminator used one frontier node with decomposition versus29
without, with68 allocated entries and606 counted elimination operations. Its
tiny wall times do not establish a speed benefit. All24 joint controls matched
97,344 independent order/key completions and168 retained literal replays.
The preserved `release-N-001` record tested the same frozen bank before a
browser slice-duration adjustment. N002 pins that revised package; N003 also
pins a corrected unrelated one-shot resource-control test fixture. All three
retain their own source/test snapshots and timings, with the same discrete
scientific outcomes and no benchmark tuning. This algorithm audit does not
itself exercise browser lifecycle behavior. These small synthetic results do
not establish a recovery rate for Kryptos.

## Phase O: reducing counted search work

All optional strategies remain off unless selected. Compare complete candidate
evaluations, frontier nodes and factor operations separately; elapsed time is not
the acceptance criterion. A stronger bound can reduce search nodes while costing
more arithmetic. A negative comparison is retained rather than called a win.

- `guided_seed.block_size=2` tries coordinated changes for connected parameter
  pairs. `max_blocks` and `max_block_completions` bound the extra work. Every
  completed trial receives its exact incident-factor score. Single-coordinate
  behavior remains available with `block_size=1`.
- `elimination_bound="mini_bucket"` partitions oversized factor groups and uses
  their exact separate maxima as an admissible upper bound. Bucket, storage and
  operation caps fall back to the existing bound. This relaxation never supplies
  a purported feasible witness.
- `joint-ranked` accepts `pruning="admissible"`. Reachable-letter/window bounds
  prune only when strictly below the current distinct-text cutoff, preserving
  tied plaintexts and deterministic recipes. A full key always counts as a
  complete objective evaluation. `top_k_exact` can be true after pruning, while
  exhaustive assignment counts are unavailable unless enumeration completed.
- `joint-ranked` also accepts `checkpoint_path` and `resume_path` in the CLI.
  The browser manages these paths itself. A pure JSON frontier pins the request,
  sources and language model; committed counters are cumulative and invocation
  counters expose slice work. Resume rechecks saved candidates and reports that
  verification separately. Pause saves the current slice; Stop discards it.
- CPU batch scoring updates only ngram windows touched by changed letters, with
  exact integer arithmetic and a full-score fallback for dense changes. The
  candidate population is unchanged. Work reports show the factor evaluations
  performed and avoided.

CUDA certified mode selects interval survivors on the device and still checks
them with exact CPU scores and replay. Its transfer counter covers explicit
filter payload, excluding library control traffic and candidate-letter transfers.
An optional `auto-measured` backend evaluates the same sample of at most32 points
on CPU and CUDA, requires agreement and caches its device choice. This adds
calibration work; it is hardware convenience, not fewer solving steps.

Sculpture path hypotheses use `routes:["paths"]` and bounded `path_parameters`.
Starting cells, cardinal directions, turn handedness and wrap policy produce
explicit bijections. Trapped paths are rejected and duplicate permutations share
one fitting call while retaining all parameter aliases. These coordinates are
ordinal text positions, not measured sculpture geometry.

`validate-controls` can run repeated complete-bank shuffled controls with
`null_replicates`, a frozen `decision_score_threshold` and a total
`max_protocol_candidates` cap. It reports completed/evaluated family counts
separately. Any censored selection suppresses the empirical exceedance rate.
That rate is a finite control statistic, never a probability of authenticity.
See [phase O evidence](../research/IMPROVEMENTS_O.md) and the frozen protocols.

## Version0.6 conditional methods

The [90-item ledger](../research/IMPROVEMENTS_Q.md) records every phase Q proposal, including unsuccessful comparisons. The [Research methods panel and CLI](RESEARCH_METHODS.md) expose finite relation/SMT, factor, model and grammar experiments. Existing cipher optimizers accept optional `and_or`, `junction`, `diagram`, `chain` and `cutset` decomposition; `strong`/`separator` ordering; and `overlap`, `adaptive`, `cycles`, `reparameterization`, `mod2`/`mod13` bounds. Joint route/key search accepts `relational` propagation and an admissible `matching` bound.

Keep the existing `auto` decomposition as the initial comparator: new exact alternatives tied it on primary decisions in the fixed whole-problem suite. Their query reuse and representation facilities can help particular workloads. Strong branching and more elaborate bounds can add more work than they save. The restarted portfolio is unavailable after its negative comparison. [Measured hardware settings](HARDWARE_SETTINGS.md) apply to CPU/CUDA family scans; exact constraint algorithms remain CPU methods.
