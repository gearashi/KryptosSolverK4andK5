# P7/P8: exact component reuse and cheap rejection gates

Both features default off. The frozen protocol is `factor_P_protocol.json`;
`factor_P.py --output FRESH.json` is the finite CPU-only audit script. It does
not read reserved O messages or use a GPU. Canonical execution waits for the
shared source freeze. The new thirteen tests and adjacent factor/search
regressions passed (37 passed, one expected CUDA opt-in skip); these development
checks are not a substitute for the future manifested run.
These are development-known mechanism controls, not a held-out recovery bank.

## Scope and options

`residual_cache="components"` enables an invocation-local exact component solver
and memo. Its independent bounds are `residual_cache_max_entries` (default256,
0..10000), `residual_cache_max_assignments` (default256, 1..100000), and
`residual_cache_max_operations` (default200000, 1..10000000). Capacity zero runs
the same component-solving procedure without storage, supplying a useful cost
control. `cheap_bound_first=true` enables a separate threshold-only gate before
expensive child bounds. CLI `optimize-plus` and parallel optimizer jobs accept
the same fields. All are part of checkpoint search identity.

P7 implements solved residual-subproblem reuse. It does **not** implement hard
cipher-constraint contradiction or nogood learning: the product optimizer
operates on an already feasible Cartesian/affine assignment family. An exact
residual optimum below the incumbent is proven uncompetitive; an optimum of
zero means every completion scores zero and remains feasible. Hard-constraint
learning belongs to a constraint engine and remains outside this implementation.

## Why component reuse preserves the exact answer

The constructor validates and copies the original objective into immutable
tuples/read-only mappings. No mutable caller-owned factor, model or count map
remains referenced, and no cache crosses problem instances or invocations.
Conditioning a node separates factors by connected components of their remaining
free variables. The key includes original factor IDs, free original variables
and their domain sizes, plus every fixed coordinate appearing in those factors.
Similar-looking or isomorphic components are not merged.

A component is stored only after exhausting its declared Cartesian domain.
The stored witness is the lexical first optimum in sorted original-variable
order. Every hit and every new optimum is checked by direct evaluation of the
frozen original component factors, including powers. A completed assembled
answer is additionally checked against every original problem factor without
using cached scores. If all component maxima are positive, multiplying them
and combining their lexical minima yields the global optimum and tie break.
If a constant or any exact component maximum is zero, all full completions
score zero, so the correct answer is the original residual lexical minimum,
including other components' non-optimal assignments and unused coordinates.

Oversized components can leave smaller solved entries for later contexts but
cannot cause an exclusion. Operation/time cutoffs return inconclusive and the
ordinary search proceeds; an elapsed global time budget restores the unexpanded
parent. Memo entries are not checkpointed. Resume rebuilds an empty memo and
the ordinary full frontier bounds, sacrificing reuse but preserving obligations.
This argument trusts internally generated entries; the cache is not an API for
importing unsigned claims of optimality from external files.

## Why the cheap gate is admissible

Each original factor gets a universal maximum, with its power applied. Their
product bounds every assignment. The gate replaces individual maxima with
already computed local bounds or values of fully fixed factors. Each successive
product remains an upper bound. Zero universal factors are handled without
division. A branch is rejected only below the incumbent score, or at equality
when its original-coordinate lexical minimum cannot improve the incumbent.

This gate never supplies a saved frontier value. Every retained child, initial
root and restored checkpoint node still uses the full deterministic grouped/
mini-bucket bound. Consequently the incumbent-dependent gate cannot make saved
bounds fail reconstruction. Disabling a feature on resume is rejected by the
search identity rather than silently changing the convention.

## Honest work comparisons

The audit compares the integrated optimizer with default-off, components with
zero storage, and components with256 entries on the same frozen repeated-context
problem. It reports nodes and original-factor evaluations including all component
enumeration and repeated witness checks. Helper-only savings are recorded
separately and cannot establish savings over the existing default optimizer.
`integrated_cache_benefit_observed` explicitly reports whether that stronger
comparison saves nodes or original-factor evaluations.

Additional counters expose immutable snapshot items, planning, component-domain
visits, lookups, hits, stores, capacity skips, invalidations, assignment-cap skips,
and resource fallback. The main evaluator counts its direct factor evaluations;
`residual_witness_factor_evaluations` is a subset and must not be added twice.
Cheap maximum-table preparation, cached-bound hits and gate checks are separate
overhead. These counters are specified operations, not a total CPU instruction
count or wall-time guarantee.

Unfavorable controls are mandatory: changing boundary values yields no cache
hits; small component/operation caps fall back; a flat optimum already solved
by the initial bound makes cheap preparation pure overhead. The benefit control
compares identical grouped/mini-bucket settings with the cheap gate off/on.
Independent finite enumeration checks scores and lexical ties for every sampled
problem and every declared partial assignment. Whole-versus-sliced execution
checks completion and recomputes every saved bound with the full evaluator.

These are finite mechanism controls, not representative Kryptos performance.
No universal speedup, cipher contradiction-learning coverage, authenticated
plaintext or probability of a solution is claimed.
