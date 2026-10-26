# Phase P joint search: exact reductions and bounded evidence

The frozen acceptance plan is `research/joint_P_protocol.json`. All five new
options default to the prior behavior. The baseline's tested work counts remain
unchanged: the historical five-letter period-one control still reports 156
completed assignments and 1566 counted states. Source hashes intentionally
invalidate checkpoints made by older engine bytes; within one source identity,
default and enhanced frontiers retain data-only JSON continuation.

## Interface

`rank_joint_columnar` and `joint-ranked` accept:

| Option | Default | Alternative |
| --- | --- | --- |
| `propagation` | `off` | `fixed_point` |
| `early_segmentation` | `false` | `true` |
| `branching` | `prefix` | `constrained` |
| `score_bound` | `independent` | `shared_key` |
| `symmetry` | `off` | `identical_chunks` |
| `max_bound_cache_entries` | 2048 | Integer 0 through 10000 |

`score_bound=shared_key` requires `pruning=admissible`; an ineffective combination
is rejected. The bound cache is disposable and its size can change on resume.
Search options, ciphertext, geometry, cribs, scoring mask/model and all involved
helper sources are part of checkpoint identity.

Constrained branching may reach one labelled route through several disjoint
key-domain branches. `route_completion_blocks` counts these blocks and is the
quantity limited by `max_orders` in that mode. `column_orders_visited` and
`total_column_orders` are null there, rather than mislabelling repeated visits as
distinct routes. Complete, unpruned assignment enumeration still has an exact
assignment count, because key branches are disjoint. After score or symmetry
exclusions, full labelled totals are withheld. `evaluated` always counts complete
search assignments actually scored, with checkpoint replay costs separate.

## Correctness arguments

**Fixed-point propagation.** The helper reuses the counting solver's supported
perfect-matching edges and key-domain propagation. An edge incompatible with a
phase domain cannot occur in a solution. An edge outside every perfect matching
cannot occur either. Every slot and every source column must select an incident
edge, so intersecting the unions of their supported phase values is necessary.
Iterating these sound reductions to stability never removes a true solution.
Singleton edge implications are also enforced in the optional domain frontier.

**Partial ragged segmentation.** Only prefix chunks have known ciphertext
offsets. The suffix is represented by one wildcard slot per remaining column
length, with no ciphertext or crib requirement. A true completion induces a
perfect matching into those wildcard slots; failure of the relaxed prefix
matching/propagation therefore excludes the whole prefix. It never fixes an
unknown suffix offset or assumes padding. In the current small controls this
reduction is sound but did not earn an efficiency recommendation.

**Interleaved branching.** The optional frontier holds finite column domains and
26-bit key domains. A constrained step splits the smallest non-singleton domain;
ties prefer key domains and then original indices. Each split partitions its
parent, so no route/key assignment is lost or visited twice. The same route can
nevertheless appear in different key blocks, hence the conservative route-count
interface. Prefix mode remains available; the constrained heuristic is not
claimed to dominate it.

**Shared-key bounds.** At a position whose source column is already fixed to an
output slot, a proposed plaintext symbol determines exactly one key residue.
Within a scored ngram, equal phases must require equal residues belonging to the
current key domain. Unmapped positions are deliberately unconstrained. Every
true gram passes this test, so the highest compatible observed count, or the
unseen smoothing count, is an upper bound. The engine takes the minimum with its
existing independent-letter bound. Multiplication across windows ignores more
correlations and remains an upper bound because all factors are nonnegative.
Only strict upper-bound inequality prunes: score ties remain searchable for
plaintext and recipe lexical tie-breaking. Complete keys are scored normally.

**Duplicate-route symmetry.** Equivalent output slots must have equal lengths
and identical complete ciphertext chunks. For TS, their starting offsets must
also agree modulo the declared key period. Swapping source columns among these
slots therefore gives identical plaintext for every key under all three cipher
equations. Sorting the source column labels within each equivalence class gives
the smallest labelled route in that orbit without changing the key. Every orbit
has exactly one such representative, so distinct-text top-k and global canonical
recipe ties are preserved. The increasing-chain support filter implements this
condition before scoring. It does not assert maximal symmetry or quotient keys.

The result records the equality rule, bounded per-segmentation example groups,
and the factorial labelled orbit size for each example. Examples come from the
current invocation's disposable cache, not an exhaustive history. All groups
are reconstructible from the declared ciphertext/segmentation and rule without
expanding factorial aliases. Filter removals are work counters, not a fabricated
number of fully enumerated labelled assignments.

## Budgets and accounting

Each joint task is processed atomically into children or a completed leaf. A
cutoff restores the original task; copied slot/key domains prevent partial
propagation from modifying the saved parent. A live frontier memory limit also
restores the parent. JSON tasks contain only typed indices, masks and flags;
hashes detect changed bytes and inputs, not maliciously fabricated local proof
histories. Retained candidates are independently rescored on resume and
literally re-encrypted for output.

`branch_decisions` counts materialization of two or more alternatives, with
separate segmentation/slot/key counts. Forced transitions do not count as
choices. Repeated interrupted attempts remain counted work, not proof coverage.
This instrumentation adds no branches or state-budget ticks to default search.
The report also preserves compatibility construction/cache activity, propagation
rounds and states, early-prefix work, shared-bound gram/phase/cache work,
symmetry checks, candidate evaluations, and checkpoint verification. Some
category counters overlap (for example early propagation is also propagation);
they must not be summed as though they formed disjoint operation categories.

## Fixed development outcomes

`python -B research/joint_P.py --output <fresh-result.json>` evaluates 19 frozen
authored cases under the baseline, each option separately and all five together.
Every one of the 133 development runs completed and matched independent full
permutation/key enumeration for distinct-text top-k, exact scores and canonical
recipes. Development result 003 preserves all unfavorable outcomes; it is
secondary evidence pending the parent's frozen-source audit manifest.

| Option | Fewer / same / more branch decisions, across 19 cases |
| --- | --- |
| Fixed point | 10 / 9 / 0 |
| Early segmentation | 0 / 19 / 0 |
| Constrained branching | 8 / 3 / 8 |
| Shared-key bound | 2 / 17 / 0 |
| Identical chunks | 10 / 3 / 6 |
| All five | 14 / 5 / 0 |

The optional domain frontier also resolves deterministic singleton edges, so
single-option measurements include that representation work; they are not a
causal attribution of every difference to one mathematical filter. Decision
reductions often cost more total counted work. Fixed-point propagation did not
save completed candidate evaluations on this bank and added state work.

The two ragged-prefix controls each reduce completed segmentations from 3 to 2
and route nodes from 7 to 6. This is a real earlier rejection, but decision and
candidate counts stay unchanged and counted states increase from 60 to 95.
The runner reports completed segmentation counts and signed deltas explicitly.

The identical-chunk TS control is a clearer structural win: 4056 to 676 scored
assignments, 166 to 27 branch decisions, and 33736 to 5726 counted states. The
shared-key sixgram control used 52 versus 26 scored assignments and 5 versus 3
decisions, but increased counted states from 4737 to 7959. The nonidentical-chunk
controls retain neutral or unfavorable symmetry overhead. Early segmentation
remains an explicitly optional experiment: no decision/evaluation win was
demonstrated here, and all its extra work is retained.

Thirteen capped combined-option slices reproduce the uninterrupted final
candidates and 52 unique search evaluations. They additionally verify 48 saved
candidate objectives and use 464 versus 402 counted states. No restart overhead
is presented as new coverage or hidden as a search-efficiency gain.

The focused source/test command passed 29 tests, including all 32 option
combinations, 12 frozen cases, restricted-domain correlated gram oracles,
negative TS-phase symmetry controls, resumed frontiers, prior phase O oracles,
and app-managed constrained continuation:

```
.venv/Scripts/python.exe -B -m unittest tests.test_joint_P tests.test_joint_ranked tests.test_search_O tests.test_app_P -q
```

These are small authored discriminators, not representative cryptanalytic
performance estimates. No reserved O validation bank, real K4 search, GPU run,
authenticity claim or universal speedup is part of this phase-P engine evidence.
