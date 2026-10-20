# Eight improvements, checkpoint N

Original development baseline: `768289f12802c05a744504e5cc3751c1a1f8be30` (historical version 0.2.0). Publication continues the recreated repository from `80b817564479aace3189217b353dad6c38ea1900`, which includes the CUDA component-path fix. Earlier commit identifiers are historical evidence, not ancestors of this repository. The user resumed all eight improvements and their validation on 2026-10-20. This implementation goal is distinct from authenticating a Kryptos decipherment.

| Obligation | Owner | Decisive acceptance check |
| --- | --- | --- |
| N01: language-ranked unknown column routes and keys | interface | Exact small exhaustive top-k oracle, independent recipe replay, explicit censoring |
| N02: bounded layered-hypothesis grammar | root | Complete declared expansion; literal gather simplifications preserve encryption; all aliases retained |
| N03: guided feasible-family seeds | engine | Exact delta scores match independent full scores; deterministic equal-budget comparison; all seeds replay |
| N04: component/separator exact optimization | engine | Exhaustive graph oracle including zero products and lexical ties; capped fallback preserves frontier |
| N05: completed-family reuse across campaigns | root | Reuse survives restart; corrupt, stale, incomplete or approximate cache records do not authorize reuse |
| N06: browser exact-search pause/resume | root | Interrupted and uninterrupted proof searches agree; immutable checkpoints commit atomically with saved frontier |
| N07: reserved K4-shaped benchmark bank | sources | Frozen independent multilingual controls, actual separated clue positions, hidden competing recipes and surviving ambiguity; completion/censoring recorded |
| N08: refitted stage/route ablations | sources | Redundant and essential synthetic stages differentiated through refitting and withheld predictions; budget limits remain explicit |

All eight implementations are present in application version0.3.0. Canonical N004 search, reserved-validation and CPU/CUDA worker audits passed after the final Python source freeze; browser and clean publication checks are recorded in [release validation](release-validation.json). Historical M and N001–N003 audits retain their original source revisions.

## Implementation and measured results

- **N01:** `joint-ranked` combines supported-edge/matching route constraints with bounded exact integer language ranking over compatible keys. Independent enumeration checked24 cases across both stage orders, two alphabets, three substitution equations and two column directions:97,344 raw route/key completions and168 retained replays agreed. Exact top-k is claimed only after declared exhaustion; a capped prefix remains incomplete.
- **N02:** the browser campaign generator expands explicit S/T stage patterns, periods, alphabets, equations and grid routes. It caps raw expansion at4096 and distinct jobs at128, composes only adjacent literal gathers, removes identity gathers and retains original recipe aliases. It neither collapses independent unknown keys nor samples an oversized grammar.
- **N03:** deterministic guided coordinate ascent uses exact incident-factor score updates inside the valid affine family. Eight preregistered general/scheduled controls used192 objective evaluations per method. Guidance improved the objective in8/8 and retained the authored truth in8/8, versus0/8 for the contiguous prefix;64 retained objective/replay checks passed. Guidance took0.063–0.125seconds versus0.047–0.063seconds for the contiguous prefix. This is a quality-per-evaluation result, not a wall-clock speedup or general recovery-rate estimate.
- **N04:** exact component/separator elimination handles fixed variables, disconnected graphs, powers, zero products and original-coordinate lexical ties. Sixty cases matched1,164 independently enumerated completions. A sparse14-variable chain required one frontier node instead of29, with68 table entries and606 counted operations. This tiny fixture does not establish a runtime speedup. A separate independent review checked160 more exhaustive cases. Entry/operation/time caps preserve ordinary exact-search fallback and frontier obligations.
- **N05:** the completed-family index survives server restart and references hashed completed runs. Family, alphabet, model, mask, source revision, full coverage and exactness are checked again. Cross-campaign aliases reconstruct their own keys and encryption recipe. Tests reject corrupted, stale, partial, approximate and changed-mask records.
- **N06:** `optimize-plus` exposes real Pause/Resume with immutable frontier files and atomic digest/pointer commits. A27-activation one-node control matches uninterrupted optimality and score. Tests cover pause/stop, restart, corruption and failed commits. CUDA seed use remains visible after CPU frontier continuation, and executable checkpoint paths are absent from exports.
- **N07:** six newly authored English/French/Spanish passages, K4's actual separated24-position clue mask, six layered/grid models and paired nulls were frozen before scoring. All66 algebra-only preflight checks reproduced. All12 inputs completed with4,316 candidate visits/replays; all6 positives uniquely ranked first and all6 nulls retained wrong alternatives. Independent numeric encryption checked all12 generated ciphertexts. Each positive ultimately had only one inequivalent surviving plaintext family, so this establishes hidden-bank filtering and within-family ranking, not ranking several distinct surviving families against one another. Fixtures were not tuned after this result.
- **N08:** ablations delete a substitution or neutralize a gather, then refit all remaining keys before inspecting withheld labels. The recorded instructional case predicts3/3 held letters at baseline; removing the substitution contradicts training, and neutralizing the route predicts0/3. Empty fits have no invented winning prediction. Scheduled models explicitly freeze or recompute their coordinate schedules. These are conditional recipe comparisons, not evidence of Kryptos's historical method.

## Further improvements found and implemented

1. Browser testing found that a fixed two-second slice could spend its whole budget rebuilding a saved frontier and make no progress on Resume. The service now doubles subsequent slice time up to the user's declared cap, saving that decision atomically with the frontier. Batch/node/activation budgets remain in force; a capped stall stays inconclusive. The failed browser attempt is preserved under `release-N-001/browser/attempt-before-adaptive-slices/`.
2. Campaign cleanup retains a worker-pool reference if shutdown fails, reports the failure, and verifies cleanup on retry. This avoids silently abandoning process ownership.
3. Loaded optimizer node/time bounds are checked again; saved checkpoint integrity is checked before launch; CUDA seed provenance survives later CPU slices.
4. Validation protocols, including refit ablations, are rejected as ordinary campaign jobs, preserving their separate withheld-label and full-bank semantics.
5. Exact candidate cards now associate the matching optimizer result with its score/model, optimality/tie proof, frontier, seed and decomposition evidence. Empty ablations display “no fitting plaintext”; their prediction/delta stays unavailable.
6. Explicit campaign resume now continues a nonterminal job whose child durably reached a budget limit just before interruption prevented the campaign outcome commit. A crash-gap regression verifies that the existing child/frontier advances only after resume; ordinary terminal incomplete jobs retain their declared budgets.
7. A decomposition timeout that restores its parent now reports processed work separately from frontier advancement. Managed slices can grow from two to four seconds when that attempt makes no frontier progress, within the user's limit; repeated work still consumes the node budget. A regression reaches exact completion without inflating reported frontier advancement.
8. A portable browser runner replaces machine-specific paths for new validation runs. Fresh output directories preserve prior evidence; tests cover CPU/CUDA comparisons, resource changes, exports, tamper rejection, new N flows and mobile layout.

The final post-integration review covers correctness, bounded performance, model coverage, usability and persistence. It closes this accepted implementation batch; it does not prove that every possible improvement has been exhausted. Future recovery studies need independently designed cases with several inequivalent surviving families, without retuning this reserved bank.

## Reproduction and evidence

- [Search audit](runs/release-N-004/search/manifest.json), [results](runs/release-N-004/search/result.json): frozen equal-budget comparisons, exhaustive decomposition and independent route/key enumeration.
- [Reserved validation audit](runs/release-N-004/validation/manifest.json), [results](runs/release-N-004/validation/result.json): predeclared multilingual bank, generated-input replay and refit ablations.
- [CPU/CUDA worker audit](runs/release-N-004/persistent/manifest.json), [results](runs/release-N-004/persistent/result.json):20 fixed pages per backend and worker mode, exact rankings, independent replay and process recovery.
- [Search strategies](../docs/SEARCH_STRATEGIES.md), [joint ranking](../docs/JOINT_RANKING.md), [validation protocol](validation_N_notes.md), [local app guide](../docs/LOCAL_APP.md).

All three audit manifests pin execution inputs before and after. Portable authored input snapshots preserve the original bytes, including the pre-fix N001 search record. The clean publication suite opts into actual CUDA tests; raw third-party source audits remain optional because those pages are excluded. See release validation for exact counts, browser evidence and verified publication status.

K4/K5 remain undeciphered here. Matching clues, exact recipe replay, plausible language or a completed finite optimization does not authenticate a solution. No authenticated public K5 ciphertext or external solution submission is added.
