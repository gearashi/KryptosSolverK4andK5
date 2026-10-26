# Phase P: eight optional search reductions

Version0.5 implements the eight proposals in [the frozen plan](phase_P_plan.json).
The priority is fewer decisions or complete candidate evaluations for the same
exact result. Bounds, propagation, cache construction, replay and other work
are reported separately. All options default off: fewer decisions can still
cost more total work, and small authored cases do not establish K4 performance.

| # | Implemented option | Recorded finite result and limitation |
| --- | --- | --- |
| 1 | Ranked route/key fixed-point propagation | Fewer branch decisions in10 of19 cases, unchanged in9; identical candidate counts and more counted state work in all19. One ragged control changes3 decisions to2, but60 states to132. |
| 2 | Early partial ragged-segmentation checks | Two controls reach2 complete length patterns instead of3 and6 route nodes instead of7. Candidate evaluations and branch decisions are unchanged; total states rise60 to95. Earlier rejection is verified, but this bank does not justify an overall efficiency recommendation. |
| 3 | Interleaved constrained variable choice | Fewer decisions in8 cases, unchanged in3, more in8. Candidate evaluations are unchanged and all19 incur more state work. It is a choice for particular constraint structures, not a better universal ordering. |
| 4 | Shared-key correlated language bounds | On the sixgram control,52 candidate evaluations become26 and5 decisions become3; state work rises4737 to7959. Another control reduces2548 evaluations to1352. Equal-score branches remain searchable. |
| 5 | Proven equivalent-route suppression | The identical-chunk TS control reduces4056 evaluations to676,166 decisions to27, and33736 states to5726. Nonidentical chunks retain neutral/unfavorable cases. Only proven equal-chunk/phase symmetries are removed. |
| 6 | Shared unfinished family scans | Compatible campaign jobs extend one original committed sequence, retaining each job's own replayed recipe and historical snapshot. Different enumeration bases never exchange offsets. Only certified, fixed-resource, same-family/model/mask jobs qualify. See the separate campaign evidence below. |
| 7 | Exact solved-component reuse | The integrated control uses3 proof nodes instead of11, but35 original-factor evaluations instead of34. Component solving without cache costs39 evaluations; caching reduces that to35. This is solved-subproblem reuse, not hard-cipher contradiction learning. |
| 8 | Cheap rejection before stronger bounds | The fixed control reduces original-factor evaluations146 to116 and grouped bounds14 to7; proof nodes remain6. There are14 preparation entries,12 gate calls and39 factor checks. The flat control adds preparation with no saving. |

The five joint options combined reduce decisions in14 of19 cases and leave5
unchanged. They reduce complete evaluations in4 cases and leave15 unchanged,
but reduce total counted states in only2 cases. These results support explicit
controls, not enabling everything by default. Domain-frontier variants also
resolve singleton edges, so their differences are not pure causal estimates
of one filter in isolation.

## Exactness and evidence

The joint audit compares19 frozen cases under7 variants, or133 completed
searches. Independent full permutation/key enumeration checks distinct-text
top-k, integer scores and canonical labelled recipes. Thirteen capped slices
produce the same52 unique search evaluations as uninterrupted execution, plus
48 saved-candidate objective checks;464 states compare with402 uninterrupted.

The factor audit checks864 partial contexts and96 complete searches against
literal enumeration, including zeros, powers, lexical ties, resource fallbacks
and checkpoint continuation. A separate reviewer checks432 residual optima,
3456 cheap-gate rejection decisions and64 full searches on16 authored problems.
Component witnesses are verified against immutable original factors; a zero
score is feasible and never treated as a contradiction.

Canonical joint and factor results are in
[release-P-001](runs/release-P-001), with per-kind manifests, frozen source
snapshots and before/after hashes. Both executions completed with valid evidence
records. The first campaign audit is preserved as failed: its independent
replay helper assumed a top-level alphabet on a scheduled recipe. That failure
is an audit-helper defect, not evidence of a solver mismatch. The repaired
campaign audit completed in a fresh [release-P-002](runs/release-P-002/campaign)
directory: all six unchanged controls,295 literal replays and exact masked-score
checks passed. All121 input hashes matched. The [repair note](campaign_P_audit_repair.md)
records the failure and correction; old evidence is not replaced.

Campaign controls distinguish repeated partial-prefix work from independently
completed rankings. Default-off limited jobs can each evaluate the same13 texts;
sharing continues13+13 to26 distinct texts. The separate52-versus26 comparison
concerns two independently completed recipe rankings, not an improvement over
the pre-existing completed-family cache. Earlier partial job snapshots stay
partial after a later owner finishes. Identity checks and literal alias replay
cost additional work. The deliberately non-equivalent Beaufort case is retained
and correctly starts its own scan.

## Reproduction and review

Use an installed computation-audit skill directory and a fresh label:

```text
python research/run_P_audit.py --audit-skill PATH --kind joint --label FRESH-LABEL
python research/run_P_audit.py --audit-skill PATH --kind factor --label FRESH-LABEL
python research/run_P_audit.py --audit-skill PATH --kind campaign --label FRESH-LABEL
```

The wrapper freezes contracts and source bytes, enforces outer deadlines and
validates v2 manifests. Reusing an output directory is refused. A successful
process alone is not a correctness or efficiency claim. These controls do not
rescore the reserved phase O multilingual bank for tuning.

Detailed arguments and limitations: [joint notes](joint_P_notes.md),
[factor notes](factor_P_notes.md), [campaign notes](campaign_P_notes.md),
[campaign review](review_P_campaign.md), [factor review](review_P_factor.md), and
[joint review](review_P_joint.md). Current package/browser/publication status is
recorded in [release-validation.json](release-validation.json).

The dashboard exposes all options and lists techniques from the saved run on
candidate cards. See [search controls](../docs/SEARCH_STRATEGIES.md) and
[campaign snapshot semantics](../docs/WORKSPACE_AND_RELEASE.md). No result in
this phase authenticates a K4/K5 plaintext or identifies Kryptos's actual cipher.
