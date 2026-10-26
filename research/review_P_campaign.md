# Independent P6 campaign review

Reviewed 2026-10-25 by the sources agent, separately from the campaign and UI
implementers, using the proof-audit general/implementation obligations. This
review read source, tests and the finite protocol; it ran no campaign, browser,
GPU or test suite and made no production edits.

**Claim and verdict: conditional on intact locally managed run records and the
existing certified scanner/family-identity contracts.** Within that scope,
equivalent recipes can extend one original committed coordinate sequence, retain
exact rankings over its prefix, and publish independent historical snapshots.
No unresolved correctness defect was found in the new sharing logic. The option
validation issue below was fixed by root and its correction was reread.

## Reviewed obligations

| Obligation | Evidence and assessment |
| --- | --- |
| Same family and score | `campaign_sharing.py:33` requires eligible matching same-alphabet affine scoring identities. `family_identity.py` fingerprints the reduced F2/F13 cosets, model bytes and full score mask. Equality permits reuse of plaintext rankings, not exchange of coordinate offsets. Passed subject to the existing affine identity/scanner contracts. |
| Valid saved prefix | The prior snapshot pins the committed run-file hash, prior recipe, original owner IDs, original coordinate request and source identity. It requires integer `0 < completed < total`, exact recorded offsets, matching family size and certified ranking. A stale/missing prefix falls back to an independent run. Passed. |
| Identical resources | Initial and current normalized settings must match the new job, and pending changes or resource-event history prevent initial sharing. Approximate, adaptive and non-accelerated combinations are rejected. Passed. |
| One original enumerator | `campaigns.py:281` searches only earlier jobs in this campaign. The reservation records the original owner request/basis; it never converts an alias offset. Reservation is saved before dispatch at line446. Passed. |
| Restart ownership | `_validate_shared_owner` at line304 rechecks original IDs/request, alias request, family/source digests, settings, resource events, forward-only progress and exact ranking. Missing or failed owners raise; no alias-basis replacement run is started. Passed for internally managed histories. |
| Immutable evidence | `_freeze_scan` at line321 deep-copies retained texts, reconstructs/re-encrypts alias witnesses, removes owner assignment-index claims and checks that run bytes did not change during replay. `snapshot` copies candidates and validation work. Later jobs do not overwrite prior snapshots. Passed. |
| UI historical selection | `app.js:166` checks `job.scan_snapshot` before fetching the live owner run. Inspect, replay and comparison therefore use the historical candidate list, own recipe and saved completion flags. The campaign table labels the saved offset and prefix reuse explicitly. Passed by source inspection; no browser execution in this review. |
| Completion scope | `campaign_sharing.snapshot` makes whole-family/top-k claims only when the owner is completed, certified and exactly at total. Partial snapshots remain `top_k_exact=false`. Queue completion and an individual job's complete enumeration are distinct. Passed. |

The correctness chain is: identical plaintext set and scoring function → same
ranking over any actually evaluated text subset → certified contiguous owner
prefix → alias membership and literal recipe replay → frozen prefix result.
Only exhaustion of the original full sequence promotes that result to exact
whole-family top-k. No claim that the alias's first coordinates would enumerate
the same prefix is needed or made.

## Finding resolved during review

The initial `app_jobs.validate_start` used lower bound0 for all capped request
fields. It therefore accepted `residual_cache_max_assignments=0` and
`residual_cache_max_operations=0`, which the optimizer later rejected. Root
changed these two minima to1 (`app_jobs.py:95`) and added boundary cases in
`tests/test_app_P.py`. The corrected code was reread; capacity0 for
`residual_cache_max_entries` remains valid. No duplicate edit was made here.

## Evidence coverage and limitations

The reviewed `tests/test_campaign_P.py` covers initial option rejection,
two-job completion, three-job continuation from the latest prefix, immutable
earlier snapshots, the Beaufort non-equivalence control, masked exact scores,
default-off independent runs, different model/mask identities, stale committed
bytes, changed resources/request/source, pause/restart, failed/missing owner and
reservation-save failure. These are test-source observations, not an assertion
that this reviewer reran them.

The canonical script declares six small CPU cases and independently enumerates
and scores 26-letter families, with literal alias replay and one actual worker
dispatch case. It preserves the initial incorrect Beaufort-equivalence
expectation as a negative control. The comparison of52 independent complete
recipe evaluations with26 shared evaluations is separate from the default-off
two partial jobs. Identity/replay cost is reported separately; reused-prefix
counts are availability counts, not a guarantee of saved wall time or another
basis's prefix coverage.

Hashes detect changed bytes; they do not authenticate maliciously fabricated
run/campaign histories. This review does not establish safety of arbitrary
hand-edited runtime JSON, independently re-prove every existing scanner primitive,
or claim K4/K5 authentication. Source changes after the hashes below require a
delta review. Canonical execution remains the coordinating task's responsibility.

## Reviewed bytes

| File | SHA256 |
| --- | --- |
| `kryptos/campaign_sharing.py` | `1c8111b3a0a203dce40831db31d29df2418ed1cb087c18dd806f974454f249c6` |
| `kryptos/campaigns.py` | `7a3f4d329acfd0dc07f9c81393f79616a7ba941ec6342551e020aec5d796742d` |
| `kryptos/app_jobs.py` | `ff94d3d9fb742a89dc2f0fa6af86e7141c9cd6cdc2d89228f261a0cfacf4ce16` |
| `kryptos/static/app.js` | `a63571d1a64122d78bbd382ecadbed148d02929f03839e9041bf3b51014d567e` |
| `kryptos/family_identity.py` | `6e2136a2d70d917e71f7e3740d92b629a44bbf7ca7ef162919aaf5583654f7b1` |
| `tests/test_campaign_P.py` | `df4436e62e30c8a32ef2831ea71cf5564fea494e6dacab85f3511ec7c18ad3dc` |
| `tests/test_app_P.py` | `f0175585be48005422a31bea7d955d14b927473da8f0883966a89eeb29eb26c7` |
| `research/campaign_P_protocol.json` | `22d94c56bc0ebc764372875e0ecf9646db3af9f91931cfd7f42204fa1b878691` |
| `research/campaign_P.py` | `546edea34734d0c2e7dc5f861c8e1e4668584b4a8a4aad1c98d9af5e8ae80206` |
