# Bounded phase O engine/integration review

Reviewed 2026-10-25. This was an independent read-only inspection of the parent's
accelerator and app persistence changes, plus an integration/self-review of the
joint engine authored by this reviewer. It is not a whole-repository security
audit or an independent reimplementation of the engine.

## Pinned source bytes

| File | SHA256 |
| --- | --- |
| `kryptos/accelerated.py` | `027f4cfea0e5d94cae9947dc3c668c893422ea9900e6c5c71cbdc15a138d4987` |
| `kryptos/app_jobs.py` | `1dce6df05848d1002f77adb03c71e617ca75a5c99b226609dcdba7e0bf4eacfe` |
| `kryptos/joint_ranked.py` | `79877e3b4bf4eafe6b979e39f0c1ecd05e6ce92808703374f25368a10cafc6a7` |
| `tests/test_search_O.py` | `3c30c0065ef2a4c6f42d0f9301ba4312b2c41947d59c050aa68252310f7fb7fd` |
| `tests/test_joint_app_resume.py` | `c9926481a6e3dd9e12feac30950d8e85ab0fd852285de679e12d4b75de459331` |
| `research/search_O.py` | `5d7e80ff6f2af9f787b50d65c3ea4702a73333be25ce5e22a428b96afccdae07` |

## Findings and checks

No unresolved ranking or checkpoint-commit defect was found in the inspected
scope. CPU odometer updates take the union of all windows touched during a carry;
net-cancelling changes may cause extra work but cannot omit an affected factor.
Replacing factors through the positive product and zero count preserves exact
products, including zero-valued factors. Candidate coverage is unchanged, and
the report correctly distinguishes saved factor evaluations from fewer search
candidates.

CUDA filtering retains every upper interval at least the kth lower endpoint.
This is admissible for integer outward bounds and preserves score equality for
lexical ties. The report retains negative transfer savings on tiny pages rather
than clamping them to zero. Its transfer accounting explicitly covers filter
payload, excluding candidate letters and internal CuPy control traffic.

The earlier calibration counter issue is resolved: an unsuccessful CUDA sample
reports an unknown exact combined candidate count plus a finite upper bound,
while preserving the known CPU sample count and the requested CUDA count. A
cache hit reports zero new calibration evaluations. Cached timing and sample
metadata describe the earlier policy decision, not a new measurement or proof
that the chosen backend is globally faster.

For managed joint continuation, source/model identities and the private saved
checkpoint hash are checked before launch and again before commit. The worker
writes a fresh immutable checkpoint; the app saves a copied run record with its
digest before updating the live record. Failed durable save leaves the old
pointer and progress intact. Stop discards an uncommitted slice; Pause permits
the current slice to commit. Per-activation caps subtract cumulative counters;
only explicit user Resume grants another activation. A pause arriving as a
budget limit or final completion settles may report Limited or Completed, with
the committed frontier retained consistently.

Joint score pruning applies only to unfinished route/key branches and uses a
strict upper-bound inequality. Completed keys are scored and counted normally.
An exhausted pruned frontier certifies top-k, while exact full assignment counts
remain withheld. An interrupted task is restored; repeated work is not mistaken
for newly advanced proof coverage.

One additional accounting gap was found and corrected with parent authorization:
loading a checkpoint independently re-scores retained candidates. Those costs
now appear separately as cumulative and per-invocation
`checkpoint_candidate_verifications` and
`checkpoint_score_window_evaluations`. They do not advance the unique search
assignment counter. The fixed 32-slice control has 156 completed search
assignments, 93 retained-row objective verifications, and 465 verification
window evaluations: 249 complete objective computations in total. Search-state
counts alone are therefore not the entire continuation cost.

## Bounded evidence and limitations

After the accounting change, this exact focused command passed 13 tests:

```
.venv/Scripts/python.exe -B -m unittest tests.test_search_O tests.test_joint_app_resume -q
```

The fixed development runner also passed, writing
`research/manual-checks/search-O-development-002.json`; it includes 576 exact
residual-bound oracle comparisons, unfavorable controls and work counters. This
development output is secondary evidence. A canonical computation-audit
manifest must pin the final package and inputs after all agents freeze sources.

No fresh GPU run, reserved validation scoring, full test suite or broad K4 search
was performed for this review. Review of CUDA arithmetic/selection was static;
actual hardware behavior is covered only by separately reported tests. Stored
hashes detect corruption and source changes; they do not authenticate a proof
history maliciously fabricated by a local writer. Tiny deterministic caps may
repeatedly interrupt the same atomic task, which remains an explicit limitation.
Output recipe reconstruction and model-display scoring are bounded verification
work, separate from search decisions; the counters do not claim to measure all
CPU instructions or wall-clock cost.
