# Independent finite-relation core review

Review date: 2026-10-28. Reviewer: the factor implementation agent, independently of the constraint implementation agent. This is a source review plus an independent literal oracle, not an independent mathematical proof.

**Primary verdict: computationally verified only in the stated range.** The reviewed claim is that the declared finite relations determine hard feasibility, that score pruning does not become a hard contradiction, and that optional learning, conflict minimization, backjumping and dead-state reuse preserve exact lexical top-k results.

The bounded run [review-Q-constraints-002](runs/review-Q-constraints-002/manifest.json) completed and its version-2 manifest validated against current inputs immediately after execution. It checked **400 exact comparisons**: 200 seeded models with propagation off and on, all other learning/probing/memoization/backjump/isomorphism options enabled. Each model has four binary variables, three hard relation tables, two integer sum factors, and top-k equal to four. The oracle enumerates all 16 original assignments directly, without using production feasibility or scoring. Every exported learned hard clause was also checked against every feasible original assignment.

The raw [result](runs/review-Q-constraints-002/result.json), [stdout](runs/review-Q-constraints-002/stdout.txt), [stderr](runs/review-Q-constraints-002/stderr.txt), [contract](review_Q_constraints_contract.json), and [reproducer](review_Q_constraints.py) are preserved. The earlier development result in `runs/review-Q-constraints-001/` remains separate.

Reviewed source hashes:

| Source | SHA-256 |
|---|---|
| `kryptos/constraint_lab.py` | `bc7c86e1ed469ed7b63be1c4bed35c4829f1aafd068e004d0d675e4b1e5a50a3` |
| `kryptos/constraint_reuse.py` | `ed1572ee69583f9b5d3ce03046de4c2cda4925acae11254dae9766987054e864` |
| `research/review_Q_constraints.py` | `b0d79af13db0adc4998be7248215ceb78dfdb558204fd2cbcb77dc1e0ce597c3` |

## Source obligations

| Obligation | Finding |
|---|---|
| Separate hard inconsistency and score exclusion | Passed source inspection. Score-pruned nodes return potentially feasible, preventing insertion into the hard dead-state cache. |
| Learn only justified path conflicts | Passed source inspection and finite oracle. Propagation-only minimization drops an assumption only after a fresh contradiction without learned clauses; probe-based exhaustion conservatively retains the path. |
| Resolve exhausted alternatives and backjump | Passed finite oracle. Parent resolution removes the branched variable only after all remaining values fail; previously propagated domain removals retain ancestor assumptions. |
| Imported hard/score proof guards | Passed source inspection, not covered by this run. Hard clauses undergo literal exhaustive counterexample checks; score exclusions carry objective identity and are reverified against feasible completions. |
| Residual-signature feasibility invariant | Passed source inspection and finite oracle. Fixed coordinates are substituted, fully satisfied relations removed, remaining value labels retained, and optional renamings transform both domains and complete residual relation tuples. Only infeasibility is cached under this signature. |
| Arbitrary-size correctness or all configurations | Not addressed by this finite experiment. |

No unsound exclusion was found. One robustness issue was reported: malformed mixed-type variable names or imported clause fields could raise `TypeError` before a controlled validation error. This did not produce a false exclusion; the author is handling validation separately.

Reproduction uses Python 3.12.2 and `random.Random(316128)`:

```text
.venv/Scripts/python.exe -B research/review_Q_constraints.py --output <fresh-result.json>
```

For canonical evidence, wrap that command with the installed computation-audit runner and the recorded contract and three exact input paths, choosing a fresh run directory. The complete recorded argv is in the manifest. Changed source hashes require a new run; the existing evidence must not be silently updated.
