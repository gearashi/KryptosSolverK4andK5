# Independent focused review of phase Q factor search

Reviewer: constraints_q, separate from the factor implementation author.
Date: 2026-10-28. This is a focused source review and finite computation check,
not a review of every phase Q capability.

**Primary verdict: computationally verified only in a stated range.**

## Target and assumptions

The reviewed claim is that nonnegative exact integer product factors can be
bounded by the overlap-forest, cycle-join, rational reparameterization, modular
projection and column-matching methods, and that guidance changes search order
without silently omitting coordinate assignments. Exact conditional optima must
also respect any supplied partial assignment. Resource-limited calculations
must not issue an optimum certificate.

The review read `factor_bounds.py`, `factor_joint_bound.py`, the relevant parts
of `factor_advanced.py`, and `search_guidance_q.py`. It reconstructed the
following implications from the actual code:

| Obligation | Result |
|---|---|
| Forest consistency relaxes omitted factor overlaps | Passed source review: feasible global tuples induce permitted separator rows; deleting other agreements enlarges the maximization domain. |
| Joining a cycle before relaxing is exact on that cluster | Passed source review: finite Cartesian table join preserves the product before other agreements are relaxed. |
| Rational cost shifts preserve every original product | Passed source review: positive marginal factors divide one table and multiply the other; zero marginal has zero source product and the divisor-one branch retains that zero. Integer flooring is safe for an integer objective. |
| Modular projection is an upper bound | Passed source review: each projected table maximizes all rows in its residue class; a true assignment remains a permitted projected assignment. |
| Column matching handles cross-column language windows | Passed source review and 12 integrated literal oracles: each local window occurs exactly once, each physical column is matched once, crossing windows retain their prior upper bounds. No eligible window is a declared fallback. |
| Preferred n-gram relation branches preserve alternatives | Passed source review: the complementary branch excludes every emitted preferred row, and no other row is excluded. |
| Score equality preserves canonical ties | Passed source review of strict score or explicit lexical tests; zero-product handling is explicit in component and diagram code. |
| Regional feasibility of initial candidates | Failed in the original implementation; fixed as described below. |
| Broad factor-suite finite results | Out of scope for this independent review; the factor owner's canonical audit and full release suite supply separate evidence. |

## Concrete issue found and corrected

The original `factor_search` accepted an ordinary initial candidate outside its
requested partial-assignment region. This reproducer returned score 9 and
assignment `[1,1]`, with `complete=True` and `optimality_claimed=True`, although
the declared region fixes the first coordinate to zero and has optimum 1:

```python
from kryptos.search_guidance_q import factor_search
from kryptos.search_runtime import SCHEMA
problem = {"schema": SCHEMA, "domains": [2, 2], "factors": [
    {"kind": "table", "scope": [0], "values": [1, 9]}]}
factor_search(problem, assignment=[0, -1], initial_assignments=[[1, 1]])
```

This counterexample was actually executed during review. The factor author
added an explicit region check for ordinary seeds and a regression test.
Separately, shared global incumbents can intentionally lie outside a worker's
partition. Those reports now distinguish `region_exhausted` and
`incumbent_in_region`; a regional optimum is not claimed for an external
witness. The global disjoint-partition coordinator may claim an optimum only
when every partition has completed.

The reviewer inspected the corrected condition and result labels in source.
The factor author reported the new regression passed. The reviewer did not
relabel that author's regression as an independent execution.

## Finite matching evidence

`tests/test_constraint_integration_q.py` runs an independent literal route/key
enumerator on 12 cases: ST and TS, Vigenere/Beaufort/variant, and unigram/bigram
models. The integrated relational propagation plus matching bound returns the
same ranked eight plaintexts and exact integer objectives in all 12 cases.
The literal oracle iterates every labeled column permutation and every key;
it does not use the matching or constraint propagation code under review.
This test ran successfully before the final production freeze.

## Reviewed source hashes after the regional fix

| File | SHA-256 |
|---|---|
| `kryptos/factor_bounds.py` | `3ce364d04944c34859e9da60eba92daef09f86cfbeefc97a16316dcd5cda5f50` |
| `kryptos/factor_advanced.py` | `84de1bf90a1854b81c467cd464f326c23968f8c85137452785e4e61d03a092cc` |
| `kryptos/factor_joint_bound.py` | `b3b36d3b7d7ecf5584d8adc5588eed5225023e8ba06bf5562caf41beb682b243` |
| `kryptos/search_guidance_q.py` | `230af7a8020d80de3cbcafabdc8d58e2582a629a8a8ca8eb040ef83dd8e8e75e` |

Later source changes require a new review of their affected claims. The review
does not establish universal reductions in search decisions, a historical
Kryptos method, or an authenticated decipherment.
