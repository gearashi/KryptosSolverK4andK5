# Independent P7/P8 review

Reviewed read-only on 2026-10-25. **No concrete correctness defect found in the
reviewed scope.** No production file was changed. This is a development review
with a small independent check, not the canonical manifested protocol run.

## Scope and reasoning

- `ResidualComponentCache` freezes factor/model data. Cache keys identify the
  original factor IDs, free variables/domains, and all fixed boundary values.
  No isomorphism, external cache, or cross-invocation equivalence is assumed.
  Only fully enumerated component optima are stored. Cached/new witnesses are
  reevaluated against original frozen factors; the integrated answer is checked
  again against the whole original objective. Witness verification alone would
  not certify an externally supplied maximum; the documented internal-cache
  trust boundary is necessary and correctly stated.
- Remaining components share no free variable. For positive component maxima,
  their product is the exact residual maximum; original-coordinate lexical
  minima combine correctly. A zero constant or exact zero component maximum
  annihilates every completion. Returning the entire residual lexical minimum
  is correct, including nonoptimal assignments in other components. Zero is
  never interpreted as infeasibility.
- Entry/assignment/operation/time bounds can leave a component unresolved, but
  do not exclude it. A global elapsed-time cutoff requeues the parent. Fully
  solved entries from earlier components remain valid even when a later
  component exceeds a cap. Constructor copying and individual arithmetic
  operations are cooperative work, not hard real-time interruptions.
- The cheap gate begins with powered universal factor maxima and substitutes
  admissible cached local bounds or exact fixed values. Its integer quotient
  removes one untouched global factor at a time, so divisibility is exact;
  zero universal bounds need no division. Equality rejection requires that the
  branch lexical minimum cannot improve the incumbent.
- The cheap gate never writes frontier bounds. Initial, retained, and restored
  nodes use full deterministic grouped/mini-bucket bounds. New options and
  their limits are in checkpoint identity; component caches are not restored.
  CLI and batch option whitelists include all new fields. Defaults remain off.
- The frozen protocol and tests distinguish helper reuse from improvement over
  the default optimizer. They retain no-benefit and capped controls, and report
  factor work, cache planning/snapshot/witness costs, and cheap preparation
  separately. The named counters are not complete CPU-instruction counts.

## Independent finite check actually executed

One CPU process, Python3.12, 0.194 seconds measured for the check body. Sixteen
deterministic authored problems used binary variables0,1,2 with factors:

```
F02(i) = (code + 3*i*i + i) mod7, i=0..3, power=1+(code mod3)
F1     = [code mod4, (code+2) mod5], power=2
Fempty = 0 when code mod7=0, otherwise2
code   = 0..15
```

A separate literal mixed-radix table lookup/product oracle was used; it did not
call solver factor evaluation or bound helpers. Exhaustively checked:

- **432** residual optima: all27 partial assignments per problem, each variable
  free or fixed0/1. Every exact score and original-coordinate lexical witness
  matched enumeration.
- **3,456** cheap-gate decisions: all27 partials against each of8 complete
  incumbents, after filling the local-bound cache. Every rejection was unable
  to improve the incumbent score or lexical tie.
- **64** complete searches: defaults, components, cheap gate, and combined
  components/cheap with operation cap1. All matched the oracle and proved ties.

The eight file hashes below were checked before and after execution and were
unchanged. No whole app, GPU, K4/K5, reserved language fixture, or canonical
factor protocol was run in this review. The existing13 P tests were read; their
reported execution belongs to the implementation agent, not this independent
check. Those tests additionally cover unused variables, nonstandard alphabet
ngrams, corrupted witnesses, boundary changes, timeout requeue, and resume.

## Reviewed bytes (SHA256)

| File | SHA256 |
| --- | --- |
| kryptos/factor_decomposition.py | 8add3c1830d719bc2ff2fd81a7fca9493bb25f2f74ab196f21cb0fae8797396e |
| kryptos/search_runtime.py | 90686a2e47f59528fd6567d2ff6ba483a4b92c7c7f2376b3113574607a98a25a |
| kryptos/next_cli.py | 7ac9e87c97a6b85c6dc6e48cfa39e703e55711647a8a554601ee5f5a076b1369 |
| kryptos/parallel_search.py | 976ee35415399acc20982fb38aa307295fc5e8d3306e9d888e3db276c3a623cb |
| tests/test_factor_P.py | 26fe4478d7f0665ac95f9a8227a8deca180daa0c9e2d262fa446ceb5ae182ebe |
| research/factor_P.py | 938c96747162656cf997a00a4333c352a1872067db27fd34ac5142d56e234881 |
| research/factor_P_protocol.json | 492e7e01806e369ef358e06262036158979a7ee17a00ecf3881de3e766e212f5 |
| research/factor_P_notes.md | b512107bfcc42ba56429b2c377361506b845ecc33c4d0f4534675f8a97c5dede |

Outcome: implementation and finite assertion independently checked in this
stated range, with the cache/admissibility argument reviewed. This does not
establish representative Kryptos efficiency or a universal speedup. The next
check is the already frozen canonical protocol and integration suite; this
review does not expand its fixtures or tune its settings.
