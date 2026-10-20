# Phase N reproduction on the release source, 2026-10-20

The three existing protocols ran sequentially after the production Python and
test sources were frozen. No fixture, model, seed, scientific bound, or success
criterion was changed. These are reproductions of previously observed controls,
not a newly reserved sample. The earlier N001/N002/N003 records remain intact.

The computation-audit 4.0.0 runner and validator accepted all three manifests
with `run.status="completed"` and current input hashes verified. The project
wrappers owned the full process tree. Search and validation each had a
60-second outer cap; the CPU/CUDA comparison had a 180-second cap. All were
uncensored. The respective observed runner times were **2.281, 4.906, and
70.797 seconds**.

## Finite results

- **Search:** all eight guided comparisons had a higher best exact objective
  than their contiguous prefixes at the same number of objective evaluations.
  All 64 retained score/recipe checks agreed independently. This compares
  evaluation counts, not unique points or equal wall time.
- **Residual decomposition:** 60 cases agreed with 1,164 independently
  enumerated completions, including exact scores and lexical ties. The fixed
  chain discriminator used 1 search node with decomposition versus 29 without,
  with 606 elimination operations. Its deliberately capped attempt returned no
  false exact answer.
- **Joint ranking:** 24 geometry/order/equation/alphabet/direction cases agreed
  with all 97,344 independent order/key completions; 168 retained candidates
  passed literal recipe replay.
- **K4-shaped controls:** the unchanged 66 algebra-only dimensions reproduced.
  All six positives and six paired nulls completed the six-model bank with
  4,316 candidate visits and literal re-encryptions. All 12 generators also
  passed a separate numeric encryption implementation. Each positive ranked
  uniquely first; null generating texts ranked 3,2,2,1,2,7. Every null retained
  25 or 675 wrong alternatives. Best-null scores were 2.297–3.486 mean-log
  units below their paired positives under the frozen maximum-over-model rule.
- **Refit ablations:** all three fits completed. The baseline predicted the
  three held letters `GAT`; removing substitution contradicted training clues
  and produced no prediction; identity gather predicted `RCG`, matching 0/3.
  The absent prediction has no invented numerical match delta.

The control-bank limitation remains: every positive retained only one
inequivalent plaintext family. The extra fitting records for French-1 and
Spanish-2 were duplicate families. This tests model filtering and ranking
within an ambiguous family, not discrimination among several different
surviving families.

## CPU/CUDA and process recovery

The existing benchmark used the actual RTX 2060, Python 3.12.2, CuPy 14.2.0,
CUDA runtime wheel 12.9.79 and NVRTC wheel 12.9.86. Each row processed the same
20 pages of 256 candidates. All four rows agreed on exact retained rankings;
240 retained scores and recipes were independently replayed.

| Backend | Worker mode | End-to-end seconds | Exact CPU scores | Immutable device cache hits |
| --- | --- | ---: | ---: | ---: |
| CPU | One-shot | 13.054 | 5,120 | 0 |
| CPU | Persistent | 4.189 | 5,120 | 0 |
| CUDA | One-shot | 43.745 | 61 | 0 |
| CUDA | Persistent | 5.160 | 61 | 19 |

These are small fixed pages, in declared order, with caches not flushed.
Persistent workers reduced overhead here; CPU was faster than CUDA on this
workload. The timings do not establish a general speedup. Active cancellation,
forced worker crash, and timeout each recycled the owned worker successfully.

## Evidence and reproduction

The compact [audit summary](runs/release-N-004/audit-summary.json) records
manifest/result hashes and the principal counts. Canonical records are:

- [Search manifest](runs/release-N-004/search/manifest.json) and
  [result](runs/release-N-004/search/result.json).
- [Validation manifest](runs/release-N-004/validation/manifest.json) and
  [result](runs/release-N-004/validation/result.json).
- [CPU/CUDA manifest](runs/release-N-004/persistent/manifest.json) and
  [result](runs/release-N-004/persistent/result.json).

The three label-specific contracts are
`release-N-004-search-contract.json`,
`release-N-004-validation-contract.json`, and
`release-N-004-persistent-contract.json`.

Portable snapshots contain exactly the declared input files:

| Audit | Files | Bytes | Verified inventory |
| --- | ---: | ---: | --- |
| Search | 104 | 964,991 | [inventory](release-N-004-search-snapshot.json) |
| Validation | 63 | 758,278 | [inventory](release-N-004-validation-snapshot.json) |
| CPU/CUDA | 54 | 645,981 | [inventory](release-N-004-persistent-snapshot.json) |

They reside under `source_snapshots/release-N-004-{search,validation,persistent}/`.
Search and persistent wrappers copied their inputs before execution; every copy
was checked afterward against both manifest hashes and current bytes. Validation
copies were created only after all current inputs matched both recorded hashes,
then every copy was verified. Companion test files are provenance inputs; these
benchmarks do not claim to execute the full unit suite.

For another authorized reproduction, choose a fresh label and run these
existing commands sequentially with the project interpreter:

```text
python -B research/run_search_N_audit.py --audit-skill PATH_TO_COMPUTATION_AUDIT --label FRESH_LABEL
python -B research/run_validation_N.py --audit-skill PATH_TO_COMPUTATION_AUDIT --label FRESH_LABEL
python -B research/run_persistent_audit.py --audit-skill PATH_TO_COMPUTATION_AUDIT --label FRESH_LABEL
```

The tested finite assertions passed their independent checks. None of these
computations searches K4/K5, authenticates a decipherment, estimates a real
false-positive probability, or establishes historical/causal stage necessity.
