# Tested settings for this computer

The October 28, 2026 comparison used an Intel Core i7-4790 (4 cores, 8 logical processors), about 16 GB RAM, and an NVIDIA RTX 2060 with 6 GB VRAM. Python was 3.12.2; the NVIDIA driver was 621.01. These recommendations apply to this machine and the tested workload.

## Family scans

| Setting | Recommended GPU scan | CPU alternative |
|---|---:|---:|
| Backend | CUDA | CPU |
| Ranking | Certified | Exact |
| Workers | 1 | 8 |
| Candidates per page | 8,192 | 2,048 |
| Adaptive page sizing | Off for the measured configuration | Off for the measured configuration |
| Idle time | 0 ms | 0 ms |
| Retained candidates | 20 | 20 |

Use these controls with a **family scan**, then choose an explicit recipe and search budget. CUDA uses one process/context; setting eight CUDA workers is not supported. Eight CPU workers use all logical processors. Four CPU workers are a reasonable interactive alternative, measured below. Worker count changes do not reduce the number of candidate evaluations.

The fixed experiment ranked the same first 32,768 distinct plaintexts in a K4 period-28 affine family, with the same frozen English model and masked clues. It compared every retained top-20 result with the exact CPU reference and literally re-encrypted retained candidates. No CUDA fallback was allowed and `CUDA_PATH` was unset.

| Backend | Workers | Page | Timed candidates/second | Time for 32,768 |
|---|---:|---:|---:|---:|
| CPU | 1 | 2,048 | 6,335 | 5.17 s |
| CPU | 4 | 2,048 | 19,819 | 1.65 s |
| CPU | 8 | 2,048 | 24,731 | 1.32 s |
| CUDA | 1 | 512 | 1,775 | 18.46 s |
| CUDA | 1 | 2,048 | 3,297 | 9.94 s |
| CUDA | 1 | 8,192 | 34,229 | 0.96 s |

These are single bounded measurements after one 256-candidate warmup per worker, excluding setup and warmup time. The small GPU pages were slower here. Larger pages amortized overhead and required fewer exact final comparisons. Different recipes, ambiguity, models, background load and thermals can change the result. This is the best **tested** configuration, not a global optimum or a promise of continuous 100% GPU utilization.

Evidence: [hardware result](../research/runs/release-Q-hardware-002/result.json), [contract](../research/runs/release-Q-hardware-002/contract.json), [telemetry](../research/runs/release-Q-hardware-002/telemetry.json). All 196,608 timed evaluations agreed across configurations. Warmups and exact comparisons are recorded separately. The earlier period-27 fixture could not supply the requested number of distinct candidates; its failed run and repair are preserved.

## Reduce search decisions first

Use the exact optimizer or constraint methods when the hypothesis admits useful pruning. These run on the CPU; they do not become GPU jobs by changing the hardware selector. A stronger bound can save candidate evaluations while consuming more intermediate work.

- Start with the existing `auto` decomposition. The new junction/chain implementations tied it on branch decisions in the fixed comparisons, so replacing it everywhere is not justified.
- For coupled factors, try `overlap` or `cycles` bounds on a bounded sample and compare total decisions, complete evaluations and preparation work. Keep the cheaper method for that family.
- For joint unknown routes/keys, `relational` propagation and the `matching` bound are optional. Matching helps only where the declared geometry exposes qualifying column-local windows.
- Reuse verified completed-family or subtree evidence only under matching model, objective and coverage identities. Imported scores alone cannot establish an incumbent or exclusion.
- The restarted portfolio was disabled after its negative comparison. Do not select it as a performance setting.

All 90 proposal outcomes, including conditional capabilities and unsuccessful comparisons, are in [phase Q](../research/IMPROVEMENTS_Q.md). There is no single setting that can guarantee discovery of the unknown Kryptos method.

## Starting the dashboard

Run `Setup.cmd -Gpu -Sat` once to enable the pinned optional GPU and SMT dependencies, then `OpenDashboard.cmd`. For standard-library CPU use, omit both options. The launcher waits for the actual HTTP service, selects another local port if 8767 is occupied, and opens the resulting URL. It prints that URL if automatic browser opening is unavailable. `OpenDashboard.cmd -Port 0` explicitly requests an available port; `-StrictPort` requests an error instead of fallback.

The app stays idle until you start an experiment. Leave the launcher window open while using it; Ctrl+C closes the server. Reopening the launcher reuses the matching running workspace.
