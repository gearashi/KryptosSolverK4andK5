Kryptos Research Workbench v0.5.0

Adds eight optional techniques: ranked constraint propagation, earlier ragged-grid rejection, constrained route/key branching, shared-key score bounds, proven route symmetry, shared unfinished family scans, exact residual-component reuse, and inexpensive rejection before stronger bounds.

On fixed controls, route symmetry reduces 4,056 candidate evaluations to 676; shared-key bounds reduce 52 to 26; residual solving/reuse reduces proof nodes from 11 to 3 but adds a factor evaluation. Some options add substantial overhead. Early ragged rejection did not reduce decisions or complete candidates, and the cheap gate reduced factor work only. All new controls default off; unfavorable results remain documented.

Validation: 448 local tests, with 447 passed and one optional raw-source audit skipped; actual RTX 2060 CUDA checks with CUDA_PATH unset; 88 browser checks and 6 Node checks. The exact tagged source also passed the complete Windows/Linux Python 3.10/3.12 CPU/package/browser CI matrix. CPU CI is separate from GPU evidence.

[Detailed outcomes and limits](https://github.com/gearashi/KryptosSolverK4andK5/blob/v0.5.0/research/IMPROVEMENTS_P.md) | [CI run](https://github.com/gearashi/KryptosSolverK4andK5/actions/runs/40347346638)

Candidate results preserve the saved techniques and replayable recipes. Shared-scan jobs retain their historical partial results even after later work finishes. No authenticated K4/K5 solution is claimed.

Download KryptosSolverK4AndK5.zip below, extract it, then use Setup.cmd and OpenDashboard.cmd on Windows. GPL-3.0-only. Published through gearashi.
