# Windows batch setup and CUDA launch check

Evidence: `research/runs/release-Q-setup-001/report.json`, with separate stdout
and stderr files for setup, the dashboard launcher, and the direct GPU probe.
The reproducer is `research/check_setup_Q.py`; it requires a fresh output
directory, an existing configured virtual environment, and Windows.

## Observed result

- Actual `Setup.cmd -Gpu -Sat` exited successfully in 5.11 seconds. CPU imports
  and Z3 imports succeeded. The environment retained seven installed
  distributions; all four explicitly pinned optional package versions were
  unchanged. Pip reported six already-satisfied dependencies, including
  transitive dependencies. This checks setup reuse, not installation into an
  empty environment or a package download.
- Actual `OpenDashboard.cmd -Port 0 -NoBrowser -StateDir <fresh state>` passed
  the HTTP health check at `http://127.0.0.1:62555/` after 2.406 seconds. Its
  descriptor instance matched the health response; the service identified
  itself as `kryptos-local-dashboard`, version `0.6.0`.
- `CUDA_PATH` and `CUDA_HOME` were absent in the child environment. The CUDA
  environment reported component-wheel mode, no configured toolkit root,
  NVIDIA GeForce RTX 2060, and a successfully compiled and executed kernel.
  The dashboard reported both CUDA available and ready.
- The newly launched dashboard had no active search and no campaign. Its
  owned process tree was closed, and the assigned port was verified closed.
  Port 8767 was closed before and after this test. No pre-existing server was
  contacted for control or terminated.
- Setup, launcher, and direct-probe stderr files were empty. None of the
  preserved logs contained the previous CUDA path detection warning. The
  separate direct probe matters because a successful dashboard startup
  removes its internal temporary probe logs.
- The recorded production-source hashes were unchanged during the run.
  This check made no production code changes.

## Limits

The run used the existing 64-bit Python 3.12.2 environment with CuPy 14.2.0,
CUDA runtime wheel 12.9.79, NVRTC wheel 12.9.86, and Z3 distribution 5.3.2.0.
The CUDA test executed a bounded probe kernel; full-load search evidence is
recorded separately in the release hardware checks. Automatic browser opening
was intentionally disabled here and is covered by the browser/launcher tests.
The process-owner helper closes only descendants created by this check.

The report deliberately excludes the dashboard control token and inherited
environment values. It preserves selected package versions, source hashes,
HTTP readiness, CUDA capability details, and cleanup observations.
