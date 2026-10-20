# Repository republication â€” 2026-10-20

This records the earlier version0.2.0 restoration. The subsequent [version0.3.0 release](../research/IMPROVEMENTS_N.md) resumes the draft described below; the original publication history and license remain its base.

The recreated repository retains its new initial commit and GPL version 3 license. The solver is restored from the last published version 0.2.0 source package, with the Windows CUDA component-path fix. The publication commit is authored and committed by gearashi. Only file contents were copied; no earlier repository commits, branches or tags were imported.

The CUDA fix discovers the separate runtime and NVRTC wheel directories, verifies the libraries actually loaded, and handles the specific missing-Toolkit-root warning only after that layout is verified. Compilation and driver failures remain visible. Backend readiness still requires a successful compiled kernel. See [GPU setup and diagnostics](ACCELERATED_SCANS.md).

The paused version 0.3.0 improvement draft remains local and is not part of this restored release. Existing research records, source snapshots, attribution maps and their observed commit hashes remain historical evidence. Those hashes are data, not ancestors of this repository; old remote-publication statements describe the earlier repository. Source hashes continue to identify their original archived bytes. The CUDA fix changes the live source identity, so an existing saved run may require a new run instead of resuming against different code.

Validation on Windows with Python 3.12.2 and an RTX 2060: the clean publication package ran 317 tests in 33.671 seconds; 316 passed and one optional raw-source audit skipped because its third-party source pages are excluded. Actual CUDA tests passed, including CPU/GPU ranking parity. `OpenDashboard.cmd` started with empty stderr, a verified compiled GPU kernel, and no active search. `CUDA_PATH` was absent during these checks. Historical browser and benchmark records remain scoped to the versions they originally tested.
