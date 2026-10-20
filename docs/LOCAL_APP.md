# Local application

The browser workbench runs on your computer at `http://127.0.0.1:8767/`. Opening it leaves the solver idle. It has bounded CPU constraint jobs, CPU or NVIDIA CUDA family scans, saved runs, candidate explanations and JSON export. No answer is submitted to an outside service.

## Setup and launch

CPU use needs Python 3.10 or later and only its standard library. Setup creates `.venv` when absent and preserves an existing environment. It verifies imports and installs no network packages unless GPU setup is explicitly requested.

On Windows, double-click `Setup.cmd` once, then `OpenDashboard.cmd`, or run:

```powershell
.\Setup.cmd
.\OpenDashboard.cmd
```

For optional NVIDIA GPU dependencies:

```powershell
.\Setup.cmd -Gpu
.\OpenDashboard.cmd
```

The tested GPU environment is 64-bit Python 3.12.2, an NVIDIA RTX 2060, `cupy-cuda12x==14.2.0`, `nvidia-cuda-runtime-cu12==12.9.79` and `nvidia-cuda-nvrtc-cu12==12.9.86`. These are the pins in `requirements-gpu.txt`. A compatible NVIDIA driver is also required; setup does not install drivers. Windows setup prefers Python 3.12 when creating a new environment. `-Python C:\path\python.exe` selects another creation interpreter, without replacing an existing `.venv`.

On Linux or macOS, CPU launch is:

```sh
sh Setup.sh
sh OpenDashboard.sh
```

`sh Setup.sh --gpu` requests the optional CUDA packages. GPU use requires a platform supported by that CUDA stack and an NVIDIA device; macOS has no supported CUDA backend here. Unix launcher syntax is provided; the recorded hardware test was on Windows. To select an interpreter, use `--python /path/to/python`.

Launchers install nothing. They prefer `.venv` and otherwise use a compatible system Python. To bypass them:

```text
python -B -m kryptos.app
```

Useful options are `-Port 8768`, `-NoBrowser`, `-SkipGpuProbe` and `-StateDir path` for the PowerShell launcher, or `--port`, `--no-browser`, `--skip-gpu-probe` and `--state-dir` for the Unix launcher/Python module. Port 0 selects an available local port and prints its address. Each launcher has `-Help`/`--help`. `--skip-gpu-probe` avoids the small compiled CUDA readiness check, leaving CPU operation available.

## First experiment

1. Choose a control preset to check the workflow, or K4 to test a stated hypothesis. The public K4 letters and 24 known plaintext letters are preloaded.
2. Choose the displayed recipe, backend and finite bounds. CUDA applies to supported scans; the exact optimizer can also use a bounded CUDA scan to suggest verified initial candidates.
3. Select **Start experiment**. Inspect the recorded assumptions, progress and candidates. Use **Run details** or **Export run** to retain inputs, bounds, hashes and replay evidence.

Custom and exploratory K5 inputs require explicit ciphertext. The project has no authenticated public K5 ciphertext to preload. Changing the passage does not turn K4 clues into K5 evidence.

## Job controls and persistence

The default local state directory is `runtime/`, excluded from version control. Completed pages advance the durable scan position. Saved runs can be inspected and resumed when their request, source revision and scoring model still match.

- **Pause** finishes the current wave of family-scan pages, commits it, then pauses. It is not an immediate interruption. Exact constraint commands can be stopped/restarted; they do not expose page pause.
- **Stop** terminates current workers and discards the in-flight wave. Earlier committed pages and results remain. Resuming repeats work from the last committed position.
- The displayed run time limit is checked **between waves**. It is not a strict deadline for an already running wave. Each worker has a separate **60-second outer deadline**; reduce batch size or command bounds if a worker reaches it.
- CPU family scans can use up to four workers. CUDA uses one worker/context. More workers can increase resource use without improving useful throughput.
- Resource controls queue changes to worker count, idle interval, and adaptive page timing. Changes apply at a committed boundary and are recorded with the offset. Adaptation changes page size by at most a factor of two per wave, with hysteresis and a bounded event log; it does not promise a particular CPU utilization percentage.
- Ctrl+C in the launcher terminal shuts down the service. Closing the browser alone does not stop the server or its work. An interrupted service is recovered from saved state on restart; a changed source/model identity prevents incompatible resume.

The service binds only to loopback and checks host, origin and a local session token for control requests. It is a local research tool, not a public multi-user web service or a BOINC server.

## What the scores mean

CPU pages use exact integer products for their frozen n-gram objective, with deterministic ties. CUDA defaults to **certified ranking**: integer-only score enclosures retain every possible best candidate for exact CPU comparison, including cutoff ties. It falls back to comparing the whole page when needed. The optional approximate float shortlist is labeled separately. Every retained candidate is independently re-encrypted on CPU. See [scanning and certification details](ACCELERATED_SCANS.md).

Completion and ranking apply to the declared family, page range, bounds and model. A page reaching the family end does not prove that earlier pages were evaluated. Saved run records preserve actual committed coverage. Known plaintext positions and every n-gram touching them are excluded from ordinary ranking. A separate reporting-only sensitivity check can additionally mask letters fixed indirectly by the model; no surviving windows means unavailable, and this does not silently change ranking.

Neither K4 nor K5 has been deciphered by this project. Crib fits, fluent text, exact re-encryption and high scores are insufficient to authenticate a solution. The recorded historical controls and model exclusions are described in [checkpoint K](../research/IMPROVEMENTS_K.md); they do not establish the sculpture's actual method.

## Campaigns, validation and imported results

**Campaigns** takes a base request and up to six explicit axes, expands at most128 jobs, and previews the normalized requests before starting. Supported axes include stage period, key length, offset, cipher, alphabet and permutation, plus top-level width/order/period/alphabet/cipher/model path. Each job keeps its own budget and outcome; an exhausted budget is inconclusive. Pause/resume and server restart preserve completed jobs and the committed pages of the current scan. A reserved child run ID is saved before dispatch, avoiding an orphaned completed run after a crash.

Accelerated campaigns fingerprint the exact affine plaintext set over F2 and F13. They reuse a previous **completed exact** ranking only when alphabet, plaintext set, frozen scoring model and excluded positions agree. Each equivalent recipe reconstructs its own keys and is literally replayed. Different encryption methods can produce the same plaintext family; the campaign retains the separate recipes and does not declare one method correct. Raw scores across different models or masks are not pooled.

**Validation** offers reduced-clue recovery and full competing-model positive/null controls. Held-out clue values are excluded from fitting, while every supplied clue position is masked from scoring. Selection is rerun before held letters are assessed. Public K4 clues make this a retrospective check, not a blind prediction. The fast control preset uses two newly authored97-letter messages, paired crib-preserving shuffles, two competing periods, and an artificial contiguous24-letter mask. Its result does not silently transfer to the actual K4 mask. Models, budgets, shuffle seed, coverage and censoring are recorded. See [validation protocols](VALIDATION_PROTOCOLS.md).

**Inspect & trace** accepts a run or candidate JSON export of at most1.5MiB. It recomputes encryption and clue consistency using a separate replay implementation, then follows a selected original letter through every stage. Arrow keys navigate the trace. Imported path strings, model hashes and saved verification claims are inert metadata; importing never starts a search or opens an imported path. A correct replay establishes consistency of that recipe, not authenticity of the source or an answer.

For exact optimization controls, choose **Control · exact optimization with optional scan seed**. Enable a bounded CPU/CUDA seed page and/or grouped factor bounds. Seeds become feasible incumbents only after independent coordinate, objective and literal replay checks; the exact solver retains its own proof obligations. Grouping combines overlapping n-gram factors within an explicit enumeration cap, falling back to the original admissible bound when the group is too large.

## Files and reproduction

The package retains normalized sculpture data and frozen language-count models. Ordinary geometry checks the pinned normalized dataset and does not require downloaded HTML. The explicit source-audit loader still requires the original source snapshots. The optional raw books, third-party page/code caches, runtime state and bulky historical results stay local; research scripts that need them explain their additional inputs. See [source distribution](SOURCE_DISTRIBUTION.md) and [third-party notices](../THIRD_PARTY_NOTICES.md).

The research CLI remains available; use [checkpoint K commands](CLI_CHECKPOINT_K.md) and [earlier examples](CLI_EXAMPLES.md). Run the CPU test suite from the repository root with:

```text
python -B -m unittest discover -s tests -v
```

GPU tests are opt-in with `KRYPTOS_TEST_CUDA=1` in the configured GPU environment. An optional raw-source audit skips when its excluded snapshots are absent; the packaged-data integrity checks still run. Test output, source versions and actual device evidence are more useful than treating a historical test count as a guarantee for another machine.
