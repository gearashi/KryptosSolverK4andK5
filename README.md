# Kryptos K4 and K5 research workbench

A local browser application for bounded CPU and optional NVIDIA GPU experiments on Kryptos. It includes exact cipher constraints, explicit sculpture-grid hypotheses, language comparisons, candidate explanations, replay checks and resumable family scans and joint route/key searches.

**This project has not deciphered K4 or K5.** Public K4 ciphertext and 24 known plaintext letters are included. There is no authenticated public K5 ciphertext in the reviewed sources; K5 experiments require your own explicit input.

## Start the application

CPU use requires Python 3.10 or newer and only the standard library. On Windows, double-click `Setup.cmd` once, then `OpenDashboard.cmd`, or run:

```powershell
.\Setup.cmd
.\OpenDashboard.cmd
```

The dashboard prefers `http://127.0.0.1:8767/` and selects a free local port if that port is occupied. It prints the actual address, waits for an HTTP readiness check, then opens your browser. It remains idle until **Start experiment**. Reopening the launcher reuses the same running workspace. Setup creates a project `.venv` if needed and preserves an existing one. It downloads no packages for CPU use.

Optional NVIDIA GPU setup is explicit:

```powershell
.\Setup.cmd -Gpu
.\OpenDashboard.cmd
```

The tested CUDA environment uses an RTX 2060 and 64-bit Python 3.12.2. Exact package versions are pinned in [requirements-gpu.txt](requirements-gpu.txt); a compatible NVIDIA driver is required. Setup does not install drivers.

On Linux or macOS, use `sh Setup.sh` and `sh OpenDashboard.sh` for CPU operation. Optional CUDA setup is `sh Setup.sh --gpu` on a supported NVIDIA platform. The hardware validation was performed on Windows. Direct launch from any compatible environment is `python -B -m kryptos.app`.

See [the local application guide](docs/LOCAL_APP.md) for interpreter selection, ports, setup options, presets and exports.

## Controls and interpretation

- CPU scans use exact integer scoring. CUDA defaults to certified ranking: rigorous score intervals retain every possible top candidate for exact CPU comparison and encryption replay. A separate approximate mode is explicitly labeled.
- Persistent workers reuse prepared families and GPU buffers across pages. The exact optimizer accepts verified CPU/GPU scan seeds, guided feasible-family seeds, joint factor bounds and exact component/separator elimination. Unknown column routes and keys can also be ranked jointly by a frozen language model.
- **Campaigns** expand an explicit recipe matrix or bounded S/T grammar into durable jobs. Completed exact rankings can be reused across campaigns when the plaintext family, model and mask agree; each recipe gets its own reconstructed keys and replay.
- **Validation** reruns selection with withheld clue values removed, compares positive and shuffled controls, and refits recipes after removing a stage or route. The harder preset uses K4's separated clue positions with multilingual texts and competing layered/grid methods. These are bounded diagnostics, not solution probabilities.
- **Inspect & trace** independently replays imported JSON and follows individual letters through substitutions, gathers, and coordinate shifts. Imported verification claims and file paths are treated as data.
- **Pause** commits the current scan wave, exact optimizer frontier or ranked joint route/key frontier. **Stop** discards in-flight work and preserves earlier commits. Resume checks saved-data integrity and source/model identity. Exact slices can grow within the declared limit when rebuilding a large frontier consumes a slice.
- The run time budget is checked between waves; every worker has a separate 60-second outer deadline. CPU family scans support up to 32 workers (limited to detected logical processors in the selector); CUDA uses one worker/context. Worker count, idle intervals and adaptive page duration can change at committed boundaries, with a saved event history.
- Known clue letters and every n-gram touching them are masked from ordinary language scoring. A reporting-only sensitivity diagnostic can also mask letters fixed indirectly by the model.
- Re-encryption, crib consistency and a high language score do not authenticate a solution. Results describe their assumptions and actual bounded coverage. Nothing is submitted to an external service.

The server binds to loopback. Closing a browser tab does not stop it; use Ctrl+C in the launcher terminal to close the service. Saved state is local to `runtime/`. This is a local workbench, not a BOINC server.

## Research tools

The CLI remains available alongside the dashboard:

```text
python -m kryptos doctor
python -m kryptos layout
python -m kryptos layers --request examples/layers-small.json
python -m kryptos joint --request examples/joint-ragged.json
python -m kryptos joint-ranked --request examples/joint-ranked.json
python -m kryptos scheduled --request examples/scheduled-shared.json
python -m kryptos mixed --request examples/mixed-shared.json
python -m kryptos optimize-plus --request examples/optimize-lazy.json
python -m kryptos batch --request examples/batch-lazy.json
python -m kryptos validate-holdout --request examples/validate-holdout.json
python -m kryptos validate-controls --request examples/validate-controls.json
python -m kryptos validate-controls --request examples/validate-k4-shaped.json
python -m kryptos validate-ablations --request examples/validate-ablations.json
```

See [checkpoint K commands](docs/CLI_CHECKPOINT_K.md), [earlier command examples](docs/CLI_EXAMPLES.md), [bounded results and limits](research/IMPROVEMENTS_K.md), and [the research history](research/STATUS.md). These document joint column/key recovery, shared keys and offsets, multiple known alphabets, coordinate-driven schedules, fractionation, arbitrary substitution feasibility, semantic hypotheses and exact constraint witnesses. The normalized sculpture dataset represents ordinal textual coordinates, not measured three-dimensional geometry.

Historical controls include independently published PK fixtures and 175,760 crib-compatible language completions. Their supplied methods, artificial clues, model choices and ambiguity limits are recorded in [PK benchmark notes](research/pk_benchmark_notes.md) and [checkpoint K](research/IMPROVEMENTS_K.md). They test the tools within declared assumptions; they do not establish Kryptos's actual method.

## Validation and packaged data

[Download v0.6.0](https://github.com/gearashi/KryptosSolverK4andK5/releases/tag/v0.6.0). Published through gearashi after all four Windows/Linux package checks; public download hashes verified.

Version **0.6.0** implements and evaluates [all 90 numbered proposals](research/IMPROVEMENTS_Q.md).89 remain available as optional methods, conditional models or supporting primitives. The restarted portfolio is disabled after its negative comparison. This is not a claim of89 independent search-efficiency wins: several methods tie previous strategies or exchange fewer decisions for more preparation and replay.

The new **Research methods** panel exposes bounded relation/SMT, factor, geometry/language/codebook and symbolic-recipe experiments, with original requests, technique traces and explicit completeness. The ordinary optimizer and joint route/key searches gain optional propagation, bounds and exact decomposition methods. [The method guide](docs/RESEARCH_METHODS.md) explains entry points and assumptions.

Windows launch now checks actual HTTP readiness, handles occupied/reserved ports, reuses the matching running workspace and survives browser-opening failure. CUDA discovery runs in a bounded owned child, so an unavailable GPU cannot indefinitely delay the CPU dashboard. Setup and launch wrappers are tested from paths containing spaces and another working directory. Optional finite SMT support is installed with `Setup.cmd -Sat` (or `sh Setup.sh --sat`).

Canonical audits include 561 exact factor comparisons, independent finite relation/affine checks, geometry subgraph enumeration and 80 recipe-bank comparisons against 36,414 literal key vectors. Failed, capped and unfavorable comparisons remain recorded. [Release validation](research/release-validation.json) states the final clean-package test counts and publication status. Historical [phase P](research/IMPROVEMENTS_P.md) and [phase O](research/IMPROVEMENTS_O.md) evidence remains intact.

Actual hardware checks on the i7-4790 / RTX2060 compare 196,608 timed candidate evaluations across all 8 CPU threads and CUDA configurations, with identical certified top 20 results. The best tested family-scan settings are **CUDA, one worker, 8,192 candidates/page, certified ranking**, or **CPU, eight workers, 2,048/page**. See [hardware settings and measured limits](docs/HARDWARE_SETTINGS.md). Hardware throughput is separate from reducing search steps.

The clean package passed **539 of 540 Python tests**, with one optional raw-source audit skipped, plus **117 browser checks** and **6 Node checks**. Actual CUDA tests and the full GPU/SMT setup-and-launch check passed with `CUDA_PATH` unset.

See [search strategies](docs/SEARCH_STRATEGIES.md) and [workspace/release operations](docs/WORKSPACE_AND_RELEASE.md) for options, saved evidence, scope and limits. Release publication checks the exact tag, complete Windows/Linux CI matrix, asset hashes and gearashi attribution.

Run the CPU suite with:

```text
python -B -m unittest discover -s tests -v
```

GPU tests require `KRYPTOS_TEST_CUDA=1` in the configured GPU environment. An optional raw-source audit skips when its excluded snapshots are absent; packaged dataset integrity tests still run.

Frozen language-count models, normalized fixtures and the authored code snapshots needed by the release audits are included. Downloaded full books, third-party page/code caches, runtime state and bulky historical outputs remain local. Some historical research scripts therefore require separately obtaining the cited inputs. See [source distribution](docs/SOURCE_DISTRIBUTION.md) and [third-party notices](THIRD_PARTY_NOTICES.md). Project-authored software and documentation are licensed under GPL-3.0-only; third-party material retains its own terms.

## License

Copyright (C) 2026 gearashi.

Project-authored software and documentation are licensed under the GNU General Public License, version 3 only (SPDX: `GPL-3.0-only`). See [LICENSE](LICENSE) for the complete terms.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The license does not grant rights to the Kryptos sculpture, third-party reference material, trademarks or separately licensed dependencies. See [third-party notices](THIRD_PARTY_NOTICES.md).
