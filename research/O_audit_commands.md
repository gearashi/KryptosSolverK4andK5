# Phase O canonical audit commands

Run sequentially after the production source freeze, using the project Python.
The wrapper reads the installed computation-audit v2 runner and owns its complete
process tree. It does not install software or change the frozen scientific inputs.

```powershell
$auditSkill = 'C:\Users\there\.codex\plugins\cache\openai-curated-remote\mathbox\4.0.0\skills\computation-audit'
.venv\Scripts\python.exe -B research/run_O_audit.py --audit-skill $auditSkill --kind validation --label release-O-001
.venv\Scripts\python.exe -B research/run_O_audit.py --audit-skill $auditSkill --kind search --label release-O-001
.venv\Scripts\python.exe -B research/run_O_audit.py --audit-skill $auditSkill --kind scan --label release-O-001
```

Append `--prepare-only` to create the immutable contract and source snapshot
without running a computation. The same command without that flag can then run
only if the prepared input bytes, contract, interpreter and audit helper hashes
still match. An existing output directory is never reused. A changed source or
partial preparation requires a fresh label; preserve the old preparation.

For each kind, the output directory is `research/runs/release-O-001/<kind>`;
the distinct identities are `release-O-001-validation`, `release-O-001-search`
and `release-O-001-scan`. The source snapshot is under
`research/source_snapshots/<identity>` and the contract is
`research/<identity>-contract.json`. Snapshot `_audit/preparation.json` records
the pre-execution state; its `benchmark_started: false` is not a live run status.
After execution, use the run manifest's status.

All package Python files, each protocol's required scripts/tests/fixtures/models,
and the wrapper are pinned. This is computation-source closure, not a browser
audit: static UI assets and unrelated research caches are intentionally absent.
The runner records Git state, argv, software, actual hardware, before/after input
hashes, results and logs. The wrapper verifies the manifest against current files
and the byte snapshots, then saves `snapshot-verification.json`. It validates
failed-run manifests too; a failure remains a failure and is never overwritten.

The validation contract copies the existing frozen scientific settings unchanged,
refreshing only source inventory and actual software. Its 30-second protocol
budget may honestly censor selections; the outer process limit is 60 seconds.
Search has a 60-second outer limit. Scan has a 90-second outer limit and always
passes `--cuda`, requiring a successful real compiled-kernel hardware probe.
The wrapper allows an additional 20 seconds for runner shutdown/manifest writing;
its validator is separately limited to 30 seconds. Workspace-local temporary
and CuPy cache directories avoid Windows compilation-cache problems.

These experiments do not claim a Kryptos solution, a general speedup, or a real
authenticity probability. Reserved recovery ranks, null exceedances, censoring,
added bound work and unfavorable controls are retained without retuning.
