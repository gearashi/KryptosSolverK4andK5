# Workspace data and release gates

Version 0.4 adds supporting research workflow features. They preserve work and
make results easier to inspect; they do not reduce cipher search decisions.

## Editing and personal presets

The dashboard saves unfinished editor text after a short idle interval, including
invalid/incomplete JSON, source-specific notes and campaign/validation drafts.
Reload restores forms only. Nothing is automatically started. **Save draft now**
flushes pending edits; **Reload saved draft** intentionally replaces the current
forms with the last saved version. Revision checks reject stale-tab overwrites.

Personal presets store a validated start configuration under a chosen name.
Loading one fills the forms. Starting remains a separate action. Removing a
preset does not remove any run. At most 50 presets and 256 KiB of draft text are
accepted; editing state is bounded to 4 MiB.

## History and recovery

Saved runs support a title, up to 12 tags, search, state filtering and pages of 25
records. Archive changes visibility only: the record, candidate evidence and
campaign-cache references remain intact. Include archived records to unarchive
them. Metadata changes do not rewrite original solver results.

The Workspace panel reports malformed or unsupported run, campaign and editing
records. Such files remain on disk and are not partially registered. Editing
saves are blocked if the editing-state file itself is damaged; back it up before
repair. Diagnostics describe the preserved record and the required next action.

Backups require an idle run/campaign queue. Both managers are locked, in campaign
then run order, during the snapshot or recovery commit. A backup includes editing
state, records, owned checkpoint bytes and previous recovery evidence. Every
entry has a byte count and SHA-256; the manifest is also hashed. Limits are 32 MiB
per bundle, 16 MiB per entry and 2,000 entries. Oversized workspaces fail explicitly
instead of silently omitting files. Keep an independent filesystem copy when a
workspace exceeds these bounds. Resolved paths must stay in the owned state root,
including on systems with symbolic links or directory junctions.

**Verify backup** checks the complete input before any writes. **Create read-only
recovery** writes into a new server-generated recovery directory, preserves all
current data, assigns fresh record IDs and exposes recovered evidence in history.
Checkpoint bytes are retained as data, never registered as executable frontiers.
Imported path controls are stripped from inspectable records and never opened.
Hash consistency detects alteration; it does not authenticate the backup or its
candidate claims. Independently replay candidates before interpreting them.

Recovered drafts and presets can be inspected and deliberately loaded into forms.
This does not replace saved editing state until a later explicit save or new edit.
No recovery automatically executes or resumes computation. Unsupported records
remain preserved as opaque bytes in the recovery's original backup.

## Automated clean-package validation

`.github/workflows/verify-package.yml` validates a Git archive on Windows and
Linux with Python 3.10 and 3.12. It runs the packaged Python suite, Node runner
checks, CPU browser workflows and separate workspace/recovery browser checks.
Each browser suite uses a fresh state directory and an owned server process tree.
External commands have deadlines; failure logs and screenshots are retained.
CUDA is explicitly disabled on ordinary CI. Such runs provide no GPU evidence.

The same driver can run locally with installed dependencies:

```text
python scripts/verify_package.py --out runtime/package-check-001 --cuda off
```

Use `--cuda required` only on an actual supported GPU host. The archive is built
from `--ref HEAD` by default; uncommitted files are not part of the tested package.
No dependency installer or credential configuration is executed by this driver.
CI installs its explicitly pinned browser test tools separately.

## Verified publication

CI has read-only repository permissions and never publishes as a bot. After the
exact source is committed, tagged remotely and its entire CI matrix succeeds,
an operator authenticated as **gearashi** can inspect the gate:

```text
python scripts/publish_release.py --tag v0.4.0 --run-id VERIFIED_RUN_ID
```

The script uses an existing GitHub CLI (`--gh` can identify a compatible local
adapter), verifies the authenticated login, expected public repository, real tag
reference and successful workflow, then downloads the validated CI artifact. Its
commit and package digest must match. No token or repository secret is created.
The initial invocation does not publish. Add `--publish` only for the explicitly
authorized release. The published author must be gearashi; the script checks
the public page, tag and every downloadable asset's SHA-256 afterward. It never
commits changes or silently creates a tag. CUDA claims require separate actual
hardware evidence and are not inferred from successful CPU CI.
