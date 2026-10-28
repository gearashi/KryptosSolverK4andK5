# Phase Q research methods browser verification

On 2026-10-28, the current checkout passed all **29 assertions** in
`research/browser_methods_Q.cjs`. This was an actual headless Chrome run using
the installed Playwright runtime and an isolated CPU-only server created by
`scripts.verify_package.browser_check`. It was not a Git-archive/package run or
additional GPU evidence.

Evidence is preserved in `research/runs/release-Q-browser-001`. The helper owned
the server and browser process trees. The server chose loopback port 62097;
an independent connection check confirmed that port closed after cleanup. The
user's port 8767 was not used. Opening the test page started no computation.

## Functional checks

The driver started and completed an actual managed job through the Research
methods tab for each of the four engines:

- `constraint-lab`: the affine cipher adapter example.
- `factor-lab`: the conditional factor-query example.
- `model-lab`: the finite codebook example.
- `grammar-lab`: the symbolic-prefix recipe example.

Every saved job preserved its declared request and returned top-level
`complete: true`. The factor adapter derives this from its individual reports;
its inner object need not contain a separate aggregate `complete` field. Each
result kept `authenticated_solution: false`, with detailed model output under
`analysis` rather than pretending generic assignments were Kryptos plaintexts.

The driver also checked all 90 ledger rows, CPU worker selectors matching the
detected hardware cap, strong/junction/overlap optimizer controls, relational
joint propagation, tab switching, no JavaScript errors and no active work at
the end. No driver assertion needed correction and no browser run failed.

Before running, the four chosen examples were compared to `validate_start`'s
normalization; all remained semantically identical. The browser then verified
the exact serialized request preservation against the actual served catalog.

## Visual inspection

The reviewer actually viewed both resulting screenshots:

| Screenshot | Size | SHA-256 |
|---|---|---|
| `methods-Q-browser/methods-desktop.png` | 1440 by 4521 | `eb5a3819540061e73e760f5c3c8ae0aacb7b81e7ca8d7d89bdaebca3d0ea4502` |
| `methods-Q-browser/methods-mobile.png` | 390 by 5192 | `6ad88021196379a74f4252eab0c894c48a486d38849ed724f4b631335c4c3dd6` |

The form, result pane and ledger fit both widths. JSON remains inside bounded
panes, and the mobile document has no horizontal overflow. The long ledger
accounts for most of the full-page height.

One release-content issue was reported to the root task before changing any
production file: every ledger entry still read `proposed`, because the current
catalog loaded the frozen phase-Q plan. The final release must show the reviewed
outcomes or clearly identify that display as the historical proposed plan.
This browser record intentionally preserves the pre-update screen state.

## Provenance

The browser driver SHA-256 was
`d1a88030bf94a1069b26082d0b155f320dea2f5761a1b1b761beb2a5b7dfb78a`.
The report SHA-256 was
`fb9beec8bf2a879491ef6965b1a69644d18f4b3bc85c077aa605f4a864bde873`.
`review-observations.json` records each saved engine result, screenshot hash,
helper hash and cleanup observation. The browser reported app version 0.6.0.

This review establishes these local UI workflows and visual observations. It
does not establish the complete release package, every solver input, search
efficiency, or authentication of any K4/K5 candidate.
