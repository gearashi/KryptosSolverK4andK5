# Packaged phase P browser review

Read-only review on 2026-10-26 of `research/runs/release-P-001`. No browser,
server, search, or test was launched again; no production or test file changed.
The root-owned verification helper is responsible for process cleanup.

**No new visual or result-label defect found in the inspected screenshots.**

## Reports inspected

| Evidence | Reported outcome | SHA256 |
| --- | --- | --- |
| browser/browser-report.json | 43 checks passed; no JavaScript errors | 39cf3ac7ed3a59989305cfd26faddb1d283352610fd7ff51637a21efdd08b339 |
| workspace-browser/report.json | 22 checks passed; no JavaScript errors | abf649709812d323e0c22f3fc65e2d9d511fdc79c23ed658dd0dde198e76a5b4 |
| search-P-browser/report.json | 23 checks passed; no JavaScript errors | 4d5fe1a25f171e02aff93080b2b82b5d53d324af8b7554a8d5d0d3da66838c02 |
| fresh-checkout-validation.json | 448 Python tests: 447 passed, one expected raw-source skip; actual CUDA enabled; copied tested files unchanged | 472ca06492ed7cf66ab76cd738b63cd677504f4d90460ec012205eb985628f88 |
| browser-node-tests.txt | Six runner checks passed | f469f03e5840d4057f3bdb9d6ec2283dcb9a21281476671aabc78437454d12fd |

Thus the three browser reports contain **88 passing assertions**, with their
separate scopes retained. The Python log ends `OK (skipped=1)`; its SHA256 is
`bfa61dca847eac849f03198df5bda9a6d1b60b0742e80380092224dd18c1cad3`.

The core suite required actual CUDA and reported an NVIDIA GeForce RTX2060,
verified compiled kernel, and matching CPU/certified-CUDA rankings for the
same128-candidate page. The workspace and P suites were bounded CPU checks;
their success is not additional GPU evidence. All three report no remaining
active test computation. These are checks of the curated fresh package and
local hardware, not a claim about a public release or every hardware platform.

## Screenshots actually viewed

| Screenshot under release-P-001 | SHA256 |
| --- | --- |
| search-P-browser/desktop-search.png | b226609b569cfde6b09f3070490c27926eaabfb2517136e03c94c3af6f098e1b |
| search-P-browser/mobile-campaign.png | 16e40cd0f65f5ca82281a5a142583cadffe57f0393c81b7a681a49a8a3fc3618 |
| browser/desktop-cuda-candidate.png | dea28dd7e29645b93023a022322452e21393e6b8508e5f811e7f0b4a01de2d67 |
| browser/mobile-workbench.png | 41ed5cb7aca7ab1bcc5d272a520cd664da8d828e8bd4d894835d717505ab9f4a |

The P desktop/mobile captures show the corrected **completed-family aliases**
headline. The three saved rows retain partial/partial/complete status at owner
offsets10,20,26, with10,10,6 newly evaluated candidates. Earlier results remain
historical rather than inheriting the completed owner's status. Mobile panels
fit the viewport; wide tables use their own horizontal scrolling containers.
The core captures show a CUDA candidate with its score/model/replay evidence
and a responsive mobile workbench, with saved-result context separate from the
editable next experiment. Only the four images above were visually inspected.

The core report's served `app.js` hash is
`291e36046d138e35bcc0990989e508bc04c745718be4f9408d9d6fab9f896237`, matching the
frozen wording fix. The P driver hash is
`e0c27b9aae9aec081a6e282d41200332bf362e45310a6d8b3234ae064a562b51`, matching the
version with the new headline assertion.

## Historical development failures and limits

`runtime/P-browser-development001` stopped after four checks because the driver
tried to fill a collapsed crib editor. `development002` stopped after17 checks
because its assertion read the workbench instead of the historical Inspect
dialog. These were preserved driver bugs, fixed before the successful003 and
004 development checks and this packaged run; they are not omitted solver
failures. This review verifies recorded UI evidence and its labels, not the
general mathematical correctness, search efficiency, or authenticity of any
K4/K5 candidate.
