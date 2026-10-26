# P campaign audit replay repair

The failed `research/runs/release-P-001/campaign` remains historical evidence.
Its `supplemental_three` control finished generating scheduled candidates, but
the audit's independent `replay` raised `KeyError: 'alphabet'` before checking
them. The ordinary recipe stores a shared top-level alphabet. The scheduled
`kryptos.expanded-recipe.v1` instead stores the alphabet in each substitution
stage and need not have a top-level alphabet. The saved example maps `PQRSTU`
through per-position key `MMMMMM` in the standard alphabet to `BCDEFG`.

Only `research/campaign_P.py` was repaired: the shared alphabet is optional;
each stage's alphabet takes precedence and must be a permutation of A–Z.
The existing literal modular equations and stage iteration remain independent
of production replay helpers. The authored controls still use substitutions
only. No cipher, key, case, bound, expected ranking, or production file changed.
The original `campaign_P_notes.md` and all old source snapshots are unchanged.
This repair supports per-stage alphabet declarations; the unchanged six-case
protocol does not newly test mixed-alphabet cryptanalysis.

The narrow preflight loaded every saved `run.json` below the P001 campaign
directory and replayed its retained candidates using the repaired function.
All 66 passed: 46 ordinary recipes and 20 expanded recipes. Each result was
checked against both the literal ciphertext `BCDEFG` and the stored
`reencrypted_ciphertext`. No searches or production helpers were used by that
replay check. The 17-file P001 tree was hashed before and after; both canonical
JSON path-to-file-hash maps gave aggregate SHA256
`de994fa748ebcfcb39903f395ec3d30584d3a5337873af7be87aab1a1246c622`.

Original audit-script SHA256:
`546edea34734d0c2e7dc5f861c8e1e4668584b4a8a4aad1c98d9af5e8ae80206`.
Repaired and frozen audit-script SHA256:
`2e78470adde4293248769b620568eb1c42fc731061e1e9ae617e58bead8f23b7`.
Unchanged old notes SHA256:
`12374a0e61ef8865b9dbf1baba4e570476f476e16110596b9a62a83c7b26faa8`.

The authorized canonical rerun keeps the existing six-case protocol and uses a
fresh directory, the installed computation-audit runner, a 120-second child
wall limit, and complete owned-process cleanup:

```powershell
.venv/Scripts/python.exe -B research/run_P_audit.py --kind campaign --label release-P-002 --audit-skill C:/Users/there/.codex/plugins/cache/openai-curated-remote/mathbox/4.0.0/skills/computation-audit
```

The finite assertion concerns this authored CPU family: committed coordinate
pages, historical incomplete snapshots, recipe replay, exact masked scores,
and complete top-20 agreement with independent 26-key enumeration. It is not
a Kryptos solution, universal work reduction, or completeness claim for a
partial ranking. Canonical outcome and manifest inspection will be appended
below without changing the frozen script or historical evidence.

## Canonical P002 outcome

The command completed on 2026-10-26. The installed validator accepted
`research/runs/release-P-002/campaign/manifest.json` with run status
`completed`. All 121 input hashes matched before/after and their immutable
copies in `research/source_snapshots/release-P-002-campaign`. The six-case
result is `research/runs/release-P-002/campaign/campaign/results.json`;
the child reported 12.828 seconds. That time is provenance, not an efficacy
comparison.

The finite records were inspected after execution, not merely accepted from
the exit code:

| Control | Committed offsets | Owned runs | Candidate evaluations | Independent literal replays |
| --- | --- | ---: | ---: | ---: |
| Shared two | 0, 13 | 1 | 26 | 53 |
| Default off two | 0, 0 | 2 | 26 | 26 |
| Supplemental scheduled three | 0, 10, 20 | 1 | 26 | 70 |
| Beaufort negative | 0, 10, 0 | 2 | 30 | 40 |
| Masked | 0, 13 | 1 | 26 | 53 |
| Production worker two | 0, 13 | 1 | 26 | 53 |

All 295 literal replays and exact masked-score checks passed. Complete saved
top-20 rankings matched independent enumeration of all 26 keys, including
lexical ties. Earlier snapshots at 10, 13, or 20 candidates remained
incomplete and explicitly lacked whole-family top-k proof. The Beaufort
negative continued to start a separate owner. The comparison was 52 complete
candidate evaluations for two independently completed equivalent recipes
versus 26 for the shared completed owner; replay and validation work are
separate costs. Default-off partial jobs are not that completed baseline.

The 17-file P001 tree hash and old notes hash were checked again after P002
and remained exactly as recorded above. The repaired script also retained
its frozen hash. Manifest SHA256:
`4d98d9cfbd978764ecb422bbaf007f0d02045bf5e6a0bf022fa6d6d467be793c`.
Result SHA256:
`bb6e24d9ada73d0b37269a92a71753bbe3d78cee03cc755c3eef5ac8a96b9038`.

Outcome: implementation and finite assertion verified for these unchanged
six authored controls. No production changes, new search cases, GPU work,
K4/K5 search, or publication were performed for this repair.
