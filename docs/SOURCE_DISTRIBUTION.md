# Publication inventory and draft third-party notices

Current licensing update (2026-10-15): project-authored software and documentation are now licensed under [GPL-3.0-only](../LICENSE), copyright (C) 2026 gearashi. The review below records the earlier packaging decision; statements that no project license had been chosen describe that earlier state. Third-party materials retain their own terms.

Reviewed on 2026-10-13 for the proposed `gearashi/KryptosSolverK4AndK5` publication. This is an inventory and packaging recommendation, not a grant of third-party rights or a choice of license for the user's code. No project license was present at the start of this review. Keep any later code-license decision separate from source-data attribution.

## Primary-source findings

The [CIA Kryptos page](https://www.cia.gov/legacy/headquarters/kryptos-sculpture/) explicitly identifies **“Kryptos” © Copyright 1988 James Sanborn. All rights reserved.** The [CIA site policy](https://www.cia.gov/site-policies/) permits reuse of unmarked agency information but excludes material marked as copyrighted. Do not describe the sculpture, inscription or photographs as public domain merely because a CIA page presents them. No sculpture photographs or CIA insignia are needed for this application.

The fifteen retained book catalogs say “Public domain in the USA.” All fifteen raw text files retain their original header and full license sections; their headers contain no special copyright-permission notice found in this bounded review. [Project Gutenberg's license guidance](https://www.gutenberg.org/policy/license.html) distinguishes book text, the trademark/license, and permission-only works, and warns that catalog metadata alone is insufficient. It describes retaining the complete license with unchanged free copies as one distribution route; the work's own terms control. No worldwide copyright assertion is made here.

[Project Gutenberg's permission guidance](https://www.gutenberg.org/policy/permission.html) permits source credit and links, recommends linking book landing pages, and separates attribution from trading on its trademark. The model manifest already gives those landing pages and authors. The app should not imply Gutenberg sponsorship.

The retrieved firsthand [PK solver repository](https://github.com/benjacasas02/independent-cryptography-research) did not expose a license in the inspected repository page. That limited observation is not proof that no license exists anywhere; it is insufficient evidence for redistributing its downloaded code. The saved `verify_all_source.txt` was read for provenance and never executed or imported. No reuse grant was verified for the full Paradigm JavaScript asset, the full methods blog, or Dunin's complete HTML transcript. Retain URLs/hashes and concise factual method descriptions rather than publish those cached copies wholesale.

## Recommended public package

| Material | Recommended treatment | Reason / remaining condition |
| --- | --- | --- |
| Project-authored `kryptos/*.py`, frontend assets, tests, examples and documentation | Include after normal code/secret review. | No license chosen here; distinguish newly authored implementations from downloaded sources. |
| Authored research scripts, bounded contracts and explanatory notes | Include selectively. | Document which optional local inputs are excluded and how to obtain them; do not claim all historical runs reproduce from the public checkout unaided. |
| Source URLs, retrieval dates, hashes, book IDs, author/title metadata | Include. | Compact provenance allows independent source retrieval without mirroring full third-party pages. |
| Canonical ciphertext, released cribs and normalized textual-coordinate reference data needed by the app | Minimal attributed research/reference fixtures, with third-party rights expressly reserved. | The code license must not purport to license the sculpture or source text. This review does not establish a separate redistribution grant for the full inscription. Avoid photos and unnecessary duplicate transcriptions. |
| Trigram count models | Prefer a small explicitly chosen model asset with source manifest and provenance notice, or local model generation. | Counts are derived research data rather than a bundled full book. Do not describe them as a grant of rights over source works; keep relevant author/book links and normalization metadata. |
| Full raw Gutenberg books in `research/corpora/` and `research/source_snapshots/evaluation-J/pg*.txt` | Exclude by default from the app repository; retain source URLs/hashes and local acquisition instructions. | They are optional training/reproduction inputs, not required at runtime once a model is supplied. If intentionally redistributed, preserve and follow each file's original terms; do not silently strip the license. |
| Full HTML pages, blogs, official site JavaScript, downloaded third-party verifier code | Exclude. | Read access and source attribution are not themselves redistribution permission. |
| PK benchmark plaintexts/source-derived fixtures | Optional research data, not needed for app startup. | Source and method attribution must accompany any included fixture; the full third-party reports/code/assets should stay excluded. |
| Raw run outputs, verbose logs, local-job databases and source caches | Exclude by default; export selected compact evidence summaries deliberately. | They can contain absolute local paths, duplicated source passages, large candidate dumps or runtime state. Historical originals should remain intact locally. |
| `__pycache__`, `.pyc`, temporary batch/job directories, `.venv`, credentials/session files | Exclude. | Generated/local state is not application source. |

Do not use `git add .` until a real allowlist/ignore policy has been applied and the staged file inventory reviewed. This document does not itself stage, delete, redact or publish anything.

## Fresh-checkout requirements

`sculpture.load_layout()` still defaults to validating full retained source pages. The new `load_packaged_layout()` verifies the normalized dataset's pinned SHA-256 and structural/section checks, explicitly reports that source pages were not re-read, and supplies ordinary cell/route functions and the layout command. It does not silently weaken the strict source audit. Original touched code/tests were preserved under `research/source_snapshots/checkpoint-K-original/` before editing. Ten focused tests pass, including source-unavailable ordinary operation, strict-audit failure without those sources, and mandatory packaged-data integrity. Only the explicit raw-source audit test skips when optional snapshots are absent; packaged integrity and regression tests always run.

The same distinction applies to language models: optional training/research commands may explain missing corpora, while the ordinary app should either ship a deliberately selected attributed model or require one explicitly. Fresh-checkout tests should not depend on excluded raw caches. If a historical manifest references an excluded input, preserve its hash and clearly label the additional reproduction dependency; do not rewrite old evidence to imply it was present.

## Draft third-party notice text

The following paragraphs are a draft for the published package's notices, adjusted to the actual included files:

> Kryptos is a sculpture by James Sanborn. Canonical ciphertext, public clues and any normalized textual-coordinate records are included solely as attributed research inputs. No ownership of the sculpture, its inscription, or third-party source material is claimed. Source references include the CIA Kryptos page and Elonka Dunin's hand-verified transcription. No endorsement by the artist, CIA, or source authors is implied.

> Language-model counts are derived from explicitly identified literary sources. Author, title, Project Gutenberg book identifiers, source links, content hashes and normalization details are recorded in the accompanying corpus manifest. Original book texts and their licenses remain separate from the application code. Project Gutenberg is a registered trademark; this project is not affiliated with or endorsed by it.

> Optional Paradigm PK benchmark references distinguish official challenge ciphertexts from firsthand solver reports and locally reconstructed plaintext. Source authors retain rights to their reports, website assets and code. Downloaded third-party implementations are not part of this application's implementation.

> The project code's selected license, if any, does not apply to third-party works merely referenced, quoted or used as research inputs. This toolkit has not produced an authenticated K4 or K5 decipherment. No authenticated public K5 ciphertext is bundled, and candidate generation does not submit answers to any outside service.

The book manifest is `research/evaluation_corpora_J.json`; it identifies training books 1342/98, 2000/17223, 17489/14155, 52484/45334 and 218/227, with independently authored validation books 1661, 17340, 2650, 61885 and 33849. Older single-book models use the first book in each training pair. Attribution should follow whichever subset is actually packaged.
