# Third-party notices

This project is an independent research toolkit. No affiliation or endorsement by James Sanborn, the Central Intelligence Agency, Paradigm, Project Gutenberg, NVIDIA, or cited researchers is implied. Project-authored software and documentation are licensed under [GPL-3.0-only](LICENSE), copyright (C) 2026 gearashi. This license does not grant rights to third-party works; their notices and terms remain applicable.

## Kryptos reference data

Kryptos is a sculpture by James Sanborn. The [CIA's sculpture page](https://www.cia.gov/legacy/headquarters/kryptos-sculpture/) identifies it as **“Kryptos” © Copyright 1988 James Sanborn. All rights reserved.** Canonical ciphertext, public clues and normalized ordinal-coordinate fixtures are attributed research inputs; ownership of the sculpture or its inscription is not claimed. The [CIA's general reuse policy](https://www.cia.gov/site-policies/) excludes marked copyrighted material.

The textual coordinate record was checked against [Elonka Dunin's hand-verified transcript](https://www.elonka.com/kryptos/transcript.html) and the CIA transcript. `research/sculpture_layout.json` records sources, hashes and the limits of ordinal coordinates. Physical distances and three-dimensional alignment are unknown. Full source-page caches and sculpture photographs are not included in the public package.

## Literary sources and derived language models

Frozen trigram-count models are derived from identified Project Gutenberg texts. Training sources for the two-author English, Spanish, French, Italian and Latin models are:

- Jane Austen, [Pride and Prejudice (1342)](https://www.gutenberg.org/ebooks/1342), and Charles Dickens, [A Tale of Two Cities (98)](https://www.gutenberg.org/ebooks/98).
- Miguel de Cervantes, [Don Quijote (2000)](https://www.gutenberg.org/ebooks/2000), and Juan Valera, [Pepita Jiménez (17223)](https://www.gutenberg.org/ebooks/17223).
- Victor Hugo, [Les Misérables I (17489)](https://www.gutenberg.org/ebooks/17489), and Gustave Flaubert, [Madame Bovary (14155)](https://www.gutenberg.org/ebooks/14155).
- Carlo Collodi, [Pinocchio (52484)](https://www.gutenberg.org/ebooks/52484), and Alessandro Manzoni, [I promessi sposi (45334)](https://www.gutenberg.org/ebooks/45334).
- Julius Caesar, [De Bello Gallico I–IV (218)](https://www.gutenberg.org/ebooks/218), and Virgil, [Aeneidos (227)](https://www.gutenberg.org/ebooks/227).

The older single-book models use the first title in each pair. Independent validation books, hashes, source metadata and normalization evidence appear in `research/evaluation_corpora_J.json`; each model also records its own training provenance. Full raw books are excluded from this application package. Local research copies retain their original license text.

The inspected catalogs describe these editions as public domain in the USA; no worldwide status is asserted. Project Gutenberg is a registered trademark. Consult its [license](https://www.gutenberg.org/policy/license.html), [permission guidance](https://www.gutenberg.org/policy/permission.html), and each edition's terms when obtaining or redistributing book copies. Source attribution here is not sponsorship or an assertion of ownership over those texts.

## Other research references

Optional PK challenge benchmarks cite [Paradigm](https://www.paradigm.xyz/writing/kryptos), [firsthand method descriptions](https://asynchronous.win/post/solving-pk1-pk7-at-paradigms-ctf/) and [firsthand solver records](https://github.com/benjacasas02/independent-cryptography-research). Official challenge assets, complete third-party reports and downloaded verifier code are excluded. Source URLs and hashes document provenance; public access is not treated as a blanket reuse license. No downloaded third-party solver implementation is executed as part of this application.

## Optional GPU dependencies

CPU operation uses the Python standard library. Explicit GPU setup installs the packages pinned in `requirements-gpu.txt`, including CuPy's CUDA 12 wheel and NVIDIA runtime/compiler libraries, into the local environment. Those dependencies are distributed by their respective publishers under their own terms; their packages and licenses are not relicensed by this repository. The `.venv` and GPU caches are excluded from publication. CUDA and NVIDIA product names identify the optional backend, not an endorsement.

## Optional finite constraint backend

The explicit `Setup.cmd -Sat` option installs the Z3 solver pinned in
`requirements-sat.txt`. Z3 retains its MIT license and is not redistributed in
the source archive. The other CPU algorithms and CUDA family scans do not
require it. Its incremental solver is used only for supplied finite models;
an inconclusive backend response is never an impossibility proof.

No authenticated K4 or K5 decipherment is claimed. No authenticated public K5 ciphertext is bundled. More detailed packaging decisions are in [SOURCE_DISTRIBUTION.md](docs/SOURCE_DISTRIBUTION.md).
