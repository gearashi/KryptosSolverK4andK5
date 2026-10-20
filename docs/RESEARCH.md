# Kryptos research inputs and limits

Source review: **12 October 2026**. This application is a reproducible search workbench, not a claim to have solved Kryptos. Search output is evidence about the named algorithm and recorded search bounds. It does not settle the whole sculpture or every possible cipher.

## K4 input

The target is the following **97 letters**, beginning immediately after the question mark at the end of K3. That question mark is excluded. The original line breaks below are retained only for comparison; the solver concatenates them.

```text
OBKR
UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO
TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
```

The last four lines of Panel 2 in the [CIA's printable transcription](https://www.cia.gov/spy-kids/games/images/KryptosPrint.pdf) agree with [Elonka Dunin's sculpture transcription](https://www.elonka.com/kryptos/transcript.html) for this target. The PDF's physical panel numbering must not be confused with the cryptographic passages K1–K4.

The four public plaintext cribs are entered as **1-based positions** in the final K4 plaintext:

| Start–end | Ciphertext at those positions | Plaintext | Release |
|---|---|---|---|
| 22–25 | FLRV | EAST | 2020 |
| 26–34 | QQPRNGKSS | NORTHEAST | 2020 |
| 64–69 | NYPVTT | BERLIN | 2010 |
| 70–74 | MZFPK | CLOCK | 2014 |

Together these fix 24 positions. See [Dunin's clue history and displayed placement](https://www.elonka.com/kryptos/). Her record distinguishes the private April 2020 EAST correspondence from authorization to publish it in August 2020. A supplied crib is a constraint on the final plaintext, not a reason to overwrite decrypted output with the desired letters.

## What changed in 2025

Researchers recovered the K4 text from archival material in 2025. That recovery does not supply the original cipher method. [RR Auction's October account](https://content.rrauction.com/kryptos-k4-discovered-not-solved-heres-what-actually-happened/) distinguishes the recovered text from the cryptographic system, and says the researchers did not intend to publish it. The [November 2025 sale announcement](https://content.rrauction.com/jim-sanborns-complete-kryptos-archive-sells-for-962500-at-auction/) records a private sale of the archive including K4 coding material. This review did not locate an authenticated public complete plaintext-and-method release. Internet reconstructions and self-published solution claims are not built-in ground truth.

Sanborn's November 2025 talk and open letter identify the clock referent as the **World Clock in Berlin**. They also connect the content to his 1986 Egypt trip, the fall of the Berlin Wall, delivery of a message, and the K2/K5 theme. These are contextual clues, not published cipher keys or numerical algorithms. [Scientific American's eyewitness report](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/) documents the statements. Its reference to “79” K4 letters is a typographical error; use the independently checked 97-letter transcription above.

## Current steward and verification, 2026

On June 12, 2026, [Paradigm identified itself as the new steward](https://www.paradigm.xyz/writing/kryptos). It says Sanborn entered the answer on a dedicated computer; a SHA-256 digest went to Google Cloud KMS for a keyed HMAC, and the computer was then wiped. This is the owner's account of setup, not an independent audit. The article also says Sanborn supplied another 97-character K5 ciphertext for later release.

The [current K4 page](https://www.paradigm.xyz/kryptos/k4), retrieved on October 12, still labels K4 unsolved. Its public client script enforces 97 uppercase ASCII A–Z letters and exact crib matches. It uppercases each grid cell and removes non-A–Z characters before concatenation; pasted text also has whitespace removed. The form carries the candidate in a `solution` field along with name, email, and a decryption-method explanation. It advertises a $1 submission fee and private email results. No submission or payment was made during this review.

**There is no established offline digest oracle.** No public K4 plaintext digest was located on these owner pages or in the page-linked client scripts inspected. The article describes a private-key HMAC verifier, not a published SHA-256 value. The public code establishes the browser's accepted input format; it does not establish the server's byte encoding, any additional normalization, or the HMAC key. Do not claim that locally hashing a candidate verifies it against Sanborn's answer.

Inspection provenance: the page-linked [K4 form script](https://www.paradigm.xyz/kryptos/_next/static/chunks/9308b667190255e3.js?dpl=dpl_B7wJQfFhM37xL7YHvMX31rRPiBah) was 15,658 UTF-8 bytes with SHA-256 `274a0f90d5fd0cc8508017b2319719aa6d63bf9f64507a39b268e6defe33e3f6`. **That is the script's hash, not a K4 answer hash.** This was static inspection of public HTTPS responses with ordinary shell tools; no runtime verifier execution, REA evidence, or server-side access occurred. The old article URL `/2026/06/kryptos` redirected to `/writing/kryptos` during retrieval.

## K5: distinguish evidence from experiments

[Sanborn's August 2025 letter](https://www.elonka.com/kryptos/OpenLetterAug2025.html) says a riddle remains as K5 after K4. The [auction lot description](https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/) identifies K5 material as an unpublished 1988 alternate K4 plaintext and coding chart. The auction house notes it relied on Sanborn's description and had not independently examined the secret archive items. The current owner's more recent description above supplies a ciphertext length and future-release intention. Keep these dated descriptions distinct; neither provides public cipher letters or warrants silently manufacturing a fifth target.

No authenticated public K5 ciphertext was located in this bounded review. Consequently `K5_CIPHERTEXT` is `None`, and there are no automatic K5 cribs. The app can test user-supplied texts and extraction hypotheses, but a run must record what was supplied and why it is considered relevant. A sequence extracted from K1–K4, a reading route through the sculpture, or an assumed further cipher layer is an **exploratory hypothesis**, not an authenticated fifth passage. A word such as BERLIN becoming visible in an arbitrary extraction is not verification.

## Relationship to Kryptos@Home

A [January 2021 launch announcement](https://www.reddit.com/r/BOINC/comments/kui7xc/) records the previous BOINC project. This application runs independently of that service, does not contact its former server, and does not import or claim its unpublished work. The user's report that the server is permanently offline is an operating premise, not evidence that a particular cipher family was exhaustively tested. The source review did not recover an authoritative final result archive or coverage certificate. Lack of published results cannot be treated as a negative cryptanalytic result.

## Interpreting local results

- The bundled candidate keys are thematic search seeds. None is asserted to be a K4 or K5 key.
- English scoring ranks possible outputs. A flexible model can manufacture readable text, especially after fitting a keystream to desired words.
- A candidate should state the complete reversible method and key, reproduce every ciphertext letter, match confirmed cribs, and explain how the key was selected without assuming the proposed plaintext.
- Even exact re-encryption alone does not authenticate a solution: an arbitrary 97-letter keystream can fit any proposed 97-letter plaintext.
- A search with no candidate eliminates only the explicitly enumerated configurations when enumeration is exhaustive. Stochastic searches provide sampled evidence, not exhaustive elimination.
- Preserve run configuration, source target, random seed where applicable, completed-work count, and candidate output so interrupted work and later comparisons can be interpreted correctly.

The review prioritized CIA transcription, the artist's open letter, Dunin's direct research record, auction records, and the current owner's site. Searches also covered recent reporting, K5 descriptions, and the old BOINC project. The owner update used direct HTTPS retrieval because the web search tool could not open that site. It was not a comprehensive literature review of every cipher family or a proof of absence of later private results.
