# Paradigm PK challenges: comment and source review

Reviewed **12 October 2026, America/Los_Angeles**. The final official-data GET
was at **2026-10-13T01:42:15Z**. Read-only investigation; no sign-in, proposed
solution submission, payment, new solver implementation, or cipher search.

## Comment coverage

The user linked [“Paradigm PK challenges are all solved — Yet K4 Kryptos remains
unsolved”](https://www.reddit.com/r/KryptosK4/comments/1wxww45/paradigm_pk_challenges_are_all_solved_yet_k4/).
The direct page exposed seven comment bodies, including colski's technical
summary, replies discussing verification of K4, and a caution about transferring
assumptions from the PK puzzles. The indexed version exposed two additional
comments: one linking Sanborn's WIRED interview and one requesting a compendium
of diagnostic signals. Those indexed comments are dated October 5–6, 2026.
The direct page supplied inconsistent cached relative ages. The `sort=new`
request failed. This review does **not** claim complete access to collapsed,
deleted or later replies.

Colski's useful point is that ordinary substitution and transposition layers
can conceal one another's diagnostic signals. The comment also reports a
deliberately misleading statistical feature in PK8. That specific construction
has not been authenticated from a complete original PK8 solution in this review.
The comment quotes Dan Robinson disclaiming inside information about K4; the
original post carrying that exact wording was not located, so retain the
attribution as secondhand rather than quoting it as a checked primary statement.

## What primary sources establish

The [official first-solves endpoint](https://www.paradigm.xyz/kryptos-ctf/api/first-solves)
records successful solves for **all ten** PK challenges. Its last three first
solves are:

| Challenge | First recorded solve, UTC |
|---|---|
| PK8 | 2026-09-06 18:20:58.332 |
| PK9 | 2026-10-02 22:29:29.926 |
| PK10 | 2026-10-02 22:52:01.808 |

The endpoint was discovered in JavaScript explicitly linked by the official
[challenge page](https://www.paradigm.xyz/kryptos-ctf/pk8), which uses it for live
status. The static page data still labels PK8 “Unsolved”; that stale constant
must not override the live official records. The separate public PK8 leaderboard
also records its September 6 first solve. These are service records of successful
challenge solutions, not public certificates of every solver's methodology.

The official June 12 [Project Kryptos announcement](https://www.paradigm.xyz/writing/kryptos)
states that Paradigm created ten new practice puzzles and arranged answer
verification without viewing K4's answer. This supports treating PK as practice,
not as disclosed K4 ground truth. All ten PK records being solved says nothing
by itself about whether K4's algorithm has been recovered. No authenticated
complete K4 method was found during this review.

One comment misdates the linked [WIRED interview](https://www.wired.com/2005/01/questions-for-kryptos-creator/)
as 2025; it is from **January 2005**. Its “different animal” comparison concerns
Kryptos's meaning versus the Cyrillic Projector, not a comparison of K4's cipher
with K1–K3. Sanborn also discusses visual systems, but gives no exact algorithm.
Claims that nobody has ever checked the full K4 round trip remain unverified;
absence of public verification does not prove that negative.

## Available solution evidence

[Asynchronous's firsthand August 15 reconstruction](https://asynchronous.win/post/solving-pk1-pk7-at-paradigms-ctf/)
reports these encryption orders. `Q` adds key indices in the shared KRYPTOS
alphabet; `T` is keyed columnar transposition; `H` is Hill substitution.

| Puzzle | Reported order | Benchmark value |
|---|---|---|
| PK1 | Q(10) | Single substitution control |
| PK2 | T(7) | Unknown column order |
| PK3 | Q(10), Q(8) | Multiple periodic key streams |
| PK4 | T(8), Q(5), Q(9) | Transposition before two substitutions |
| PK5 | T(8), Q using PK4's 224-letter plaintext | Earlier answer as running key |
| PK6 | T(9), T(9), Q(6) | Two distinct transpositions |
| PK7 | Q(6), 3-by-3 H | Linear block mixing |

The author supplies encryption formulas and reports exact re-encryption. This
review did not rerun those proofs. Its claim that PK8–10 were still unsolved is
historical, superseded by the live leaderboard. Its later speculative searches
are not validated PK8–10 methods.

A separate [firsthand research repository](https://github.com/benjacasas02/independent-cryptography-research/blob/main/research/paradigm-kryptos/README.md)
reports reproducible PK1, PK2, PK3 and PK6 solutions with exact re-encryption
checks. Its own discussion limits conclusions about its proposed key generator
to the tested case. The code/results are potential benchmark fixtures, not yet
independently audited in this project.

A [related Reddit discussion](https://www.reddit.com/r/KryptosK4/comments/1u3wui2/link_to_kryptos_site/)
reports PK8 as four Q layers with periods 4,5,6,7 and PK9 as Q plus spiral and
columnar routes. These are **reported methods awaiting a complete verified
plaintext/key/ciphertext fixture**. Its generic T description also differs from
the explicit column-reading formula in the firsthand reconstruction. Use exact
permutations, not a shared “T” label, before comparing or implementing them.

## Three actionable improvements

1. **Use published PK cases as independent recovery benchmarks.** Start with
   PK1–3 and PK6, whose firsthand source includes reproducible results. First
   validate full encryption/decryption from the published method. Then withhold
   keys from the recovery routine and measure success under a declared budget.
   Record method-known recovery separately from method selection. This adds
   independently authored text and keyed column orders to our twelve synthetic
   cases. It is not a claim of a blind human benchmark: we have read the methods.

2. **Close the reverse-order running-key gap.** PK5's reported order is
   `C=S(T(P),K)`, whereas our first running-key filter covers `C=T(S(P,K))`.
   For a fixed key, undo S at each ciphertext position to get `T(P)`. Its
   inventory must contain every symbol demanded by the 24 plaintext cribs.
   A deficit excludes every permutation for that key. Passing remains weak
   arbitrary-permutation feasibility. Preserve this as a separate model with
   independent direction/indexing controls. The report supplies motivation,
   not evidence that K4 uses PK5's construction.

3. **Benchmark layered-cipher diagnosis before expanding searches.** The
   existing model bank has two substitutions and one fixed permutation, not
   arbitrary keyed column orders, multiple independent transpositions or Hill
   mixing. Compare masked language scores and mod-2/mod-13/period diagnostics
   across verified PK fixtures, new synthetic examples, and matched nulls.
   Record false classifications and method-known recovery failures. Additional
   adjacent Q layers could be modeled as a sum of repeating key streams, but
   treat the reported PK8 periods as unverified until its complete fixture is
   reproduced. A statistical peak or a solver miss is not a family exclusion.

The comments provide useful examples of missing coverage, but no new
authenticated K4 crib, key, grid size or exact cipher rule. The decisive test for
the next implementation remains whether it recovers verified examples and
produces exact rejection certificates within its stated limits.

Implementation follow-through: [the reverse-order inventory test](../research/runs/running-key-after-route-001/results.json)
is complete (2,258 rejections and 622 arbitrary consistency witnesses), and
[published PK1/PK3 recovery benchmarks](../research/pk_benchmark_notes.md) now
validate exact official ciphertext round trips. PK1 recovers uniquely from the
supplied method and artificial crib mask. A separate bounded PK3 run checks all
17,576 remaining plaintexts and ranks the published one first. No answer keys
enter candidate recovery. This closes these specific implementation steps;
general method diagnosis and the remaining PK families are still untested here.

## Retrieval record

The official dynamic pages had empty text extraction, and no browser was
available. Approved read-only HTTPS GETs retrieved the public HTML and linked
JavaScript; no downloaded script was executed. Only the public first-solves and
PK8 leaderboard GET endpoints were queried. Authentication and submission
endpoints were not called.

Retained public source: [paradigm_first_solves_2026-10-12.json](source_snapshots/paradigm_first_solves_2026-10-12.json),
945 bytes, SHA-256
`083af556c7b272608d79a8da6e6b5526f050ae7351b98443577dd8e8effe4799`.
Source URL: <https://www.paradigm.xyz/kryptos-ctf/api/first-solves>.
The filename uses the local review date; retrieval UTC is recorded above.
This hash authenticates the retained response bytes, not a cipher answer.

The challenge site's currently linked application asset used to discover the
public endpoint was
<https://www.paradigm.xyz/kryptos-ctf/_next/static/chunks/0h1ap~1.6ljs6.js>.
Assets and leaderboard entries can change. Original X hint links returned 403;
no mirror was treated as authenticated primary evidence of their contents.
