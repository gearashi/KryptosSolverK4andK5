# Bounded review of r/KryptosK4

Reviewed on **12 October 2026**. Scope: the subreddit feed, selected substantive
posts/comments, linked sources, the local coverage record, and one direct
24-position arithmetic check. No posting, contact, external candidate submission,
language search, or large CPU/GPU computation. This is a shortlist, not a survey
of every historical post. Reddit's cached relative dates were inconsistent with
crawl dates; exact post dates below are **unverified**, rather than inferred.
Posts are evidence of proposed hypotheses, not of the artist's intentions.

Follow-up: the user's specific PK challenge thread and its accessible comments
are reviewed in [PK_CHALLENGE_REVIEW.md](../docs/PK_CHALLENGE_REVIEW.md), including
an official dated first-solves snapshot, source corrections and benchmark gaps.

## 1. Repeated-letter parity: a precise new filter

[Post by Laszlos-BatForm](https://www.reddit.com/r/KryptosK4/comments/1x2y08f/k4_every_repeated_plaintext_letter_in_the_cribs/)
(extraction displayed “33m ago”; exact timestamp unavailable) proposes
`q_i = (A0(cipher_i) + i) mod 2`, with one-based positions. Its claim is that
`q_i = q_j` whenever the corresponding known plaintext letters are equal.
The direct local check confirms all 13 pairs, representing 11 independent
equalities, across the 24 crib positions. With these conventions, `BEHIORS` have
bit 1 and `ACKLNT` bit 0. Zero-based positions or A=1 flips every bit, preserving
the equality statement. The prediction is falsifiable on any independently
obtained plaintext: each repeated letter must retain its bit throughout.

The author's [expanded explanation](https://www.kryptosbot.com/crib-parity/)
already recognizes that this constrains parity only and allows very many
completions. Its displayed formal-verification and simulation claims were not
executed or audited here. Its site footer identifies a 12 October rebuild and
11 October newest research input. Do not adopt the proposed post-selection odds
as a calibrated probability or a probability that this is the actual cipher.

**Our mathematical distinction:** an arbitrary letter-to-bit map need not be
balanced. If the map is parity of a *bijective 26-letter alphabet*, exactly 13
letters belong to each bit: the 13 unseen symbols must supply six more bit-1 and
seven more bit-0 letters. A complete candidate then must satisfy repeated-letter
consistency and use at most 13 distinct symbols in either class. These are
conditional filters, not new authenticated cribs.

A stricter fixed-step model `C_i = f(P_i) + d*i (mod 26)` already contradicts
two E differences: positions 22/31 require `9d=1`, hence `d=3`; positions 22/65
require `43d=19`, whereas `43*3=25 (mod 26)`. This rejects that subclass only.
The expanded source permits arbitrary keystream values of alternating parity,
so this calculation does **not** refute its broader proposal.

**Coverage/next step:** our earlier periodic/progressive tests fixed alphabet
choices; they are not a test of every parity-compatible alphabet or keystream.
Record this invariant as a separate optional candidate filter and test its
specified subclasses with exact witnesses. Do not promote it into a scoring
bonus selected after looking at candidates.

## 2. K3 running key, followed by unknown transposition

[“Beaufort, or inverse Quagmire III,” by colski](https://www.reddit.com/r/KryptosK4/comments/1vxgnup/beaufort_or_inverse_quagmire_iii/)
(displayed “1mo ago”; exact date unverified) proposes a K3-derived running key
with a further transposition. Its frequency argument assumes a particular
plaintext/key distribution; matching a short ciphertext's histogram is not
validation. Specify equations directly to avoid disputed cipher names:
`Z_i=P_i+K_i`, `Z_i=K_i-P_i`, or `Z_i=P_i-K_i`, modulo 26 in a fixed alphabet,
then `C=T(Z)`.

**New exact prediction:** each crib determines a symbol of `Z`. For every
letter, the count forced by the cribs cannot exceed its count in `C`, because
transposition preserves inventory. This can reject a running-key window without
searching even one transposition. It is not the same model as `C=S(T(P),K)`.

**Coverage/next step:** the existing short repeating-key and 29-route scans do
not cover arbitrary transpositions with nonrepeating K3 windows. A bounded test
can examine all 97-letter nonwrapping windows of the verified 336-letter K3
plaintext, both reading directions, the two fixed alphabets and three equations.
Store exact deficit witnesses. Passing remains weak: unspecified plaintext
letters and an arbitrary permutation can absorb remaining counts.

## 3. Physical tableau overlays: promising data work, incomplete cipher rules

[“CT Row Lengths, Tableau Overlay (Palimpsest), and Abscissa X Coordinates,” by mnlsp](https://www.reddit.com/r/KryptosK4/comments/1wmp4hf/ct_row_lengths_tableau_overlay_palimpsest_and/)
(displayed “23m ago” despite an older crawl; date unverified) aligns the whole
cipher panel with the tableau and selects letters corresponding to separators.
This differs from our K4-only occupied-cell scan permutations. It requires an
authenticated coordinate transcription, including variable row lengths,
punctuation, raised letters, and the extra tableau L. Its selected output does
not yet give a reproducible cipher or predict the 24 cribs.

The [compass-geometry discussion](https://www.reddit.com/r/KryptosK4/comments/1wriejc/could_the_kryptos_compass_rose_be_a_geometric/)
(displayed “7d ago”; date unverified) adds curvature and local surface normals.
Its numerical angles and claimed Smithsonian sketch measurements were not
authenticated here. It calls position 30 an E: in the pinned one-based crib it
is H, while zero-based 30 is E. That convention must be resolved before using
the apparent alignment. Generic sculpture curvature can also explain clustered
vectors without encoding anything.

**Next step:** first make a photo/plan-backed coordinate dataset. Preregister
one overlay, orientation, origin and character-consumption rule. Require the
same rule to reproduce known K1/K2 table operations, then test K4 crib
constraints. Geometry should be compared against matched placements or the
same curve without the letter labels. Invented precision or freely movable
overlays cannot support a cryptanalytic result.

## 4. Joint K3/K4 palimpsest or null grid

[“Pushing a palimpsest into the original matrix,” by colski](https://www.reddit.com/r/KryptosK4/comments/1thvafi/pushing_a_palimpsest_into_the_original_matrix/)
(displayed “5mo ago”; date unverified) expands a K3 layout with null cells and
puts a second message into them. In the comments the author explicitly explains
that K2 text was inserted as a demonstration; it was not discovered inside K3.
Choice of the occupied nulls remains part of the unknown hypothesis.

**Exact limit:** even allowing a joint K3+K4 pure letter permutation cannot
remove the current E-inventory contradiction if canonical K3 is preserved.
K3's plaintext and ciphertext inventories agree, so they cancel from the joint
inventory equation; K4 still has only two E's against at least three in its
crib-bearing plaintext. Extra substitution or actual insertion/deletion of
letters changes the model and must be stated. Empty grid cells alone do not.

**Next step:** only after a fixed null mask is independently justified, derive
its induced permutation and known-K3 constraints. Avoid enumerating arbitrary
masks to manufacture a readable result. Our two ragged K3 adaptations do not
cover extended grids, but the inventory obstruction already excludes the
letter-preserving version.

## Lower priority: clock blocks and anomaly keywords

The [24-city split proposal](https://www.reddit.com/r/KryptosK4/comments/1wdo2q1/weltzeituhr_24city_theory_bsol_kcar_split_matches/)
uses the first symbol plus a 24-by-4 remainder. That arithmetic gives a concrete
layout, but no city-to-column permutation. Its crib table mixes indexing:
the correct one-based EAST ciphertext is `FLRV` at 22–25; BERLIN starts at 64,
not 63. The same post also returns to lamp-clock coordinates. Sanborn's
[12 November 2025 letter](https://assets.documentcloud.org/documents/26229389/adobe-scan-nov-12-2025.pdf),
previously visually checked in [SEMANTIC_SOURCES.md](../docs/SEMANTIC_SOURCES.md),
explicitly identifies the World Clock. This supports the referent, not the
24-by-4 transformation. A future test needs fixed handling of the first symbol
and a source-grounded ordering before running any permutations.

The [Morse keyword discussion](https://www.reddit.com/r/KryptosK4/comments/1qbtrbn/morse_code_clues/)
can spell known keys by shifting lines, but also produces many unrelated words.
The [mixed-alphabet anomaly experiment](https://www.reddit.com/r/KryptosK4/comments/1wl6kd6/k4_observations_egyptxqundig/)
reports an Egypt fragment but does not reproduce the released cribs. Its own
author acknowledges experimental boundaries and skips an inconvenient source
line. The feed and cached post disagree over a handwritten-note transcription;
the linked image did not load, so neither transcription was authenticated here.
Free choices of anomaly letters, omitted lines, switch boundaries and anagrams
are not yet a constrained cipher. Sanborn's [August 2025 letter](https://www.elonka.com/kryptos/OpenLetterAug2025.html)
does label a remark about the point of secrecy as a clue; it does not instruct
readers to replace POINT with X.

## Primary-source checks and limits

Richard Bean's [2021 HistoCrypt paper, DOI 10.3384/ecp183153](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109/52)
does record the equal-key implication at zero-based positions 27/65 and tests
Gromark variants. Its statistical preference against transposition is an
inference under its comparisons, not a proof excluding layered transpositions.
Its older lamp-clock motivation must be distinguished from the later World
Clock identification. Our software should not silently inherit either a cipher
family choice or a claim of uniqueness from those statistical arguments.

Scheidt's [21 January 2005 interview](https://www.wired.com/2005/01/inside-info-on-kryptos-codes/)
supports English being masked and acknowledges uncertainty about Sanborn's final
changes. It supplies no exact grid, running key, transposition order or physical
decoding instruction. Reddit comments turning that into a definite custom
algorithm go beyond the source. The linked owner history page exposed only
navigation in text extraction, and one linked archive photograph did not load;
claims depending on those images remain unverified here.
