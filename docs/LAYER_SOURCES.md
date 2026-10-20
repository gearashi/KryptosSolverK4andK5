# Sources and conventions for a K1/K2/K3 layered hypothesis

Checked 12 October 2026. The proposed K4 composition is a research hypothesis. The known algorithms below establish useful components and regression fixtures; they do not establish that K4 uses those components.

## K1 and K2: the same substitution family, different keys

Jim Gillogly's first-person paper, *The Kryptos Sculpture Cipher: A Partial Solution*, *The Cryptogram*, September/October 1999, printed pages 5–7 (PDF pages 3–5), identifies both passages as Quagmire III with KRYPTOS as the alphabet keyword. His [June 1999 announcement](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html) identifies PALIMPSEST for K1 and ABSCISSA for K2. The paper is available as a [scan hosted by The Kryptos Project](https://www.thekryptosproject.com/kryptos/cia/thecryptogram/pdfs/Binder1.pdf). Its relevant pages were rendered and visually inspected, because the PDF has no extractable text.

For an exact arithmetic convention, let

```text
A = KRYPTOSABCDEFGHIJLMNQUVWXZ
idx(A[j]) = j, for j = 0,...,25
encrypt: C[i] = A[(idx(P[i]) + idx(key[i % len(key)])) % 26]
decrypt: P[i] = A[(idx(C[i]) - idx(key[i % len(key)])) % 26]
```

The running keyword starts at its first letter at the beginning of each passage. Strip spaces and punctuation; question marks do not consume a key position. This exact convention was checked over all 63 K1 letters and all 369 as-inscribed K2 letters against the published normalized text. K1 preserves the spelling IQLUSION; K2 preserves UNDERGRUUND.

The sculpture's displayed alphabet margins can be misleading when implementing the substitution. David Stein's [first-person CIA report, transcribed by Dunin](https://www.elonka.com/kryptos/mirrors/daw/steinarticle.html), specifically discusses removing the exterior alphabet labels when recovering the keywords. Do not copy that HTML transcription's final paragraph blindly: it swaps the key associations relative to its own period discussion and Gillogly's known-answer mapping. Its earlier question-mark-based labels “Parts I–V” also differ from the now-standard K1–K4 labels.

## K2's corrected ending needs a corrected ciphertext fixture

Dunin's [2006 announcement recording Sanborn's correction](https://www.elonka.com/kryptos/CorrectedK2Announcement.html) explains a missing ciphertext S before the last eight letters. The as-inscribed 369-letter stream decrypts to the old IDBYROWS ending. Inserting S at zero-based index 361 yields a 370-letter stream whose intended ending is WESTXLAYERTWO. Both variants were trivially checked with the above formula. Never pair the corrected plaintext with the uncorrected ciphertext and then call the resulting mismatch an algorithm failure.

## K3: a reproducible equivalent, with a historical caveat

Gillogly's paper, printed page 7 / PDF page 5, describes three route stages with row widths 14, 24, and 8, and reversed column order. Earlier he describes removing a period-8 transposition before finding a period-14 intermediate. This is a first-person account of his solve. It is not sufficient on its own to identify Sanborn's original encryption construction or unambiguously recover every stage convention. A naive composition of three identically defined route operations at widths 14,24,8 does **not** reproduce the known pair.

The following precisely defined **equivalent decryption** does reproduce all 336 known K3 letters:

1. Define `T_w`: write the input left-to-right in rows of width `w`; read the columns right-to-left, each from top to bottom. On a complete rectangle this is a 90-degree counterclockwise rotation followed by row-major flattening.
2. Compute `P = T_8(T_24(C))`.
3. The first input rectangle has **14 rows × 24 columns**. The second has **42 rows × 8 columns**, constructed from the first stage's flattened output.
4. Re-encrypt using the inverses in reverse order: `C = inverse(T_24)(inverse(T_8)(P))`.

This is a finite known-pair verification, not a new claim about the sculpture's intended method. The [canonical sculpture transcript](https://www.elonka.com/kryptos/transcript.html) supplies K3 from ENDY through DOHW, excluding the following question mark. The known plaintext has length 336, preserves DESPARATLY, and ends with Q. The exact pair and executable transform are in [research/k3_reference.py](../research/k3_reference.py). Running `python research/k3_reference.py` confirmed all 336 plaintext letters and exact re-encryption. There was no large search or language scoring in that check.

Dunin's [2003 geometric reconstruction](https://elonka.com/kryptos/part3.html) provides another firsthand reconstruction route, but explicitly presents it as reverse engineering rather than the artist's method. Its initial displayed ciphertext contains a shortened line; use the separate canonical transcript for machine fixtures. Its historical speculation involving IDBYROWS predates the 2006 correction.

## Adapting K3 to a 97-letter K4 layer

The exact K3 rectangles work because 336 is divisible by 24 and 8. Since 97 is prime, there is no nontrivial filled rectangle of 97 letters. A length-97 test must introduce an explicit choice such as skipped empty cells, padding, a disrupted route, or a separately specified permutation. Those choices create distinct hypotheses.

The reference helper chooses **row-major fill with a ragged final row and skipped nonexistent cells**, without padding or letter deletion. It returns the output-to-input permutation, which has an exact inverse. A K4 test may evaluate `T_8(T_24(C))`, `T_24(T_8(C))`, and their inverses under that convention, but must label them as adaptations. Agreement of the two orders on the complete K3 rectangle does not justify treating them as identical at length 97. The guarded `decrypt_k3()` function only accepts 336 letters; use the generic route helpers when making a new hypothesis explicit.

## Consequences for the user's layered proposal

Two adjacent K1/K2-style substitutions using the same fixed alphabet are algebraically two periodic additions. They commute and collapse to one combined keystream with period dividing the least common multiple of their periods. For historical key lengths 10 and 8 that bound is 40. This is our direct algebraic deduction from the stated formula, not an externally sourced claim. A transposition between them can prevent that simplification because it relocates the first layer's key positions. Therefore order testing must distinguish substitutions adjacent to one another from substitutions separated by a permutation.

Gillogly's [2013 answer reproduced by a correspondent](https://kryptosfan.wordpress.com/kryptos-foia/kryptos-fan-letter-to-solvers/jim-gilloglys-response/) mentions a hypothetical fractionation → Quagmire III → double-transposition construction as an example of why guessing cipher families is difficult. It does **not** identify that construction as K4's actual method, nor is it a report of exhaustive elimination. This is an attributed first-person response hosted by its recipient; no signed original was examined.

Limits: this review verified conventions and a known-pair equivalent, not all archival descriptions of K3. Direct CIA PDF URLs redirected to the reading-room index. The direct NSA summary download was denied by its host, so no specific NSA K3 permutation is claimed here. `kryptos/data.py` was left unchanged.
