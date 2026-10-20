# Bounded recovery without supplied keys

`kryptos/recovery.py` implements deterministic crib-guided recovery for one repeating substitution, optionally before or after a supplied transposition. It uses only the Python standard library. This replaces key enumeration with exact key-residue deductions for these specified families. It does not infer the cipher family or supply missing key letters from an English score.

```python
recover_periodic_keys(
    ciphertext, cribs, *, periods=range(1, 33), alphabet="kryptos",
    cipher="vigenere", routes=None, max_models=2048, max_crib_checks=100000,
)
recover_transposition_routes(
    ciphertext, cribs, routes, *, max_models=2048, max_crib_checks=100000,
)
```

Cribs are `{"start": 1, "text": "LETTERS"}` objects with one-based original-plaintext positions. A route has `name`, `permutation`, and optionally `order`: its encryption gather convention is `T(text)[j] = text[permutation[j]]`. For key recovery, `ST` means substitute then transpose; `TS` means transpose then substitute. Pure route recovery uses `T`. Duplicate permutations with the same order are tested once and retain all name aliases. Returned `route_index` indexes this deduplicated sequence in order of first appearance, not the original input list.

The alphabet is `standard`, `kryptos`, or an explicit uppercase permutation of A–Z. Plaintext, key, and ciphertext symbols are indexed in that same alphabet. The conventions modulo 26 are Vigenere `C=P+K`, Beaufort `C=K-P`, and variant Beaufort `C=P-K`. Consequently each crib gives one exact key residue. Conflicting residues reject that route/period and return the two plaintext positions and incompatible key letters as a witness. For `ST` the residue slot is the original plaintext position modulo the period; for `TS` it is the transported output position modulo the period.

Every missing key slot remains `?`. A fit with `f` free slots represents exactly `26**f` keys of the declared length; some can have a shorter fundamental period, and candidate families for different declared periods can overlap. Corresponding plaintext letters remain `?` unless their slot is known. A complete key is reduced to the shortest word whose repetitions form that entire key. Equivalent complete keys on the same route are merged while preserving all tested declared periods. A partial key is never reduced to one guessed shorter completion. Full plaintext is returned only when every encountered key slot is known; it is checked against every crib and by literal re-encryption. Unused slots in a key longer than the text can remain uncertain even when the whole text is determined.

An extra key-origin search would be redundant here. For an unrestricted period-`p` key, starting at origin `s` is precisely the origin-zero key with residues rotated by `s`. Every such rotated key already belongs to the recovery family. This argument holds at the substitution's own index for both stage orders. A future dictionary-constrained key family could distinguish named words from their rotations, but this API has no dictionary restriction.

The model and crib-check budgets are explicit. A model starts only when the remaining crib budget can cover all unique known positions; early contradictions can use fewer checks. A budget stop is marked `truncated`, never as a complete exclusion. Work reports requested/tested models, actual crib comparisons, route deduplication, decoded plaintext symbols, and merged complete keys. Texts and keys have a 4096-letter limit; period and route lists each have at most 4096 entries. Input validation, route normalization, and output construction are bounded by those input sizes but are not charged as crib comparisons. There are no workers or randomized searches.

## Verified benchmarks

The fixture sources are the [sculpture transcript](https://www.elonka.com/kryptos/transcript.html), [Gillogly's first-person 1999 announcement](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html), and [the 2006 K2 correction announcement](https://www.elonka.com/kryptos/CorrectedK2Announcement.html), reread on 12 October 2026. The script embeds K1/K2 fixtures and verifies each independently with the published key before calling recovery. K1 preserves IQLUSION; K2 preserves UNDERGRUUND. The original 369-letter K2 ends IDBYROWS. The separate corrected fixture inserts ciphertext S at zero-based index 361 and has 370 letters with the intended XLAYERTWO ending. These inputs are never conflated.

Each experiment gives the API only 23 plaintext letters: the first 15 and the last 8, at their correct positions. The published key and correct period are withheld from the recovery API; all periods 1 through 24 are tested. This is a known-answer benchmark designed by an author who knows the answers, not a blind historical decipherment. Its crib selection is not a claim about the clues available to the original solvers.

| Fixture | Models tested | Crib comparisons | Retained candidates | Withheld plaintext letters |
| --- | ---: | ---: | --- | ---: |
| K1, 63 letters | 24 | 302 | 1 complete key | 40 |
| K2 as inscribed, 369 letters | 24 | 343 | 2 complete keys, 5 partial keys | 346 |
| K2 corrected, 370 letters | 24 | 345 | 2 complete keys, 5 partial keys | 347 |
| K3 route family, 336 letters | 46 distinct routes | 71 | 1 distinct route | 313 |

K1 recovers PALIMPSEST and all 63 plaintext letters; declared periods 10 and 20 merge. Both K2 variants recover ABSCISSA and the entire expected plaintext; declared periods 8 and 16 merge. They also admit the complete period-15 key `ABSCISSAABSCISS` and partial period-18, 20, 22, 23, and 24 keys. Therefore these particular K2 cribs do not uniquely recover the message within the tested family. Exact re-encryption of a candidate is necessary but does not remove that ambiguity.

K3 tests all ordered pairs from widths `2,3,4,6,7,8,12,14,16,21,24,28`: the divisors of 336 between 2 and 28. Each stage fills rows left to right, then reads columns right to left and top to bottom. The 144 pair labels reduce to 46 distinct permutations. One surviving permutation recovers all 336 letters; it has four aliases: decryption widths `(8,24)`, `(12,16)`, `(16,12)`, and `(24,8)`. This verifies route recovery within that explicitly supplied family. It does not uniquely recover the pair of width parameters or establish Sanborn's historical construction. The reused reference and historical caveat are in `research/k3_reference.py` and `docs/LAYER_SOURCES.md`.

The first local benchmark check completed in about 0.12 seconds in one process. All 118 distinct models completed, using 1061 crib comparisons, with all input SHA-256 hashes unchanged. Twelve narrow unit tests cover independent Vigenere recovery, both route positions under all three cipher conventions and both alphabets, non-involutive permutations, uncertainty, canonical periods, overlapping cribs, witnesses, route aliases, and atomic work limits. These results establish implementation behavior on the stated controls; they do not identify the K4/K5 method, rank authenticity, or eliminate other families.

## Reproduction and dependencies

From the project root:

```powershell
python -m unittest discover -s tests -p test_recovery.py -v
python research/recovery_benchmarks.py --output PATH_TO_NEW_RESULT_JSON
```

The benchmark imports only `kryptos/recovery.py`, `kryptos/ciphers.py`, and `research/k3_reference.py` plus the standard library. It hashes those three files and its own script before and after execution, records Python/platform/workers, declared ranges, results, and elapsed time, and rejects output paths that overwrite those inputs. Fixtures are embedded in the benchmark script; no network access is used during execution. Tests additionally depend on `tests/test_recovery.py`. A separately recorded bounded run can be treated as canonical evidence; the initial local checks produced console output only. Existing application modules, data, and pinned research files were read but not changed.
