# Bounded coordinate-fractionation alternative

Base checkpoint **K4-20261012-H**. This addition explores a defined new family; it is not a claim that K4 uses it. Gillogly's hypothetical fractionation/substitution/transposition example is distinguished from an actual K4 method in [LAYER_SOURCES.md](../docs/LAYER_SOURCES.md). No further external algorithm or historical claim is needed for the definition below.

## Definition and rectangular-grid issue

An alphabet of length `R*C` fills an `R`-row, `C`-column grid in row-major order. Split the text into blocks of at most `period` letters, starting at position zero. For a block of length `n`, collect the row digits followed by the column digits.

Simply pairing that concatenated list is unsafe on a rectangle: a column digit may exceed the row range. For example, on a 2x13 standard-alphabet grid, CA yields grouped digits `0,0,2,0`; interpreting the second pair as row 2, column 0 is invalid. The implementation rejects out-of-range digits in its rank primitives and never folds an invalid coordinate modulo the grid dimensions.

The explicitly chosen **mixed-radix extension** instead treats the grouped digits in radices `[R]*n + [C]*n`, ranks them as an integer, and unranks the same integer in radices `[R,C]*n`. The output is consequently a valid sequence of grid coordinates. This changes digit values through radix conversion; it is not ordinary rectangular digit shuffling. On a square all radices coincide, so it reduces to direct coordinate regrouping. The final short block uses its actual length, with no padding. Text is not normalized and no I/J merge occurs.

Both radix products equal `(R*C)**n`. Ranking and unranking are bijections on their full finite domains, so reversing the conversion gives an exact inverse for every input block. This is a mathematical definition and proof of reversibility, not historical evidence for the rectangular construction.

An independent formulation used by the probe encodes the row stream in base R and the column stream in base C. It computes `V = row_code * C**n + column_code`, then writes V as n base-`R*C` output symbols. This avoids the production interleaved-digit helpers.

## API and bounded probe

`kryptos.fractionation.fractionate_encrypt` and `fractionate_decrypt` accept text plus keyword arguments `alphabet`, `rows`, `columns`, and `period`. Defaults are the standard alphabet, 2x13, and period 5. Empty text returns empty text; malformed alphabets, invalid symbols, nonpositive periods/dimensions, and invalid digits raise `ValueError`.

The probe uses only the fixed standard and KRYPTOS alphabets, dimensions 2x13 and 13x2, periods 1 through 97, and both transform orientations: **776 direct transformations**. It checks the 24 original K4 crib letters. It does not add another substitution, route, offset, padding convention, unknown alphabet or language score. Each rejection records a first mismatching crib position, and every candidate is round-tripped and checked by the independent rank formula. Equal candidate outputs are counted separately from model parameters; equality on this one input is not proof of globally equivalent functions.

```text
python -m unittest discover -s tests -p test_fractionation.py -v
python research/fractionation_probe.py --output <fresh-result-path>
```

The probe records before/after hashes of its source, backend and data. An outer bounded runner can supply the standard execution manifest. The unit tests include independent hand values, direct square-grid regrouping, invalid rectangular coordinates, exact bijectivity on all 676 two-letter blocks for both rectangle orientations, custom alphabets, short blocks, and strict symbol handling.

Scope limits: a negative result excludes only this direct, fully specified parameter bank. It does not exclude all Bifid-like systems or fractionation combined with other layers. A 25-symbol grid cannot directly output a ciphertext containing 26 distinct symbols; that elementary alphabet-size check does not exclude a later outer layer with different encoding rules. K5 has no supplied ciphertext here and is not tested.
