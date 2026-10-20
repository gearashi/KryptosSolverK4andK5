# Fixed running key after transposition

Prepared contract, base **K4-20261012-H**. This complements the saved `research/running_key_probe.py` model without modifying its code, run, or interpretation. The earlier probe tests `C=T(S(P,K))`. This runner tests **`C=S(T(P),K)`**, with the same fixed K3-derived key bank. Changing order is substantive when key symbols differ by position; it is not a new language-score or key-window tuning step.

## Exact model and decision

Let `T(P)[j]=P[pi[j]]` for any bijection `pi` of positions. All symbols use the same selected standard or KRYPTOS alphabet. The complete fixed key is consumed at **ciphertext/output positions `j`**, after the route. Put `Y=T(P)` and invert substitution at every position:

| Forward equation | Inversion fixing the entire `Y` |
|---|---|
| `C[j] = Y[j] + K[j] mod 26` | `Y[j] = C[j] - K[j] mod 26` |
| `C[j] = K[j] - Y[j] mod 26` | `Y[j] = K[j] - C[j] mod 26` |
| `C[j] = Y[j] - K[j] mod 26` | `Y[j] = C[j] + K[j] mod 26` |

For each letter, count its occurrences among the 24 known plaintext positions and in `Y`. A deficit rejects **every** transposition under this exact key/alphabet/equation: a bijection cannot supply additional instances of a letter.

Conversely, absence of every deficit is sufficient for an *unrestricted arbitrary completion*. Allocate different matching positions of `Y` to each known plaintext position; fill unknown plaintext positions with all remaining `Y` symbols. This constructs a full gather permutation and its inverse. It does not restrict the route to sculpture geometry, a historical K3 transform, a readable plaintext, or an independently justified rule. The implementation saves this arbitrary completion on every pass and verifies both route directions plus literal re-encryption.

## Declared finite bank

Use `K3_PLAINTEXT` exactly as stored in `research/k3_reference.py`: 336 uppercase letters, including its retained spelling and final letters. The target and one-based released cribs come from `kryptos/data.py`.

- Every nonwrapping length-97 source window: starting positions 1 through 240 inclusive.
- Read each window forward or reverse its 97 characters.
- Standard A–Z or the stored KRYPTOS alphabet, consistently for input/key/output symbols.
- All three equations above.

Total: `240 * 2 * 2 * 3 = 2,880` parameter combinations, with 279,360 positionwise substitution inversions in the main run. Parameter combinations can be equivalent; this is not a count of statistically independent hypotheses. No cyclic wrapping, source edits, alternate offsets, transposition search, score threshold, additional layer, or invented K5 input is included.

## Saved evidence

Every model record includes its exact source endpoints/direction, alphabet/equation and key hash, the full inverted `Y`, available/required letter counts, **all** deficit certificates, and total deficit. Each certificate identifies required plaintext positions and the available intermediate positions. Thus an independent auditor can derive the key from the materialized K3 source, invert each ciphertext symbol, and replay every rejected inventory inequality.

Passing records additionally include one deliberately arbitrary complete plaintext, zero-based gather and inverse permutations, re-encrypted ciphertext, and verification flags. Unknown plaintext positions are filled in ascending unused-output order; there is no language preference. The global result records resolved inputs and their hash, before/after source hashes, groups/counts, validation controls, environment and scope limitations.

Input files to pin:

```text
kryptos/data.py
research/k3_reference.py
research/running_key_after_route.py
```

Only the Python standard library and those local canonical inputs are dependencies. The runner does not import the earlier probe or its results.

## Hand controls and execution

The non-involutive gather `[2,0,3,1]` has inverse `[1,3,0,2]`. With standard-alphabet `P=ABCA`, it gives `Y=CAAB`. For the unequal key `BDFH`, the three hand ciphertexts are `DDFI`, `ZDFG`, and `BXVU`. Their keyed-alphabet counterparts use `P=KRYK`, `K=RPOA`, `Y=YKKR`, producing `PPOB`, `ZPOS`, and `RWUQ`. Negative companions replace one required repeated symbol and must return the exact deficit positions and counts.

The stage-order discriminator uses the same `P`, key and gather. Substitution *before* the route gives `HBHE` under addition; substitution *after* gives `DDFI`. Inverting `HBHE` with the output-indexed key gives `GYCX`, which lacks the two known As. A constant key would hide this indexing error, so the controls explicitly use unequal key symbols.

Additional tiny controls cover partial/empty crib materialization, multiple simultaneous deficits, invalid indices, invalid key length, malformed alphabet and unknown equation.

```text
C:\Python314\python.exe -B research/running_key_after_route.py --self-test
C:\Python314\python.exe -B research/running_key_after_route.py --output research/runs/running-key-after-route-001/results.json
```

The parent task runs the full bounded filter once under its evidence runner. The script refuses an existing output file and records unchanged inputs before writing. This prepared note makes no claim about the number of full-run survivors or rejections.
