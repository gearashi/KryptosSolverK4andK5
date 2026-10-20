# Generalized linear layers and bounded exact optimization

Base input: checkpoint I, `kryptos/data.py` SHA256
`2f143d57fa9b450b4ee9a6ef1fd2a95224b171d2a01902eeebbc4b12ad0e35b2`.
This is a finite-model implementation and benchmark protocol, not an
authenticated Kryptos decryption. No K5 input is invented.

## Exact layer model

`kryptos.general_layers.solve_layers(ciphertext, known, stages, alphabet)` takes
uppercase ciphertext and a dictionary of **zero-based original plaintext** crib
positions. The one shared alphabet may be `standard`, `kryptos`, or an explicit
A–Z permutation. Encryption stages are explicit objects:

```python
[
    {"operation": "substitution", "period": 2, "cipher": "beaufort"},
    {"operation": "gather", "permutation": [2, 0, 3, 1]},
    {"operation": "substitution", "period": 3, "cipher": "variant"},
    {"operation": "gather", "permutation": [1, 3, 0, 2]},
    {"operation": "substitution", "period": 2, "cipher": "vigenere"},
]
```

Gather means `output[j] = input[permutation[j]]`. Keys start at index zero at
their own substitution stage. Vigenere uses `P+K`, Beaufort `K-P`, and variant
`P-K`, all modulo 26. Each substitution has a separate unknown periodic key.
Mixed alphabets, unknown alphabets, shared-key identities between stages, and
arbitrary nonlinear substitutions are unsupported and are not inferred.

Following each original symbol through the stages gives
`C[j] = sign*P[i] + row[i]*key`, where `sign` is +1 or -1. A crib creates one
linear equation in the unknown key slots. The code solves this system separately
over the prime fields F2 and F13, retaining row-operation weights. An inconsistent
field supplies a certificate: its weighted original coefficient rows vanish,
while its weighted right sides give the reported nonzero residue. Certificate
indices refer to the `constraints` array in `summary()`.

For a consistent field, let `x0 + N*u` be the key solution and `M` the key-to-
plaintext linear map. The code retains a basis of `image(M*N)`, along with the
corresponding original key vectors. Vectors in `kernel(M*N)` change keys without
changing the plaintext and are removed from plaintext enumeration. If the two
image dimensions are d2 and d13, CRT gives exactly **2^d2 × 13^d13** distinct
plaintexts. The full key count separately uses each field's key nullity. These
arguments concern the specified linear model, without a language assumption.

A plaintext position is fixed only if both field images vanish at that position.
Otherwise the mask shows `?`; this can mean 2, 13, or 26 possible letters
marginally, so it does not automatically mean all 26 letters are possible.

The returned `GeneralLayerSolution` exposes:

- `summary()`: ranks, both dimensions, exact counts, mask, constraints,
  rejection certificates, and bounds.
- `plaintext(values2=None, values13=None)` and `keys(...)`: a plaintext and its
  representative keys; omitted coordinates mean the all-zero choice.
- `candidate(...)`: the same values with separate literal-stage re-encryption
  and crib verification. Arbitrary representatives are consistency witnesses.
- `enumerate_plaintexts(max_candidates)`: triples `(values2, values13, text)`
  once per distinct plaintext; rejects the entire request before iteration when
  the family exceeds the cap.
- `affine_plaintext()`: a base and columns modulo 26, with finite domain sizes
  2 followed by 13. This representation feeds exact score factors.

Limits: 1–16 stages; text length 1–4096; periods 1–256; default total key slots
256 (configurable only through 512); estimated matrix cells 2,000,000; scalar
algebra-work units 20,000,000. Budget failure raises `LayerBudgetExceeded`, not
an infeasibility verdict. These are storage/work bounds, not a hard time limit.

## A hand-checkable unequal-rank fixture

Use plaintext `ABCDEFGH`, three period-2 Vigenere stages, keys `BC`, `DE`, `FG`,
and two intermediate gathers:

```text
[0,2,1,3,4,6,5,7]
[0,4,2,6,1,5,3,7]
```

Take cribs only at original positions 0, 3, 5, 6. The three binary phase labels
cover all eight cube vertices. The four crib rows have labels 000, 110, 101,
011: their coefficient sum vanishes modulo 2 but not modulo 13. Their ranks are
3 and 4; the full-text ranks are 4 in both fields. Hence d2=1, d13=0. The exact
two plaintexts are `ABCDEFGH` and `AOPDRFGU`; they have 1,352 total key assignments
between them. This is a direct regression against an incorrect `26**dimension`
count, and not a claimed Kryptos pattern.

## Integer-factor optimization

`kryptos.factor_search.IntegerFactor(scope, values, name='', power=1)` stores a
complete table of nonnegative integer scores. Scope indices are sorted; tuple
keys enumerate its Cartesian domain. `optimize_product(domains, factors, ...)`
maximizes their product. The default caps are 100,000 popped nodes, 10 seconds
(checked between complete expansions), and 200,000 cached local factor bounds.

At a partial variable assignment, take each factor's maximum over its remaining
local assignments. Any full completion is no greater than each local maximum;
the product is therefore an admissible upper bound because all factors are
nonnegative. A product of maxima can ignore consistency between shared variables,
making it loose but never too small. No floating-point score comparison is used.

The incumbent is always a valid complete assignment and supplies a lower bound.
The largest frontier bound and incumbent supply the global upper bound. Node or
time interruption preserves both. `complete` says all remaining branches were
searched or pruned; `optimal` says the objective upper and lower bounds agree;
`tie_break_proven` additionally says no earlier tied assignment remains possible.
Ties use the lexicographically smallest variable tuple, **not** the smallest
plaintext. Variable branching order is the fixed index order. A finished optimum
does not authenticate the plaintext.

`ngram_problem(solution, model, excluded_positions, max_factor_entries=200000)`
uses a validated `CharacterNgramModel` trained on an explicitly supplied corpus.
It excludes every window touching a masked position, without joining gaps. All
symbols must be supported under identity or single-letter uppercase normalization.
Writing the saved alpha's exact IEEE rational as p/q, the factor value is
`count*q+p`. Length, window count and the model's probability denominator are
fixed across the candidate family, so the integer product gives the exact
probability ordering. This does not treat the decimal spelling `0.1` as 1/10.

Factor tables are preflighted; excessive dependence on many freedoms raises
`FactorBudgetExceeded` instead of omitting difficult factors. This is an important
limitation: exact optimization is not guaranteed to be cheap for a dense model.
`optimize_ngrams(...)` combines construction, optimization, literal candidate
verification, and a separately labelled floating display score. No-window scores
are marked unavailable (the neutral empty product is 1). Comparisons across
different models, languages or masks require separate calibration.

Exact scores may exceed Python's default decimal JSON digit limit for long
texts. Consumers should serialize such integers with an explicit exact encoding,
such as a tagged hexadecimal string; do not replace them with floats or alter
the global integer-parsing security limit.

## Validation and canonical run protocol

The two new unit files contain seven tests each. They cover all three two-layer
placements against the existing solver, the unequal-rank fixture, three
substitutions/two gathers with all three equations, a non-affine fixed alphabet,
full 26^3 constant-key brute force, independent rejection-certificate arithmetic,
unused keys, pure routes and resource failures. Factor tests compare overlapping
tables against brute force, check every small node budget's admissible bounds,
force a time interruption, exercise ties/zeros, and compare masked n-gram factors
with independent exact products. These are bounded implementation checks.

The canonical script is `research/general_layer_benchmarks.py`. It has a
90-second cooperative cap and before/after input hashes. Root should run it once
through the normal bounded runner:

```text
python -B research/general_layer_benchmarks.py --output research/runs/general-layers-001/results.json
```

Declare every input in `SOURCE_PATHS`. `--self-test` runs only three tiny controls;
it does not enumerate PK3 or test K4. The canonical run also checks equality with
the existing six two-layer families and all 17,576 PK3 plaintexts, re-encrypting
each generalized PK3 candidate. PK3's method and artificial crib locations are
supplied; it is not blind method discovery.

The optimizer compares one fixed 676-member synthetic plaintext family against
brute force using the already saved English model
`research/models/multilingual-001/artifacts/pg1342-english-trigram.json`. No model
training or retuning occurs. A separate 1,024-assignment unary-factor control
shows admissible pruning; its easy structure is stated explicitly.

The K4 bank is declared before execution: three Vigenere periods from
`(2,3,5), (3,5,7), (5,7,11), (7,8,9)`, and two gather pairs formed by swapping
the existing `geometry/rotate90/forward` and `rows/major0/minor0/snake1/forward`
routes on the occupied K4 grid. These are exactly eight models. Each stores
feasibility, ranks, counts and any conflict certificates. The bank performs no
candidate enumeration or language ranking and cannot exclude other routes,
periods, stage orders or cipher families. No canonical benchmark result is
asserted here before root executes it.
