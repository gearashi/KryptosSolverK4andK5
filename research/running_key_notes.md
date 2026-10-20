# K3 running-key inventory filter

The [reviewed running-key proposal](https://www.reddit.com/r/KryptosK4/comments/1vxgnup/beaufort_or_inverse_quagmire_iii/)
motivates a new bounded model bank, not a claim about Sanborn's method. The local
known-answer K3 fixture supplies the exact 336-letter plaintext, including its
spelling and final Q. No alternative source text is silently substituted.

The fixed bank consists of all **240** contiguous, nonwrapping windows of length
97, each forward and reversed, with the standard and KRYPTOS alphabets and three
equations. This is **2,880 parameter combinations**, possibly including equivalent
models. A reversed window covers the same one-based start/end source interval,
read from end to start. The key is consumed once at the original plaintext
positions, without cycling or a keyword repetition assumption.

For alphabet indices 0–25, compute the intermediate symbol `Z_i` using one of
`P_i+K_i`, `K_i-P_i`, or `P_i-K_i`, modulo 26. The ciphertext is any permutation
`C=T(Z)`. Each known plaintext symbol therefore forces a particular intermediate
symbol. If the cribs force more copies of a letter than occur in C, **every**
permutation contradicts this model. The output stores a direct deficit witness:
letter, required and available counts, excess, and original plaintext positions
forcing that letter. It also stores every model's forced inventory and the total
excess over all letters.

This condition is both necessary and sufficient for *arbitrary* completion under
the stated model: when no count is overdrawn, put the remaining ciphertext
multiset into the unknown intermediate positions, invert the chosen substitution
at each position to get the remaining plaintext, and match equal symbols to build
a permutation. It says nothing about whether the result is English or the
permutation follows the sculpture. That flexibility makes passing a weak result.
The test does not inspect or choose a transposition.

The ordering matters. `C=S(T(P),K)` consumes the running key at different positions
and is **not covered**. Neither are arbitrary key texts, wrapping, additional
layers, nulls, changed spellings, keyed alphabets beyond the two stated ones,
K3 ciphertext as key, or K5.

Independent hand controls spell out all three equations with a nonidentity gather
permutation, exact positive/negative inventory witnesses, KRYPTOS-alphabet vectors,
and a varying key that checks plaintext-position indexing. They do not import the
layer solver or generate expected outputs with the tested equation function.
The full run checks source hashes before and after and stores the materialized
ciphertext, cribs, K3 plaintext, equations and alphabets with a resolved-input hash.

Exact source inputs for a runner manifest:

```
kryptos/data.py
research/k3_reference.py
research/running_key_probe.py
```

Small hand controls, without scanning K4:

```powershell
python research/running_key_probe.py --self-test
```

Full fixed filter, to a fresh path under the bounded experiment runner:

```powershell
python research/running_key_probe.py --output research/runs/running-key-001/results.json
```

The runner may call `analyze()` directly. No flags expand the model bank. A
failure to fit excludes only the fixed model; a fit is not a decipherment.
