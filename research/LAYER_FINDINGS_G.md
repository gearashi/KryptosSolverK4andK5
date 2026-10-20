# Checkpoint G: alphabet changes and arbitrary substitution tables

Base: K4-20261012-F. The objective remains an authenticated K4/K5 decipherment; it has not been achieved. This checkpoint extends the user's two-substitutions-plus-transposition hypothesis. All computations retain the original 97-letter K4 ciphertext and 24 literal crib letters. No language score or word-abbreviation replacement is used.

## Changing the alphabet between additive stages

The [mixed-alphabet solver](mixed_alphabet_constraints.py) permits each substitution to use its own fixed alphabet. This scan chooses independently from ordinary A–Z and KRYPTOS, giving four ordered alphabet pairs. It fixes the previous 29 routes, all three placements of the transposition, and key-length pairs (3,2), (2,3), (10,8), (8,10). Keys are otherwise arbitrary. This gives **1,392 parameter records**, of which 696 switch alphabets and 348 repeat previously checked KRYPTOS/KRYPTOS cases.

**All 1,392 contradict the cribs.** [Results](runs/mixed-001/results.json) and the [validated manifest](runs/mixed-001/manifest.json) preserve every root trial and its certificate. An [independent audit](audit_mixed_results.json), which imports no solver code, reconstructed all 33,408 crib equations, checked 3,116 components, replayed 78,086 rejected-root certificates, and verified 2,930 accepted component assignments. Every whole model has a failed component. The source data and code hashes remained unchanged.

The exact reduction is explained in [mixed_alphabet_math.md](mixed_alphabet_math.md), with an independent derivation and hand example in [mixed_alphabet_audit.md](mixed_alphabet_audit.md). Each crib gives a bijection between two key-slot values. Once one slot in a connected component is chosen, every other slot is forced; there are only 26 root values to test. This covers all keys of the stated lengths without a keyword search.

The independent toy example also prevents a false inference: with different alphabets, one connected constraint graph can admit two distinct complete plaintexts. Connectedness alone does not establish uniqueness.

Historically, K1 and K2 use the same KRYPTOS alphabet. Different alphabets are an explicitly added modeling alternative, not evidence about Sanborn's method. This scan does not exclude other alphabets, periods, transpositions, row resets, padding, feedback, or different cipher families.

## Removing the alphabet assumption entirely

Next, allow each repeating phase in each substitution stage to use an arbitrary bijection of A–Z. This includes many systems outside K1/K2. Only the 29 routes, three stage orders, and four period pairs remain fixed: **348 models**. There is no alphabet-pair multiplier in this broader model.

The [first equality check](phase_pair_invariants.md) rejected 172 models. The stronger [arbitrary-table solver](arbitrary_layer_constraints.py) rejects **189** and constructs completions for **159**, including 17 additional contradictions missed by the first check.

| Key/map periods | Contradictions out of 87 | Arbitrary-table completions |
|---|---:|---:|
| (3,2) | 86 | 1 |
| (2,3) | 81 | 6 |
| (10,8) | 10 | 77 |
| (8,10) | 12 | 75 |
| Total | 189 | 159 |

Each crib equates two descriptions of its intermediate letter: the first substitution's output and the second substitution's inverse on the ciphertext. Following these equalities can force distinct inputs to one table to have the same output, which violates bijectivity. Such a contradiction excludes every choice of substitution alphabets within that route/order/period model.

The converse is also constructive here. With 24 crib equations there are at most 24 equality components. If no component violates a table's injectivity, assign a different alphabet symbol to each component and complete the partial tables to permutations. Decrypt the remaining ciphertext with those tables. This proves exact feasibility for this deliberately broad model; it does not infer the artist's tables or meaningful text. The generic implementation returns inconclusive above 26 components when this construction alone cannot decide the problem.

The reduction received independent mathematical review. The [bounded scan](check_arbitrary_layers.py) independently recomputed all 348 classifications using a graph on crib observations instead of the solver's union-find variables. Every positive representative passed full literal re-encryption and all 24 cribs. Five previous additive-model fits passed as positive controls. [Results](runs/arbitrary-001/results.json) and the [validated manifest](runs/arbitrary-001/manifest.json) retain the complete evidence.

The 159 broad fits do not contradict the 1,392 additive-model exclusions: arbitrary tables are more flexible than cyclic shifts in a fixed alphabet. Their representative plaintexts are artificial completions and provide no decipherment evidence.

## Research decision

Changing between the two tested alphabets does not rescue the selected key-length models. For 189 route/order/period combinations, even arbitrary substitution tables cannot work. The 159 surviving broad models show exactly where the released letters alone leave substantial freedom.

The next useful input would constrain that freedom: an independently justified alphabet/table family, a different justified transposition, or authenticated additional plaintext/ciphertext. Merely generating more arbitrary completions supplies no new evidence. Other key lengths and cipher families remain open. The ENE/BC semantic hypothesis also remains open because none of these tests concerns interpretation after decryption.

The source review gives no precise alphabet, time, bearing origin, or extraction rule from the World Clock/message-delivery statements. K5's shared BERLINCLOCK feature may become useful if authenticated K5 ciphertext becomes available; similar coding does not establish a shared keystream. No such ciphertext was obtained in this checkpoint.

All runs used one Python process and took seconds. Full application tests and large CPU/GPU searches remain deferred pending the requested confirmation that n5_runner was interrupted. No K4/K5 solution or external verification submission was made.
