# Phase O engine acceptance contract

This plan precedes the development experiments. Primary improvements are fewer
objective evaluations or search decisions for the same independently verified
answer; wall time is descriptive only. All new heuristic/pruning/bound options
default off and no universal improvement is claimed.

1. Coordinated moves: exact two-coordinate deltas on factors with zeros, powers,
   nonstandard alphabet and unused coordinates. An explicitly coupled two-bit
   barrier embedded in a larger binary domain is the positive discriminator;
   an independent-singleton problem is the negative/control case. Compare exact
   objective evaluations to a fixed contiguous enumeration budget. Verify every
   retained point using the original complete product.
2. Mini-bucket bounds: independently enumerate every residual completion in
   seeded small binary/ternary graphs, including constants/zeros/powers. Every
   reported upper bound must dominate the true maximum. Caps must return no
   bound, never an exclusion. A contradictory cycle of equality/inequality
   factors is the correlated-bound discriminator; report any case where the
   additional work does not reduce search decisions.
3. Ranked joint search: independent exhaustive permutations and keys on at most
   three occupied columns and periods one/two, both layer orders, all three
   equations, repeated plaintexts, ragged cells and standard/swapped alphabets.
   Compare distinct-text top-k, all exact score ties and selected recipes. A
   frozen unigram model concentrated on one symbol is the pruning discriminator.
   Score-pruned compatible assignments must never appear as enumerated coverage.
4. Continuation: resume with tiny state/evaluation/order caps until exhausted;
   compare cumulative evaluated counts, distinct-text top-k and exact recipes to
   an uninterrupted run. Tampered hashes, changed model/mask/source/parameters,
   malformed tasks, and duplicate JSON keys must be rejected. A cutoff restores
   unfinished work and never marks it complete. No checkpoint executes code.

Development controls are single-process and small. Canonical source-pinned
audits follow only after the parent declares a source freeze. Historical audits
remain unchanged. This contract does not claim Kryptos authenticity or test a
new K4 search bank.
