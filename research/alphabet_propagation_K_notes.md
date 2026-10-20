# Supported-edge alphabet propagation, checkpoint K

`kryptos/alphabet_propagation.py` is a separate upgrade of the checkpoint-J solver. The pinned J implementation is unchanged. The new API `recover_cyclic_alphabet` preserves its signature, supplied absolute indices, modular cipher equations, rotational gauge, handling of unused key phases, complete-assignment count convention, witness replay, storage caps and censored-result semantics. It adds supported-edge filtering for the alphabet's all-different constraint. No unit-scaling quotient is applied, so assignments related by such a scaling remain separately counted, exactly as in J.

## Why the pruning is exact

The alphabet domains form a square bipartite graph: one variable per letter and one possible value per index. First find a perfect matching M. If none exists, no complete alphabet can satisfy the domains. If M exists, form a directed graph on variables with an arc from variable v to the M-owner of each value in v's domain. An unmatched edge belongs to some perfect matching precisely when this arc is on a directed cycle, equivalently when its endpoints belong to the same strongly connected component. Matched edges give self-arcs and always survive.

For necessity, the symmetric difference of two perfect matchings decomposes into alternating cycles. For sufficiency, reversing the matching edges along such a cycle constructs a perfect matching containing the proposed edge. Therefore removing edges outside these components removes no feasible complete alphabet. Filtering supports the all-different constraint alone; modular constraints and search remain necessary. It is stronger than testing only matching existence, but its extra work does not guarantee lower wall-clock time on every instance.

The public helper `all_different_support(domains)` accepts 1–26 integer bitmasks for a square domain graph. It returns the original and filtered domains, a perfect matching and SCC identifiers when feasible, removed-edge counts and matching/SCC work counters. The cipher solver records up to three actual pruning witnesses, aggregate pruning work, and its other search statistics. A Hall-set example `[3,3,15,15]` becomes `[3,3,12,12]`: no input is a singleton and a perfect matching already exists, so the stronger inference is visible.

## Frozen verification scope

Seven narrow unit tests passed, including every domain graph of size 1, 2 and 3, independent brute-force matching support, Hall-set pruning/contradiction, unchanged exact cipher counts/storage caps, absolute indices, Beaufort's nonunit coefficient, and truncation semantics.

`research/alphabet_propagation_K.py` extends the graph audit to **all 66,066 square domain graphs of sizes 1 through 4**, including empty domains. For each graph, an independent enumerator visits every index permutation and computes the exact supported edges. It then compares twelve fixed planted/ambiguous cipher controls against both the J implementation and exhaustive enumeration of the 24 possible permutations of four unfixed alphabet letters. Three fixed impossible controls cover Vigenère, Beaufort and variant Beaufort. Every saved cipher witness is independently re-encrypted through the existing recipe replayer.

The result preserves full benchmark witnesses, state/revision/work counts and before/after input hashes. Counts refer to complete alphabets and message-used key phases after the stated rotational gauge, not distinct plaintexts. The audit does not run a K4 scan or claim that an alphabet witness authenticates a solution.

```text
python -B -m unittest discover -s tests -p test_alphabet_propagation.py -v
python -B research/alphabet_propagation_K.py --output research/runs/alphabet-K-NEW/results.json
```

`INPUT_PATHS` in the runner supplies its five direct code dependencies. Use a fresh result path and an outer 30-second cap. The parent records the canonical full run separately; these notes do not fabricate that result in advance.
