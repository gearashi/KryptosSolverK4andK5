# Bounded research methods

Version0.6 adds a Research methods panel alongside the ordinary cipher
workbench. Choose a recorded example, inspect its JSON assumptions and bounds,
then run it. The saved result retains the original request, technique details,
witnesses, work counters and completeness status. Generic assignments and
geometric paths are not presented as authenticated plaintexts.

The [90-item record](../research/phase_Q_plan.json) links each proposal to its
implementation and evaluation. Conditional language, grid, codebook and K5
models are explicit hypotheses. The ordinary K4 workbench keeps its literal
released crib positions; an ENE/BC interpretation does not replace those clues.

The commands are also available from the command line:

```text
python -m kryptos constraint-lab --request examples/constraint-Q-affine.json
python -m kryptos factor-lab --request examples/factor-Q-conditional.json
python -m kryptos model-lab --request examples/model-lab-geometry.json
python -m kryptos grammar-lab --request examples/grammar-Q-prefixes.json
```

Add `--output NEW.json` to preserve a result. Existing output files are not
overwritten. The optional SMT example needs `Setup.cmd -Sat`; ordinary relation,
factor, grammar, geometry and language experiments use the standard library.

In the existing exact optimizer, **Additional exact factor methods** exposes
AND/OR contexts, separator messages, decision diagrams, chain/cutset algorithms,
overlap bounds and alternative branching orders. Their existing operation and
entry caps still apply. Unsupported structure or exhausted preprocessing falls
back conservatively rather than excluding a possible solution. More elaborate
preprocessing can cost more than the search saved.

Ranked joint search also supports `propagation: "relational"` and
`score_bound: "matching"`. The latter requires `pruning: "admissible"` and
falls back where no column-local scoring windows exist. All selected techniques
and their work counters remain in the saved run.

Research-method completeness concerns the declared finite model. A first-witness
grammar search explicitly leaves the rest of its recipe bank unsearched.
Resource cutoffs, a missing optional backend, and a model that does not fit
the supported domain are not cryptanalytic exclusions.
