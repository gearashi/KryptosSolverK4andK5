# Q71-90: explicit geometry, language and K5 models

These twenty proposals now have bounded implementations exposed through
`kryptos.model_lab.run`. They are optional research methods. None supplies a
dictionary, unknown K5 text, physical measurement, or authenticated Kryptos
mechanism. A successful result is complete only within its declared finite
input model. A resource limit raises an error without an exhaustive verdict.

The dispatch request is `{ "method": "...", "parameters": { ... } }`.
All inputs are JSON data; these methods do not read caller-supplied paths or
contact services. Coordinate/crib positions are zero-based. Geometry supports
1 through 256 occupied cells, including full K4-length requests; a 97-cell
control verifies this bound. The geometric examples use transcription ordinals,
not measured three-dimensional positions.

## Item-by-item outcome

| Item | Implemented method | Verified result and limit |
| --- | --- | --- |
| 71 | `geometry`: Hamiltonian path CSP over explicit occupied cells | On the 2x3 control, 120 complete permutations reduce to 3 complete neighbour-respecting routes. This is a conditional geometric family, not a reduction valid for arbitrary gathers. |
| 72 | Residual connectivity rejection | 3x4 fixed-endpoint decisions fall 33 to 28; all four routes survive. Extra graph checks are counted. |
| 73 | Residual endpoint/degree constraints | Same control: 33 to 12 decisions, 161 to 53 prefix states. |
| 74 | Articulation removal limits and mandatory-bridge component-chain test | Same control: 33 to 12 decisions, 161 to 52 states. These are necessary tests, not a sufficient feasibility certificate. The bridge test has no separately demonstrated advantage over articulation on these fixtures. |
| 75 | `geometry_frontier`: edge-frontier degree/connectivity transfer DP | Exact counts and one literal path witness agree on all six controls. On 3x4, four full route checks are replaced by 148 edge transitions, 75 stored states and one witness replay. It does not enumerate every route or rank plaintexts. |
| 76 | `geometry_meet`: disjoint visited-set joins of endpoint half-paths | 3x4 decisions 33 to 32, with 110 half states and 63 join lookups. Several smaller controls are worse. Keep selectable, not preferred automatically. |
| 77 | Prefix crib/key propagation | Positive 3x4 control: 17 postfiltered routes reduce to 8 completed routes, preserving exactly the eight literal matches. A contradictory control rejects before any completion. |
| 78 | Verified label-preserving D4 prefix symmetry | Eight 3x3 centre-start routes become one representative; applying reported automorphisms reconstructs all eight. Distinct letter labels disable nonidentity maps. Counts are orbit counts, not labelled-route counts. |
| 79 | `turn_grammar`: freeze observed turn/pair rules, then propagate during routes | Three completed control routes reduce to one, matching literal postfiltering. Grammar transfer from solved passages is an explicit additional hypothesis. |
| 80 | `tableau_registrations` and shared registration/key states in `geometry` | Rigid signed-permutation matrices and offsets compile against explicit tableau cells; missing cells reject a registration. Three registration hypotheses would perform 51 full route checks; shared search completes four routes with 20 prefix registration checks. Equal offset vectors preserve every alias. This does not infer the actual physical registration. |
| 81 | `language_lattice`: exact boundary/tag Viterbi DP | Nine complete enumerations agree. The six-A, no-switch control has 215 complete segmentation evaluations; the DP uses 23 states and 53 transitions, then replays one optimum. Unknown characters remain possible. |
| 82 | `morphology`: finite stem/class/suffix compilation plus tag-transition scoring | Explicit class licensing and derivation scores verified. This provides conditional language guidance; no separate search-decision reduction is claimed for the compiler itself. |
| 83 | Bounded language switching in `language_lattice` | Zero, one and two switches match independent complete enumeration. The two-switch six-A control replaces 934 complete segmentation evaluations with 55 states and 164 transitions. This optimizes an explicit multi-language objective. |
| 84 | `verify_seeds`: replay chat suggestions and check literal cribs | Valid control accepted; wrong ciphertext/crib proposals rejected. This is a verified seed gate, not an implemented LLM service or a measured incumbent-search win. |
| 85 | `codebook`: finite word/output transducer with merged equivalent prefixes | Twelve-A control: 927 completed tokenizations become 60 distinct output evaluations; 274 transitions and 36 initial match checks are counted. ENE/BC mapping works only as an explicit additional interpretation. Literal cipher cribs remain untouched. |
| 86 | Exact suffix projections for length, inventory and modular counts | Twelve-A contradictory inventory control reduces 60 complete output evaluations to zero, paying 156 suffix transitions. Feasible length control reduces prefix states 31 to 5 but still checks one completed output. Filters have no benefit without selective constraints. |
| 87 | `source_keys`: letters/initials, reversal and stride transducers, then primitive-period quotient | Six explicitly sourced transforms become three distinct repeating keys, retaining source text hashes and aliases. Quotient applies to repeating-key semantics only. |
| 88 | `robust_rank`: fixed minimum or sum of scaled integer corpus objectives | Explicit two-corpus ranks and duplicate aliases verified. This changes the declared scoring objective; it is not evidence that robustness alone reduces search decisions. Four input aliases cause three distinct text evaluations. |
| 89 | `joint_cribs`: independently sourced extraction constraints pulled back to K4 positions | Literal index witnesses and conflict tests verified; translated constraints feed `geometry` before completion. The synthetic contradiction eliminates all 17 postfiltered routes. Empty independent evidence is rejected; independence is a caller assertion, not authenticated by this code. |
| 90 | `extractions`: source-traceable index extraction bank, quotient by output | Three rules yield two distinct outputs with full mappings and all rule witnesses. Shared downstream evaluation is possible; raw gather work is still counted. |

## Evidence

The frozen pre-experiment contract is `research/phase_Q_models_contract.json`.
`research/audit_Q_models.py` contains the independent literal control routines.
`research/run_Q_models_audit.py` records input hashes and outputs using the
installed computation-audit runner. The current completed record is
`research/runs/release-Q-models-003/manifest.json`, with its `result.json`.
Earlier completed runs 001 and 002 are preserved; later additions strengthened
positive controls, tableau compilation, and complete-output work accounting.
Their inputs are older revisions and their manifests must not be presented as
hash matches to current source.

Run the current finite audit in a fresh directory with:

```text
python -B research/run_Q_models_audit.py --runner PATH/TO/computation-audit/scripts/run_experiment.py --output research/runs/NEW-DIRECTORY
python -B -m unittest discover -s tests -p test_model_lab_Q.py -v
```

All **18 tests pass**. This includes all 63 nonempty 2x3 subgraphs against full
permutation enumeration; frontier counts and meet joins checked for every
possible fixed endpoint in that domain; all 511 nonempty 3x3 subgraphs against
independent literal prefix enumeration; singleton, impossible, budget, distinct
labels, unknown words, duplicate aliases and contradictory-constraint controls.
The experiment checks six geometry fixtures, nine language fixtures, fifteen
codebook comparisons and the other numbered controls.

The arithmetic and invariant review here is a **self-review**, supported by
independent algorithms, not an independent reviewer. Graph connectivity is
necessary because a completion must visit the entire residual graph. Removing
a path endpoint leaves at most one component; removing an internal path vertex
leaves at most two. Every graph bridge must be used, so the bridge-component
tree must be a path whose leaf blocks contain the specified endpoints. The
frontier DP checks final degrees on forgetting vertices, prevents cycles, and
rejects prematurely closed components. Language DP merges prefixes only when
position, last tag, language and switch count agree. Codebook DP merges only
identical source-position/output-prefix pairs, retaining exact multiplicities.
Suffix count projections are necessary rather than sufficient and are checked
against literal enumeration. Geometric symmetry requires explicit coordinate,
endpoint and label preservation; a turn grammar conservatively disables it.

## Examples

`examples/model-lab-geometry.json` demonstrates exact orbit reduction.
`examples/model-lab-codebook.json` is the user-suggested ENE/BC interpretation.
`examples/model-lab-language.json` demonstrates unknown-character fallback.
`examples/model-lab-k4-first-four.json` uses only K4's first four ordinal cells
and ciphertext `OBKR`, pinned in `research/sculpture_layout.json`; it is a tiny
coordinate/launcher control, not a full K4 search or a claim about its route.

Do not automatically enable conditional models to make a search look easier.
The topology checks preserve their declared geometric family, while grammar,
language, codebook and K5 assumptions define additional families. All work and
assumptions remain visible in returned JSON.
