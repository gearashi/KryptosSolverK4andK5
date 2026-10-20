"""Freeze bounded checkpoint-K protocols before canonical execution."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research.alphabet_propagation_K import INPUT_PATHS as ALPHABET_INPUTS
from research.scheduled_layers_K import SOURCE_PATHS as SCHEDULED_INPUTS
from research.hard_controls_K import input_paths as hard_inputs,contract as hard_bounds
from research.search_runtime_K import INPUT_PATHS as RUNTIME_INPUTS


def write(name,assertion,domain,conventions,paths,bounds,nonclaims,seed=None):
    paths=sorted(set(paths)|{p.relative_to(ROOT).as_posix() for p in (ROOT/"kryptos").glob("*.py")}
        |{"research/prepare_K_contracts.py","research/run_checkpoint_K.py"})
    assert all((ROOT/p).is_file() for p in paths)
    value={"claim_id":"K4-20261013-K-"+name,"mathematics":{"assertion_tested":assertion,
        "coefficient_domain":domain,"conventions":conventions,"inputs":paths,"bounds":bounds,"non_claims":nonclaims},
        "execution_artifacts":paths,"software":[{"name":"Python","version":"3.14.5"}],
        "randomness":{"used":seed is not None,"generator":"Python random.Random" if seed is not None else "","seed":seed}}
    with (ROOT/"research"/("K-"+name+"-contract.json")).open("x",encoding="utf-8") as stream:
        json.dump(value,stream,indent=2)


nonclaims=["No authenticated K4/K5 decipherment","Finite specified models only; no global cryptanalytic exclusion"]
write("joint","Joint unknown column order and repeating key agree with finite direct controls; fixed18-model K4 bank reports bounded outcomes.",
      "Exact matching and modular key equations over Z/26","Encryption order ST or TS, ragged occupied cells, labeled column/key assignment counts.",
      ["research/joint_columnar_K.py","research/source_snapshots/sculpture-J/pk2_fixture.json"],
      {"controls":10,"K4_models":18,"widths":[7,8,10],"periods":[2,3,4],"orders":["ST","TS"],
       "per_K4_model":{"max_states":20000,"max_segmentations":128,"seconds":1,"stored_candidates":3},"outer_seconds":45},nonclaims)
write("scheduled","Shared and scheduled keys and mixed known alphabets agree with independent finite controls; fixed18+8 K4 models are classified within explicit caps.",
      "F2/F13 linear systems and finite cyclic substitution constraints","Shared keys mean identical letters; gather output[j]=input[permutation[j]]; source/current coordinate frames explicit.",
      SCHEDULED_INPUTS,{"controls":4,"scheduled_K4_models":18,"mixed_K4_models":8,
      "mixed_per_model":{"max_nodes":2000,"max_relation_checks":750000,"max_distinct_plaintexts":1000,"seconds":3},"outer_seconds":90},nonclaims)
write("alphabet","Supported matching edges agree with exhaustive small graphs and old-solver/direct-alphabet finite counts.",
      "Finite bipartite matching and modular alphabet equations","No unit-scaling quotient; preserve checkpoint-J counting and gauge conventions.",
      ALPHABET_INPUTS,{"all_square_graph_sizes":[1,4],"graphs":66066,"finite_positive_or_ambiguous_cipher_cases":12,"impossible_cipher_cases":3,"outer_seconds":30},nonclaims+["No K4 target scan"])
write("hard-controls","Frozen multilingual ranking is tested on ten crib-compatible families with17576 completions each, including deliberate nulls.",
      "Z/26 additive families; unchanged floating-point masked trigram scores","Five independent-author later windows; same five-model maximum and lexical tie rule for positives and nulls.",
      hard_inputs(),{**hard_bounds(),"outer_seconds":180,"workers":1},nonclaims+["No probability estimate, threshold fitting or K4 scoring"],2026101306)
write("runtime","Lazy and dense exact scores agree on676-point controls; natural/adaptive searches agree with independent brute force on20 frozen graphs.",
      "Nonnegative integer product objectives","Tie break in original coordinate order; duplicate identical factors retained through powers.",
      RUNTIME_INPUTS,{"ngram_family_size":676,"merged_window_family_size":676,"random_graphs":20,"binary_variables":8,"factors_per_graph":10,"outer_seconds":75},
      nonclaims+["Adaptive branching is not guaranteed faster; no K4 search"],20261013)
write("runtime-audit","Independent literal objectives verify lazy upper bounds, interrupted/resumed frontiers, tie rules and serial/CPU-worker agreement.",
      "Finite exact integer products","Full unknown partial assignments; checkpoint source and problem identities; relative paths use caller directory.",
      ["research/search_runtime_audit_K.py"],{"tiny_objectives":2,"global_partial_bounds":63,"local_partial_bounds":126,"capped_searches":20,"max_workers":2,"outer_seconds":30},
      nonclaims+["Checkpoint hashes detect accidental changes, not malicious coverage forgery"])
unit=json.loads((ROOT/"research/J-unit-contract.json").read_text())["execution_artifacts"]
write("unit","All available unit tests pass for the frozen checkpoint-K package.","Exact finite controls and declared numerical comparisons",
      "Includes old regressions and all new modules; temporary files isolated and removed.",unit+[p.relative_to(ROOT).as_posix() for p in (ROOT/"tests").glob("*.py")],
      {"outer_seconds":90,"maximum_CPU_workers":2},nonclaims+["No GPU/dashboard/BOINC test"],"Literal fixed test seeds; UUIDs name temporary files only")
write("cli","All six new commands and a stopped/resumed CLI search produce replayable saved results.","Finite cipher constraints and exact score products",
      "Complete candidates replay independently; canonical inputs are not replaced; outputs use fresh paths.",
      ["research/verify_K_cli.py","examples/joint-ragged.json","examples/scheduled-shared.json","examples/mixed-shared.json",
       "examples/alphabet-cycle.json","examples/optimize-lazy.json","examples/batch-lazy.json",
       "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"],
      {"commands":8,"maximum_CPU_workers":2,"outer_seconds":60},nonclaims)
