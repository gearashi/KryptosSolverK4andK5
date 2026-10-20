"""Materialize the predeclared new benchmark contracts before their runs."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research.general_layer_benchmarks import SOURCE_PATHS
from research.evaluation_J import input_paths


def write(name, assertion, domain, conventions, paths, bounds, nonclaims, random=False):
    # Pin the complete local cipher package in addition to direct benchmark
    # dependencies. Some imports are validation helpers rather than arithmetic.
    paths = sorted(set(paths) | {p.relative_to(ROOT).as_posix() for p in (ROOT / "kryptos").glob("*.py")})
    result = {"claim_id":"K4-20261013-J-"+name,"mathematics":{
        "assertion_tested":assertion,"coefficient_domain":domain,"conventions":conventions,
        "inputs":paths,"bounds":bounds,"non_claims":nonclaims},"execution_artifacts":paths,
        "software":[{"name":"Python","version":"3.14.5"}],
        "randomness":{"used":random,"generator":"Python random.Random" if random else "", "seed":20261013 if random else None}}
    with (ROOT / "research" / ("J-"+name+"-contract.json")).open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)


write("general", "Separate-prime generalized solver agrees with independent finite controls and existing complete PK3 family; exact ngram optimizer agrees with brute force; bounded8-model K4 bank reports feasibility/counts.",
      "F2 and F13 linear systems combined by CRT; exact integer factor products",
      "Encryption-order stages; gather output[j]=input[permutation[j]]. Keys withheld, supplied cribs and model families. Score excludes every ngram touching a known letter.",
      SOURCE_PATHS, {"pk3_candidates":17576,"legacy_comparisons":6,"optimizer_brute_candidates":676,"k4_period_triples":[[2,3,5],[3,5,7],[5,7,11],[7,8,9]],"k4_route_pairs":2,"k4_models":8,"cooperative_seconds":90,"workers":1},
      ["No mixed or unknown alphabets in this linear solver","No arbitrary K4 witnesses ranked","No global cipher exclusion or authentication"])
write("evaluation", "Frozen two-author-per-language models are evaluated on independent-author documents and matched controls, including identical model-bank selection on planted and shuffled ciphertexts.",
      "Exact masked ngram counts/products, finite algebraic models, deterministic pseudorandom shuffles",
      "15 public-domain books;2training and1heldout per language. Every score omits the24known positions and all crossing ngrams. No re-selection or tuning on results.",
      input_paths(), {"languages":5,"training_letters_per_book":50000,"skip_letters":5000,"heldout_windows_per_language":20,"letters_per_window":97,"shuffle_controls_per_window":8,"pipeline_positives":10,"pipeline_nulls":10,"models_per_pipeline_input":768,"pipeline_max_plaintext_dimension":0,"seed":20261013,"workers":1},
      ["Limited historical-literature sample","No solution probabilities","Higher-dimensional pipeline families excluded explicitly","No K4 target search or K5 identification","No evaluation of every prior research hypothesis"],True)
