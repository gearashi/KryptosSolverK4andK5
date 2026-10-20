"""Frozen bounded runtime comparison, separate from cryptanalytic success."""
import argparse
import itertools
import json
from pathlib import Path
import random
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.advanced_cli import json_safe_integers
from kryptos.factor_search import ngram_problem,product_score
from kryptos.general_layers import solve_layers
from kryptos.language import CharacterNgramModel
from kryptos.search_runtime import SCHEMA,lazy_ngram_problem,optimize_lazy
from research.search_runtime_audit_K import literal

MODEL="research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
FIXTURE="research/runs/general-J-002/results.json"
INPUT_PATHS=["research/search_runtime_K.py","research/search_runtime_audit_K.py",MODEL,FIXTURE]


def run():
    started=time.perf_counter()
    fixture=json.loads((ROOT/FIXTURE).read_text())["fixed_model_language_optimization"]
    model=CharacterNgramModel.from_json((ROOT/MODEL).read_text())
    solution=solve_layers(fixture["ciphertext"],{},fixture["stages"])
    lazy=lazy_ngram_problem(solution,model)
    dense=ngram_problem(solution,model,max_factor_entries=20000)
    expected=[]
    for point in itertools.product(*(range(d) for d in lazy["domains"])):
        score=literal(lazy,point)
        assert score==product_score(dense.domains,dense.factors,point)
        expected.append((score,point))
    truth=min(expected,key=lambda v:(-v[0],v[1]))
    rows=[]
    for ordering in ("natural","impact"):
        for local_limit in (1,64):
            result=optimize_lazy(lazy,ordering=ordering,local_exact_limit=local_limit,max_nodes=10000,time_limit_seconds=15)
            assert result["complete"]
            assert (result["score"],tuple(result["assignment"]))==truth
            rows.append({"ordering":ordering,"local_exact_limit":local_limit,**result})
    repeated=solve_layers("ABABABABABAB",{},[{"operation":"substitution","period":2}])
    merged=lazy_ngram_problem(repeated,model)
    unmerged=ngram_problem(repeated,model,max_factor_entries=20000)
    for point in itertools.product(*(range(d) for d in merged["domains"])):
        assert literal(merged,point)==product_score(unmerged.domains,unmerged.factors,point)
    assert len(merged["factors"])<merged["metadata"]["windows"]
    rng=random.Random(20261013)
    graph_results=[]
    for number in range(20):
        factors=[]
        for _ in range(10):
            scope=sorted(rng.sample(range(8),3))
            factors.append({"kind":"table","scope":scope,"values":[rng.randrange(1,21) for _ in range(8)]})
        problem={"schema":SCHEMA,"domains":[2]*8,"factors":factors}
        points=list(itertools.product(range(2),repeat=8))
        scored=[(literal(problem,p),p) for p in points]
        best=min(scored,key=lambda v:(-v[0],v[1]))
        record={"id":number,"enumerated":len(points)}
        for ordering in ("natural","impact"):
            result=optimize_lazy(problem,ordering=ordering,max_nodes=10000,time_limit_seconds=5)
            assert result["complete"] and (result["score"],tuple(result["assignment"]))==best
            record[ordering]={k:result[k] for k in ("nodes","score","assignment","runtime_seconds")}
        graph_results.append(record)
    return {"schema":"kryptos.runtime-comparison.K.v1","passed":True,"elapsed_seconds":time.perf_counter()-started,
        "ngram_fixture":{"assignment_count":len(expected),"scoring":lazy["metadata"],"searches":rows,
            "winning_plaintext":solution.candidate(truth[1][:solution.dimensions_mod2],truth[1][solution.dimensions_mod2:])["plaintext"]},
        "duplicate_window_control":{"assignment_count":676,"metadata":merged["metadata"],"distinct_factors":len(merged["factors"])},
        "adaptive_branching":{"seed":20261013,"graphs":graph_results,
            "impact_fewer_nodes":sum(r["impact"]["nodes"]<r["natural"]["nodes"] for r in graph_results),
            "impact_more_nodes":sum(r["impact"]["nodes"]>r["natural"]["nodes"] for r in graph_results),
            "same_nodes":sum(r["impact"]["nodes"]==r["natural"]["nodes"] for r in graph_results)},
        "interpretation":"Finite correctness and efficiency controls only. Adaptive branching need not always win. No K4 search or solution authentication."}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output")
    result=run()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(json_safe_integers(result),stream,indent=2)
    print(json.dumps({"passed":True,"elapsed_seconds":result["elapsed_seconds"],"adaptive":{k:v for k,v in result["adaptive_branching"].items() if k!="graphs"}}))
