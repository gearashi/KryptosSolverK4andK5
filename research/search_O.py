"""Fixed small phase O work-count controls; emit JSON at a fresh path.

Run: python research/search_O.py --output <fresh-result.json>
No K4 scan, GPU work or external inputs. Scientific assertions and caveats are
declared in search_O_acceptance.md. Timing is intentionally not a success metric.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.guided_search import guided_seeds
from kryptos.factor_decomposition import mini_bucket_upper
from kryptos.search_runtime import optimize_lazy, SCHEMA
from kryptos.joint_ranked import rank_joint_columnar
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.explanations import replay_recipe


def table(scope,values,power=1):
    return dict(kind="table",scope=scope,values=values,power=power)


def objective(problem,point):
    value=1
    for f in problem["factors"]:
        slot=0
        for v in f["scope"]:
            slot=slot*problem["domains"][v]+point[v]
        value*=f["values"][slot]**f.get("power",1)
    return value


def oracle_joint(text,width,period,model,top):
    # This oracle has no matching, phase-edge, pruning or resume implementation.
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    columns=[list(range(c,len(text),width)) for c in range(width)]
    p,q=model.alpha.as_integer_ratio()
    retained={}
    count=0
    for cols in itertools.permutations(range(width)):
        route=[i for c in cols for i in columns[c]]
        for key in itertools.product(range(26),repeat=period):
            plain=[None]*len(text)
            for j,i in enumerate(route):
                plain[i]=alphabet[(alphabet.index(text[j])-key[i%period])%26]
            plain="".join(plain)
            value=1
            for start in range(len(text)-model.order+1):
                value*=model.counts.get(plain[start:start+model.order],0)*q+p
            representation=(cols,"".join(alphabet[k] for k in key))
            if plain not in retained or representation<retained[plain][1]:
                retained[plain]=(value,representation)
            count+=1
    rows=sorted(retained.items(),key=lambda item:(-item[1][0],item[0]))[:top]
    return rows,count


def run():
    guided=[]
    for dimensions in (2,6):
        problem=dict(schema=SCHEMA,domains=[2]*dimensions,factors=[table([0,1],[2,1,1,9])])
        one=guided_seeds(problem,restarts=1,max_sweeps=3,max_evaluations=100)
        paired=guided_seeds(problem,restarts=1,max_sweeps=3,max_evaluations=100,block_size=2)
        optimum=max(objective(problem,p) for p in itertools.product(range(2),repeat=dimensions))
        first=next(i+1 for i,p in enumerate(itertools.product(range(2),repeat=dimensions)) if objective(problem,p)==optimum)
        for report in (one,paired):
            for candidate in report["candidates"]:
                assert objective(problem,candidate["assignment"])==int(candidate["score_hex"],16)
        assert int(paired["candidates"][0]["score_hex"],16)==optimum
        guided.append(dict(dimensions=dimensions,oracle_optimum=optimum,contiguous_evaluations_to_first_optimum=first,
            single_coordinate_best=int(one["candidates"][0]["score_hex"],16),single_coordinate_work=one["work"],
            coordinated_best=optimum,coordinated_work=paired["work"],oracle_match=True,
            fewer_evaluations_than_contiguous=paired["work"]["objective_evaluations"]<first))
    graph=dict(schema=SCHEMA,domains=[2]*3,factors=[table([0,1],[9,1,1,9]),table([1,2],[9,1,1,9]),table([0,2],[1,9,9,1])])
    truth=min(itertools.product(range(2),repeat=3),key=lambda p:(-objective(graph,p),p))
    baseline=optimize_lazy(graph,ordering="natural")
    bounds=[]
    for cap in (1,4,8):
        reduced=optimize_lazy(graph,ordering="natural",elimination_bound="mini_bucket",elimination_bucket_entries=cap)
        assert tuple(reduced["assignment"])==truth and reduced["score"]==objective(graph,truth)
        bounds.append(dict(bucket_entries=cap,oracle_match=True,nodes=reduced["nodes"],work=reduced["work"],
            fewer_nodes=reduced["nodes"]<baseline["nodes"]))
    rng=random.Random(60132)
    checked=0
    for _ in range(36):
        domains=[rng.randrange(2,4) for _ in range(3)]
        factors=[]
        for scope in ([],[0,1],[1,2],[0,2]):
            size=1
            for v in scope:size*=domains[v]
            factors.append(table(scope,[rng.randrange(5) for _ in range(size)],rng.randrange(1,4)))
        problem=dict(schema=SCHEMA,domains=domains,factors=factors)
        for partial in itertools.product((-1,0),repeat=3):
            true=max(objective(problem,p) for p in itertools.product(*(range(d) if v<0 else (v,) for d,v in zip(domains,partial))))
            for cap in (9,27):
                report=mini_bucket_upper(problem,partial,bucket_entries=cap)
                assert report["bound_available"] and report["upper_bound"]>=true
                checked+=1
    model=train_ngram_model([CorpusDocument("AAAAAAAAAAAAAAAAAABCDEFFEDCBA","phase-O synthetic")],label="Phase O",order=1)
    joint=[]
    for period,top in ((1,3),(2,1)):
        expected,count=oracle_joint("AAAAA",3,period,model,top)
        args=dict(model=model,period=period,width=3,alphabet="standard",top=top,max_states=1000000,time_limit_seconds=10)
        reports=[rank_joint_columnar("AAAAA",[],pruning=mode,**args) for mode in ("off","admissible")]
        for result in reports:
            assert result["complete"]
            for candidate,(text,(score,(cols,key))) in zip(result["candidates"],expected):
                assert (candidate["plaintext"],int(candidate["score_exact"],16),tuple(candidate["column_order"]),candidate["key_pattern"])==(text,score,cols,key)
                assert replay_recipe(text,candidate["encryption_recipe"])["ciphertext"]=="AAAAA"
        joint.append(dict(period=period,top=top,oracle_assignments=count,oracle_match=True,
            baseline_evaluated=reports[0]["evaluated"],pruned_evaluated=reports[1]["evaluated"],
            baseline_work=reports[0]["work"],pruned_work=reports[1]["work"],
            pruned_branches=reports[1]["pruned_score_branches"],enumeration_complete=reports[1]["enumeration_complete"]))
    # A separate bounded checkpoint control avoids adding a persistent test
    # frontier to the scientific output. Its work includes all repeated work.
    base=ROOT/"research"/"manual-checks"
    base.mkdir(parents=True,exist_ok=True)
    folder=Path(tempfile.mkdtemp(prefix="search-O-",dir=base))
    try:
        args=dict(model=model,period=1,width=3,alphabet="standard",top=3,pruning="admissible",time_limit_seconds=10)
        whole=rank_joint_columnar("AAAAA",[],**args)
        previous=None
        slices=[]
        for number in range(100):
            destination=folder/f"{number}.json"
            partial=rank_joint_columnar("AAAAA",[],**args,resume_path=previous,checkpoint_path=destination,
                max_evaluations=5,max_states=350,max_orders=1,max_segmentations=1)
            slices.append(dict(evaluated_this_run=partial["evaluated_this_run"],states_this_run=partial["states_this_run"],
                frontier_progress_nodes=partial["frontier_progress_nodes"],frontier_nodes=partial["frontier_nodes"],
                checkpoint_candidate_verifications=partial["work_this_run"]["checkpoint_candidate_verifications"],
                checkpoint_score_window_evaluations=partial["work_this_run"]["checkpoint_score_window_evaluations"]))
            previous=destination
            if partial["complete"]:break
        assert partial["complete"] and partial["candidates"]==whole["candidates"]
        assert partial["evaluated"]==whole["evaluated"]==sum(row["evaluated_this_run"] for row in slices)
        assert partial["work"]["checkpoint_candidate_verifications"]==sum(row["checkpoint_candidate_verifications"] for row in slices)
        assert partial["work"]["checkpoint_score_window_evaluations"]==sum(row["checkpoint_score_window_evaluations"] for row in slices)
        continuation=dict(oracle_match=True,complete=True,slices=slices,evaluated=partial["evaluated"],
            uninterrupted_evaluated=whole["evaluated"],states_total=partial["states_total"],uninterrupted_states=whole["states_total"],
            checkpoint_candidate_verifications=partial["work"]["checkpoint_candidate_verifications"],
            checkpoint_score_window_evaluations=partial["work"]["checkpoint_score_window_evaluations"],
            search_plus_checkpoint_objective_evaluations=partial["evaluated"]+partial["work"]["checkpoint_candidate_verifications"])
    finally:
        resolved=folder.resolve()
        if resolved.parent!=base.resolve() or not resolved.name.startswith("search-O-"):
            raise RuntimeError("unsafe temporary cleanup target")
        shutil.rmtree(resolved)
    files=["kryptos/guided_search.py","kryptos/factor_decomposition.py","kryptos/search_runtime.py",
           "kryptos/joint_ranked.py","kryptos/next_cli.py","research/search_O.py","research/search_O_acceptance.md","tests/test_search_O.py"]
    return dict(schema="kryptos.search-O-work.v1",guided=guided,
        elimination=dict(baseline_nodes=baseline["nodes"],baseline_work=baseline["work"],variants=bounds,oracle_bound_checks=checked),
        joint=joint,continuation=continuation,sources={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files},
        limits=dict(random_seed=60132,small_graphs=36,residuals_per_graph=8,bucket_caps=[9,27],maximum_checkpoint_slices=100),
        nonclaims=["No universal improvement: small coupled domains and weak bucket caps may add work.",
                   "A guided optimum found in a synthetic control is not an optimality certificate for general use.",
                   "Pruning work and repeated checkpoint preparation remain in the state/operation counts.",
                   "No K4 search, cryptographic authenticity, hardware speedup or CPU/GPU comparison is claimed."])


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    output=Path(args.output)
    if output.exists():raise ValueError("output exists; choose a fresh path")
    result=run()
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,allow_nan=False)
    print(json.dumps(dict(output=str(output),guided_controls=len(result["guided"]),bound_oracles=result["elimination"]["oracle_bound_checks"],joint_controls=len(result["joint"]))))
