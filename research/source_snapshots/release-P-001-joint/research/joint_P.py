"""Execute the frozen authored phase P controls, keeping every work outcome.

python -B research/joint_P.py --output <fresh-result.json>
No real K4 search or reserved phase O scoring. The parent wraps final execution
in the source-pinned computation-audit runner after the all-agent source freeze.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.joint_ranked import rank_joint_columnar
from kryptos.language import CorpusDocument,train_ngram_model
from kryptos.explanations import replay_recipe
from tests.test_joint_P import oracle,encrypt,fixtures,A,ALL

VARIANTS=[("baseline",{}),("fixed_point",dict(propagation="fixed_point")),
          ("early_segmentation",dict(early_segmentation=True)),
          ("constrained",dict(branching="constrained")),
          ("shared_key",dict(score_bound="shared_key")),
          ("identical_chunks",dict(symmetry="identical_chunks")),
          ("combined",{key:value for key,value in ALL.items() if key!="pruning"})]
INPUTS=["research/joint_P_protocol.json","research/joint_P.py","tests/test_joint_P.py",
        "kryptos/joint_ranked.py","kryptos/joint_ranked_helpers.py","kryptos/joint_columnar.py",
        "kryptos/columnar.py","kryptos/explanations.py","kryptos/language.py"]


def hashes():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}


def run():
    before=hashes()
    protocol=json.loads((ROOT/"research/joint_P_protocol.json").read_text())
    model=train_ngram_model([CorpusDocument("ABACABADABACABAEABCDEFFEDCBA","P authored")],label="P tests",order=2)
    correlated=train_ngram_model([CorpusDocument("ABXABY"*10+"A"*12,"P shared-key authored")],label="P shared-key",order=6)
    cases=[]
    for text,name in (("AAAAAA","identical-chunks"),("ABCDEF","nonidentical-chunks")):
        for order in ("ST","TS"):
            cases.append(dict(id=name+"-"+order,ciphertext=text,known={},width=3,period=2,order=order,alphabet=A))
    for order in ("ST","TS"):
        plain="ABCDEFG"
        cases.append(dict(id="ragged-prefix-"+order,ciphertext=encrypt(plain,3,[2,7],[2,0,1],order),
            known={i:plain[i] for i in (0,1,4,6)},width=3,period=2,order=order,alphabet=A))
    cases.append(dict(id="shared-key-sixgram",ciphertext="AAAAAAAAA",known={},width=1,period=3,order="ST",alphabet=A))
    cases.extend(fixtures())
    results=[]
    for case in cases:
        case=dict(case);name=case.pop("id");known=case.pop("known");text=case.pop("ciphertext")
        scoring=correlated if name=="shared-key-sixgram" else model
        top=1 if name=="shared-key-sixgram" else 5
        expected,assignment_count,route_count=oracle(text,known,model=scoring,**case)
        rows=[]
        for variant,options in VARIANTS:
            result=rank_joint_columnar(text,[dict(start=i+1,text=c) for i,c in known.items()],
                model=scoring,top=top,pruning="admissible",max_states=2000000,max_evaluations=100000,
                time_limit_seconds=10,**case,**options)
            expected_map=dict(expected)
            for candidate in result["candidates"]:
                plain=candidate["plaintext"]
                assert plain in expected_map
                assert int(candidate["score_exact"],16)==expected_map[plain][0]
                assert replay_recipe(plain,candidate["encryption_recipe"])["ciphertext"]==text
            if result["complete"]:
                assert len(result["candidates"])==min(top,len(expected))
                for candidate,(plain,(score,(cols,key))) in zip(result["candidates"],expected):
                    assert (candidate["plaintext"],int(candidate["score_exact"],16),tuple(candidate["column_order"]),candidate["key_pattern"])==(plain,score,cols,key)
            if result["total_order_key_assignments"] is not None:assert result["total_order_key_assignments"]==assignment_count
            if result["total_column_orders"] is not None:assert result["total_column_orders"]==route_count
            rows.append(dict(variant=variant,options=options,complete=result["complete"],stop_reason=result["stop_reason"],
                oracle_top_and_recipe_match=True if result["complete"] else None,retained_scores_and_replay_valid=True,
                evaluated=result["evaluated"],states_total=result["states_total"],work=result["work"],
                branch_decisions=result["work"].get("branch_decisions",0),
                segmentations_tested=result["segmentations_tested"],
                route_completion_blocks=result["route_completion_blocks"],column_orders_visited=result["column_orders_visited"],
                total_order_key_assignments=result["total_order_key_assignments"],total_column_orders=result["total_column_orders"],
                enumeration_complete=result["enumeration_complete"],symmetry=result["route_symmetry"],
                candidates=[{key:row[key] for key in ("plaintext","column_order","key_pattern","score_exact")} for row in result["candidates"]]))
        baseline=rows[0]
        for row in rows:
            comparable=baseline["complete"] and row["complete"]
            row["comparison_to_baseline"]=dict(comparable=comparable,
                candidate_evaluations_saved=baseline["evaluated"]-row["evaluated"] if comparable else None,
                counted_states_saved=baseline["states_total"]-row["states_total"] if comparable else None,
                branch_decisions_saved=baseline["branch_decisions"]-row["branch_decisions"] if comparable else None,
                completed_segmentations_saved=baseline["segmentations_tested"]-row["segmentations_tested"] if comparable else None,
                interpretation="Positive means fewer counted operations; negative is added work. Different work categories are also retained. No timing success metric.")
        results.append(dict(id=name,ciphertext=text,known=known,assumptions=case,model_id=scoring.model_id,
            oracle_assignment_count=assignment_count,oracle_distinct_route_count=route_count,variants=rows))
    base=ROOT/"research"/"manual-checks";base.mkdir(parents=True,exist_ok=True)
    folder=Path(tempfile.mkdtemp(prefix="joint-P-protocol-",dir=base))
    try:
        args=dict(width=2,period=1,model=model,alphabet=A,top=4,**ALL)
        whole=rank_joint_columnar("BDBC",[],**args)
        previous=None;slices=[]
        for step in range(protocol["limits"]["maximum_resume_slices"]):
            output=folder/f"{step}.json"
            part=rank_joint_columnar("BDBC",[],**args,resume_path=previous,checkpoint_path=output,
                max_evaluations=4,max_states=800)
            slices.append(dict(evaluated=part["evaluated_this_run"],states=part["states_this_run"],
                advanced=part["frontier_progress_nodes"],verification_objectives=part["work_this_run"]["checkpoint_candidate_verifications"]))
            previous=output
            if part["complete"]:break
        assert part["complete"] and whole["complete"] and part["candidates"]==whole["candidates"]
        assert part["evaluated"]==whole["evaluated"]==sum(row["evaluated"] for row in slices)
        continuation=dict(complete=True,oracle_top_and_recipe_match=True,slices=slices,
            unique_search_evaluations=part["evaluated"],verification_objectives=part["work"]["checkpoint_candidate_verifications"],
            states_total=part["states_total"],uninterrupted_states=whole["states_total"])
    finally:
        resolved=folder.resolve()
        if resolved.parent!=base.resolve() or not resolved.name.startswith("joint-P-protocol-"):
            raise RuntimeError("unsafe temporary cleanup target")
        shutil.rmtree(resolved)
    after=hashes()
    if before!=after:raise RuntimeError("Protocol inputs changed during execution")
    return dict(schema="kryptos.joint-P-results.v1",assertion_tested=protocol["assertion_tested"],
        inputs_before=before,inputs_after=after,case_count=len(results),variants_per_case=len(VARIANTS),
        cases=results,continuation=continuation,nonclaims=protocol["nonclaims"],limits=protocol["limits"])


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--output",required=True);args=parser.parse_args()
    output=Path(args.output)
    if output.exists():raise ValueError("Choose a fresh output path")
    result=run();output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as stream:json.dump(result,stream,indent=2,allow_nan=False)
    print(json.dumps(dict(output=str(output),cases=result["case_count"],variants=result["variants_per_case"])))
