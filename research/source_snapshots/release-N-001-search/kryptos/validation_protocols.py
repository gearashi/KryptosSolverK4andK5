"""Bounded, leakage-controlled model selection and matched surviving controls.

These descriptive protocols never turn a score into authentication or a p-value.
The fitting function receives ciphertext and training letters only. Held labels
and generating keys are retained by the assessment layer, outside selection.
"""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import random
import time

from .general_layers import LayerBudgetExceeded, literal_encrypt, solve_layers, _alphabet
from .scheduled_layers import solve_scheduled
from .language import CharacterNgramModel
from .next_cli import _check, _integer, _stages, _candidate, _verify

COMMON={"model_paths","model_bank","max_candidates_per_family","max_total_candidates",
        "time_limit_seconds","top","max_key_slots","max_matrix_cells","max_operations"}
BANK_FIELDS={"id","layer_model","alphabet","stages","cells"}


def _hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def _positions(value,length,label):
    if not isinstance(value,list) or any(type(i) is not int or not 0<=i<length for i in value) or len(set(value))!=len(value):
        raise ValueError(label+" must be distinct zero-based positions inside the message")
    return sorted(value)


def _configuration(request):
    paths=request.get("model_paths")
    if not isinstance(paths,list) or not 1<=len(paths)<=5 or any(not isinstance(p,str) for p in paths):
        raise ValueError("model_paths needs1..5 explicit frozen model paths")
    models=[]
    for raw_path in paths:
        path=Path(raw_path)
        if path.stat().st_size>32*1024*1024:
            raise ValueError("model exceeds32MiB")
        raw=path.read_bytes()
        model=CharacterNgramModel.from_json(raw.decode("utf-8-sig"))
        if set(model.alphabet)!=set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") or model.normalization not in ("identity","upper-single"):
            raise ValueError("validation models require an A-Z alphabet and compatible normalization")
        models.append({"model":model,"path":raw_path,"sha256":hashlib.sha256(raw).hexdigest()})
    if len({r["model"].model_id for r in models})!=len(models):
        raise ValueError("duplicate scoring models would count the same comparison twice")
    if len({(r["model"].order,r["model"].normalization) for r in models})!=1:
        raise ValueError("scoring models must use the same ngram order and normalization")
    bank=request.get("model_bank")
    if not isinstance(bank,list) or not 1<=len(bank)<=16:
        raise ValueError("model_bank needs1..16 explicit model records")
    ids=set()
    for row in bank:
        _check(row,BANK_FIELDS)
        name=row.get("id")
        if not isinstance(name,str) or not 1<=len(name)<=80 or name in ids:
            raise ValueError("model bank IDs must be unique nonempty strings up to80characters")
        ids.add(name)
        if row.get("layer_model","general") not in ("general","scheduled"):
            raise ValueError("bank layer_model must be general or scheduled")
        if not isinstance(row.get("stages"),list) or not 1<=len(row["stages"])<=16:
            raise ValueError("each bank model requires1..16 stages")
        _alphabet(row.get("alphabet","kryptos"))
        if "cells" in row and row.get("layer_model","general")!="scheduled":
            raise ValueError("bank cells require a scheduled model")
    seconds=request.get("time_limit_seconds",10)
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=30:
        raise ValueError("time_limit_seconds must be finite in(0,30]")
    bounds={"max_candidates_per_family":_integer(request.get("max_candidates_per_family",676),"max_candidates_per_family",1,17576),
            "max_total_candidates":_integer(request.get("max_total_candidates",10000),"max_total_candidates",1,100000),
            "top":_integer(request.get("top",5),"top",1,20),"time_limit_seconds":seconds,
            "max_key_slots":_integer(request.get("max_key_slots",128),"max_key_slots",1,256),
            "max_matrix_cells":_integer(request.get("max_matrix_cells",2000000),"max_matrix_cells",1,2000000),
            "max_operations":_integer(request.get("max_operations",20000000),"max_operations",1,20000000)}
    return models,bank,bounds


def _scores(text,models,starts):
    order=models[0]["model"].order
    grams=[text[i:i+order] for i in starts]
    # Same ordered accumulation as CharacterNgramModel.score; retained rows are
    # checked against that separate public scoring path below.
    values=[]
    for row in models:
        model=row["model"]
        total=0.0
        for gram in grams:
            total+=model._log_probabilities.get(gram,model._unknown_log_probability)
        values.append(total/len(grams))
    return values


def select_family_bank(ciphertext,training,score_mask,bank,models,bounds,deadline):
    """Pure fitting boundary: no withheld labels, generating truth or keys.

    Every family receives identical explicit caps. A shared per-input visit cap
    and protocol wall-clock deadline can censor later families; that is reported
    and never interpreted as a completed comparison. Oversize families are not
    represented by a misleading arbitrary first subset.
    """
    n=len(ciphertext)
    order=models[0]["model"].order
    starts=[i for i in range(n-order+1) if not set(range(i,i+order)).intersection(score_mask)]
    if not starts:
        raise ValueError("score mask leaves no ngram windows for comparison")
    rows,candidates=[],{}
    evaluated=0
    stream=hashlib.sha256()
    for bank_row in bank:
        record={"id":bank_row["id"],"feasible":None,"complete":False,"evaluated":0}
        rows.append(record)
        if time.monotonic()>=deadline:
            record["stop_reason"]="protocol_time_limit"
            continue
        if evaluated>=bounds["max_total_candidates"]:
            record["stop_reason"]="per_input_candidate_limit"
            continue
        model_type=bank_row.get("layer_model","general")
        stages=bank_row["stages"]
        if model_type=="scheduled":
            stages,_=_stages(bank_row,"custom",ciphertext)
        solver=solve_scheduled if model_type=="scheduled" else solve_layers
        try:
            solution=solver(ciphertext,training,stages,bank_row.get("alphabet","kryptos"),
                            **{k:bounds[k] for k in ("max_key_slots","max_matrix_cells","max_operations")})
        except LayerBudgetExceeded as error:
            record.update(stop_reason="algebra_budget",detail=str(error))
            continue
        record.update(feasible=solution.feasible,distinct_plaintext_count=solution.distinct_plaintext_count,
                      dimensions_mod2=solution.dimensions_mod2,dimensions_mod13=solution.dimensions_mod13)
        if not solution.feasible:
            record.update(complete=True,stop_reason="exact_contradiction")
            continue
        if solution.distinct_plaintext_count>bounds["max_candidates_per_family"]:
            record["stop_reason"]="family_candidate_limit"
            continue
        if solution.distinct_plaintext_count>bounds["max_total_candidates"]-evaluated:
            record["stop_reason"]="per_input_candidate_limit"
            continue
        for a,b,text in solution.enumerate_plaintexts(bounds["max_candidates_per_family"]):
            if time.monotonic()>=deadline:
                record["stop_reason"]="protocol_time_limit"
                break
            # Independently constructed keys re-encrypt every enumerated text.
            witness=solution.candidate(a,b)
            if witness["plaintext"]!=text or witness["reencrypted_ciphertext"]!=ciphertext:
                raise AssertionError("validation candidate literal replay failed")
            record["evaluated"]+=1
            evaluated+=1
            stream.update((bank_row["id"]+":"+text+"\n").encode())
            if text in candidates:
                candidates[text]["model_ids"].append(bank_row["id"])
                continue
            scores=_scores(text,models,starts)
            candidates[text]={"plaintext":text,"scores":scores,"selected_score":max(scores),
                              "model_ids":[bank_row["id"]],"_witness":witness,
                              "_stages":stages,"_model_type":model_type,"_alphabet":solution.alphabet}
        else:
            record.update(complete=True,stop_reason="exhausted_declared_family")
    ranked=sorted(candidates.values(),key=lambda r:(-r["selected_score"],r["plaintext"]))
    retained=[]
    for row in ranked[:bounds["top"]]:
        witness=row["_witness"]
        if row["_model_type"]=="general":
            witness=_candidate(witness,row["_stages"],row["_alphabet"],ciphertext,training)
        witness=_verify(witness,ciphertext,training)
        reference=[r["model"].score(row["plaintext"],score_mask).mean_log_probability for r in models]
        if row["scores"]!=reference:
            raise AssertionError("fast score differs from public masked scorer")
        retained.append({**witness,"scores":row["scores"],"selected_score":row["selected_score"],"model_ids":row["model_ids"]})
    complete=all(r["complete"] for r in rows)
    public={"complete":complete,"truncated":not complete,"stop_reason":"exhausted_bank" if complete else "censored_model_bank",
            "model_records":rows,"evaluated":evaluated,"literal_reencryptions":evaluated,
            "distinct_completed_plaintexts":len(ranked),"candidates":retained,
            "best_selected_score":ranked[0]["selected_score"] if ranked else None,
            "score_mask":list(score_mask),"scored_windows":len(starts),
            "ordered_family_stream_sha256":stream.hexdigest(),
            "selection_sha256":_hash([[r["plaintext"],r["scores"],r["model_ids"]] for r in ranked]),
            "training_input_sha256":_hash({"ciphertext":ciphertext,"training":sorted(training.items()),"mask":score_mask,"bank":bank}),
            "ranking":"maximum frozen-model mean log score, then plaintext lexical order; duplicate plaintexts merged"}
    return public,ranked


def _truth_assessment(ranked,truth,complete):
    row=next((r for r in ranked if r["plaintext"]==truth),None)
    return {"truth_present_in_evaluated_candidates":row is not None,
            "truth_competition_rank":None if row is None else 1+sum(r["selected_score"]>row["selected_score"] for r in ranked),
            "truth_score_ties":None if row is None else sum(r["selected_score"]==row["selected_score"] for r in ranked),
            "truth_selected_score":None if row is None else row["selected_score"],
            "rank_scope":"complete declared bank" if complete else "evaluated subset only; censored",
            "wrong_alternatives":sum(r["plaintext"]!=truth for r in ranked)}


def run_validation(command,request):
    if command=="validate-ablations":
        from .ablations import run_ablations
        return run_ablations(request)
    if command not in ("validate-holdout","validate-controls"):
        raise ValueError("unknown validation command")
    extra=({"target","ciphertext","cribs","withheld_positions"} if command=="validate-holdout"
           else {"seed","crib_positions","cases"})
    _check(request,COMMON|extra)
    started=time.monotonic()
    models,bank,bounds=_configuration(request)
    deadline=started+bounds["time_limit_seconds"]
    result={"schema":"kryptos.validation-protocol.v1","command":command,"bounds":bounds,
            "model_bank":bank,"scoring_models":[{"path":r["path"],"sha256":r["sha256"],"id":r["model"].model_id} for r in models],
            "request_sha256":_hash(request),"authenticated_solution":False,
            "interpretation":"Descriptive bounded selection controls, not solution confidence or a false-positive probability."}
    if command=="validate-holdout":
        from .__main__ import _target
        target,ciphertext,cribs,known=_target(request)
        if len(ciphertext)>512:
            raise ValueError("validation supports messages up to512letters")
        withheld=_positions(request.get("withheld_positions"),len(ciphertext),"withheld_positions")
        if not withheld or not set(withheld)<set(known):
            raise ValueError("withheld_positions must be a nonempty proper subset of supplied crib positions")
        training={i:c for i,c in known.items() if i not in withheld}
        # Do not pass `known`, `request`, cribs or withheld answers into fitting.
        selection,ranked=select_family_bank(ciphertext,training,sorted(known),bank,models,bounds,deadline)
        assessments=[{"plaintext_sha256":hashlib.sha256(r["plaintext"].encode()).hexdigest(),
                      "predicted":"".join(r["plaintext"][i] for i in withheld),
                      "matching_letters":sum(r["plaintext"][i]==known[i] for i in withheld),
                      "all_withheld_match":all(r["plaintext"][i]==known[i] for i in withheld)} for r in selection["candidates"]]
        result.update(target=target,selection=selection,training_positions=sorted(training),withheld_positions=withheld,
                      assessment={"answers":"".join(known[i] for i in withheld),"retained_candidates":assessments,
                                  "assessed_count":len(assessments),"evaluated_candidates_matching_all":sum(all(r["plaintext"][i]==known[i] for i in withheld) for r in ranked)},
                      complete=selection["complete"],truncated=not selection["complete"],stop_reason=selection["stop_reason"],
                      holdout_caveat="Public K4 clues remain retrospectively known to researchers; this prevents algorithmic label leakage, not historical hypothesis selection bias.")
    else:
        cases=request.get("cases")
        if not isinstance(cases,list) or not 2<=len(cases)<=8 or len(bank)<2:
            raise ValueError("controls require2..8 independent cases and at least2 declared model records")
        seed=_integer(request.get("seed",20261014),"seed",0,2**63-1)
        ids,texts=set(),set()
        bank_by_id={r["id"]:r for r in bank}
        length=None
        prepared=[]
        for row in cases:
            _check(row,{"id","plaintext","source","generating_model_id","keys","language"})
            name,text,source=row.get("id"),row.get("plaintext"),row.get("source")
            if not isinstance(name,str) or not name or len(name)>80 or name in ids:
                raise ValueError("control case IDs must be unique nonempty strings up to80characters")
            if not isinstance(text,str) or not 4<=len(text)<=512 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in text) or text in texts:
                raise ValueError("control plaintexts must be distinct4..512letter uppercase strings")
            if not isinstance(source,str) or not source.strip() or len(source)>1000:
                raise ValueError("each control needs an explicit source/authorship description")
            if "language" in row and (not isinstance(row["language"],str) or not 1<=len(row["language"])<=40):
                raise ValueError("control language must be a short explicit label")
            if length is not None and len(text)!=length:
                raise ValueError("control passages must have identical lengths and mask layouts")
            length=len(text)
            ids.add(name); texts.add(text)
            generator=bank_by_id.get(row.get("generating_model_id"))
            if generator is None or generator.get("layer_model","general")!="general":
                raise ValueError("control generator must name a general-layer bank model")
            keys=row.get("keys")
            if not isinstance(keys,list) or any(not isinstance(k,str) or not k or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in k) for k in keys):
                raise ValueError("generator keys must be explicit nonempty A-Z strings")
            # Validate generator against the normal stage parser before executing controls.
            from .general_layers import _stages as general_stages
            normalized,_=general_stages(generator["stages"],length,bounds["max_key_slots"])
            periods=[s.period for s in normalized if s.operation=="substitution"]
            if list(map(len,keys))!=periods:
                raise ValueError("generator keys must match every substitution stage period")
            prepared.append((row,generator))
        mask=_positions(request.get("crib_positions"),length,"crib_positions")
        if not mask or len(mask)>=length-1:
            raise ValueError("control mask must leave at least two unsupplied letters")
        records=[]
        for index,(row,generator) in enumerate(prepared):
            truth=row["plaintext"]
            positions=[i for i in range(length) if i not in mask]
            letters=[truth[i] for i in positions]
            random.Random(seed+index).shuffle(letters)
            null=list(truth)
            for i,c in zip(positions,letters): null[i]=c
            null="".join(null)
            if null==truth:
                raise ValueError("frozen shuffle did not change this plaintext; choose a varied control passage")
            assert Counter(null)==Counter(truth) and all(null[i]==truth[i] for i in mask)
            known={i:truth[i] for i in mask}
            pair={"id":row["id"],"source":row["source"],"seed":seed+index,
                  "generating_model_id":generator["id"],"generating_keys":row["keys"]}
            if "language" in row:
                pair["language"]=row["language"]
            for label,text in (("positive",truth),("null",null)):
                cipher=literal_encrypt(text,row["keys"],generator["stages"],_alphabet(generator.get("alphabet","kryptos")))
                selection,ranked=select_family_bank(cipher,known,mask,bank,models,bounds,deadline)
                pair[label]={"ciphertext":cipher,"generating_plaintext":text,"selection":selection,
                             "assessment":_truth_assessment(ranked,text,selection["complete"])}
            p,q=pair["positive"]["selection"],pair["null"]["selection"]
            comparable=p["complete"] and q["complete"] and p["best_selected_score"] is not None and q["best_selected_score"] is not None
            pair["comparison"]={"complete_comparison":comparable,
                                "null_best_minus_positive_best":q["best_selected_score"]-p["best_selected_score"] if comparable else None,
                                "null_best_at_least_positive_best":q["best_selected_score"]>=p["best_selected_score"] if comparable else None}
            records.append(pair)
        complete=all(r[label]["selection"]["complete"] for r in records for label in ("positive","null"))
        result.update(cases=records,crib_positions=mask,seed=seed,complete=complete,truncated=not complete,
                      stop_reason="exhausted_protocol" if complete else "censored_protocol",
                      summary={"positive_inputs":len(records),"paired_null_inputs":len(records),
                               "completed_comparisons":sum(r["comparison"]["complete_comparison"] for r in records),
                               "candidate_visits":sum(r[label]["selection"]["evaluated"] for r in records for label in ("positive","null")),
                               "positive_truth_rank_one":sum(r["positive"]["selection"]["complete"] and r["positive"]["assessment"]["truth_competition_rank"]==1 for r in records),
                               "nulls_with_surviving_wrong_candidates":sum(r["null"]["assessment"]["wrong_alternatives"]>0 for r in records)})
    for row in models:
        if hashlib.sha256(Path(row["path"]).read_bytes()).hexdigest()!=row["sha256"]:
            raise RuntimeError("frozen scoring model changed during validation")
    result["elapsed_seconds"]=time.monotonic()-started
    result["source_sha256"]={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))}
    result["nonclaims"]=["No authenticated Kryptos decipherment or external submission.",
                         "Frozen authored controls are not a representative language population or a false-positive probability.",
                         "Wall time is cooperative between algebra/candidate steps; use the app's hard worker deadline.",
                         "Different model parameterizations may overlap; candidate texts are merged, model aliases retained."]
    return result
