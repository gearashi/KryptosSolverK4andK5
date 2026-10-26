"""Refit precisely defined smaller recipes without consulting withheld labels.

Deleting a stage is a conditional model comparison, not a causal explanation
of an unknown cipher. Complete family equality is checked on plaintext sets.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import time

from .validation_protocols import COMMON, _configuration, _hash, _positions, select_family_bank
from .next_cli import _check, _stages


def ablation_bank(model, length, stage_indices=None, schedule_semantics="recompute"):
    """Return baseline and one-stage refits; no text or clue values enter here.

    Recompute preserves declarative coordinate rules and resolves their frame
    against the modified preceding gathers. Freeze resolves the original rules
    once and holds those per-position key-slot maps fixed in every variant.
    """
    if schedule_semantics not in ("recompute","freeze"):
        raise ValueError("schedule_semantics must be recompute or freeze")
    if type(length) is not int or not 1<=length<=512:
        raise ValueError("ablation length must be in1..512")
    stages=model.get("stages") if isinstance(model,dict) else None
    if not isinstance(stages,list) or not 1<=len(stages)<=16 or any(
            not isinstance(stage,dict) or stage.get("operation") not in ("substitution","gather") for stage in stages):
        raise ValueError("ablations require1..16 substitution/gather stage objects")
    selected=list(range(len(stages))) if stage_indices is None else _positions(stage_indices,len(stages),"ablation_stage_indices")
    if not selected:
        raise ValueError("select at least one stage to ablate")
    baseline=deepcopy(model)
    baseline["id"]="baseline"
    if model.get("layer_model","general")=="scheduled" and schedule_semantics=="freeze":
        baseline["stages"],_=_stages(baseline,"custom","A"*length)
    records=[{"kind":"baseline","stage_zero_based":None,"model":baseline}]
    for index in selected:
        variant=deepcopy(baseline)
        operation=variant["stages"][index].get("operation")
        if operation=="substitution":
            del variant["stages"][index]
            kind="remove_substitution"
        elif operation=="gather":
            variant["stages"][index]={"operation":"gather","permutation":list(range(length))}
            kind="identity_gather"
        else:
            raise ValueError("ablations support substitution and gather stages only")
        if not variant["stages"]:
            variant["stages"]=[{"operation":"gather","permutation":list(range(length))}]
        variant["id"]=f"ablation-{index}"
        records.append({"kind":kind,"stage_zero_based":index,"model":variant})
    return records


def _assess(selection, ranked, withheld, answers):
    def matches(text):
        return sum(text[i]==letter for i,letter in zip(withheld,answers))
    retained=[{"plaintext_sha256":hashlib.sha256(row["plaintext"].encode()).hexdigest(),
               "predicted":"".join(row["plaintext"][i] for i in withheld),
               "matching_letters":matches(row["plaintext"]),
               "all_withheld_match":matches(row["plaintext"])==len(withheld)}
              for row in selection["candidates"]]
    return {"answers":answers,"retained_candidates":retained,
            "top_matching_letters":retained[0]["matching_letters"] if retained else None,
            "top_all_withheld_match":retained[0]["all_withheld_match"] if retained else None,
            "evaluated_candidates_matching_all":sum(matches(row["plaintext"])==len(withheld) for row in ranked),
            "assessment_scope":"complete family" if selection["complete"] else "evaluated subset only; censored"}


def run_ablations(request):
    _check(request,COMMON|{"target","ciphertext","cribs","withheld_positions",
                           "ablation_stage_indices","schedule_semantics"})
    started=time.monotonic()
    models,bank,bounds=_configuration(request)
    if len(bank)!=1:
        raise ValueError("ablations require exactly one baseline model")
    from .__main__ import _target
    target,ciphertext,cribs,known=_target(request)
    if len(ciphertext)>512:
        raise ValueError("ablations support messages up to512letters")
    withheld=_positions(request.get("withheld_positions"),len(ciphertext),"withheld_positions")
    if not withheld or not set(withheld)<set(known):
        raise ValueError("withheld_positions must be a nonempty proper subset of supplied crib positions")
    training={i:c for i,c in known.items() if i not in withheld}
    mask=sorted(known)
    semantics=request.get("schedule_semantics","recompute")
    variants=ablation_bank(bank[0],len(ciphertext),request.get("ablation_stage_indices"),semantics)
    deadline=started+bounds["time_limit_seconds"]
    fitted=[]
    remaining=bounds["max_total_candidates"]
    for variant in variants:
        if variant["model"].get("layer_model","general")=="scheduled":
            resolved,provenance=_stages(variant["model"],"custom",ciphertext)
        else:
            resolved,provenance=deepcopy(variant["model"]["stages"]),[]
        variant["resolved_stages"]=resolved
        variant["phase_provenance"]=provenance
        local=dict(bounds,max_total_candidates=remaining)
        # This boundary receives neither held answers nor any original key.
        selection,ranked=select_family_bank(ciphertext,training,mask,[variant["model"]],models,local,deadline)
        remaining-=selection["evaluated"]
        fitted.append((variant,selection,ranked))
    # Only after every refit is done are held-out values accessed for assessment.
    answers="".join(known[i] for i in withheld)
    records=[]
    baseline_set={row["plaintext"] for row in fitted[0][2]}
    baseline_complete=fitted[0][1]["complete"]
    baseline_assessment=_assess(fitted[0][1],fitted[0][2],withheld,answers)
    for variant,selection,ranked in fitted:
        texts={row["plaintext"] for row in ranked}
        assessment=_assess(selection,ranked,withheld,answers)
        comparable=baseline_complete and selection["complete"]
        base_top=baseline_assessment["top_matching_letters"]
        top=assessment["top_matching_letters"]
        comparison={"complete_comparison":comparable,
                    "same_completed_plaintext_family":texts==baseline_set if comparable else None,
                    "lost_plaintexts":len(baseline_set-texts) if comparable else None,
                    "gained_plaintexts":len(texts-baseline_set) if comparable else None,
                    "top_match_delta":top-base_top if comparable and top is not None and base_top is not None else None,
                    "interpretation":"Conditional refit of this declared stage; family equality and predictive differences do not authenticate a cipher or establish causation."}
        records.append({**variant,"selection":selection,"assessment":assessment,
                        "completed_family_sha256":_hash(sorted(texts)) if selection["complete"] else None,
                        "comparison_to_baseline":comparison})
    for row in models:
        if hashlib.sha256(Path(row["path"]).read_bytes()).hexdigest()!=row["sha256"]:
            raise RuntimeError("frozen scoring model changed during ablations")
    complete=all(row["selection"]["complete"] for row in records)
    return {"schema":"kryptos.validation-protocol.v1","command":"validate-ablations","target":target,
            "request_sha256":_hash(request),"bounds":bounds,"baseline_model_id":bank[0]["id"],
            "model_bank":bank,"scoring_models":[{"path":r["path"],"sha256":r["sha256"],"id":r["model"].model_id} for r in models],
            "schedule_semantics":semantics,"training_positions":sorted(training),"withheld_positions":withheld,
            "score_mask":mask,"records":records,"candidates":records[0]["selection"]["candidates"],
            "complete":complete,"truncated":not complete,"stop_reason":"exhausted_ablations" if complete else "censored_ablations",
            "candidate_visits":bounds["max_total_candidates"]-remaining,"elapsed_seconds":time.monotonic()-started,
            "source_sha256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))},
            "authenticated_solution":False,
            "interpretation":"Each smaller recipe refits all remaining keys using training letters only, with all supplied clue positions masked from scoring.",
            "nonclaims":["No causal or historical necessity, authenticated solution, or correctness probability.",
                         "Public K4 clues remain retrospective; algorithmic label separation cannot remove prior hypothesis selection bias.",
                         "Ablations need not be nested plaintext families. Complete set comparisons are conditional on these supplied models.",
                         "Candidate visits share one protocol cap; time is cooperative between bounded algebra/candidate steps."]}
