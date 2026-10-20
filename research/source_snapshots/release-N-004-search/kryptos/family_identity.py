"""Exact same-alphabet affine coset identity and model-specific alias replay.

Independent row-reduced spans over F2 and F13 characterize the plaintext set.
Scoring reuse additionally pins the model bytes and every excluded position.
Different alphabets conservatively remain distinct; equality does not identify
physical encryption methods. All original recipes remain separate aliases.
"""
import hashlib
import json

def _hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()

def canonical_coset(base,columns,prime,max_operations=5_000_000):
    if prime not in (2,13) or not base or any(len(c)!=len(base) for c in columns):
        raise ValueError("Expected a nonempty F2/F13 affine plaintext family")
    rows=[[x%prime for x in col] for col in columns if any(x%prime for x in col)]
    width=len(base)
    pivots=[]
    top=work=0
    for col in range(width):
        pivot=next((i for i in range(top,len(rows)) if rows[i][col]),None)
        if pivot is None:
            continue
        rows[top],rows[pivot]=rows[pivot],rows[top]
        inv=pow(rows[top][col],-1,prime)
        rows[top]=[(x*inv)%prime for x in rows[top]]
        work+=width
        for i,row in enumerate(rows):
            if i!=top and row[col]:
                factor=row[col]
                rows[i]=[(x-factor*y)%prime for x,y in zip(row,rows[top])]
                work+=width
                if work>max_operations:
                    raise ValueError("Affine fingerprint work cap exceeded")
        pivots.append(col)
        top+=1
        if top==len(rows):
            break
    reduced=[x%prime for x in base]
    for pivot,row in zip(pivots,rows[:top]):
        factor=reduced[pivot]
        reduced=[(x-factor*y)%prime for x,y in zip(reduced,row)]
    return {"prime":prime,"base":reduced,"basis":rows[:top]}

def _job(request):
    from .__main__ import _target
    from .next_cli import _optimization_job
    return _optimization_job(request,_target)

def describe_family(request):
    job=_job(request)
    if job["algebra_budget"] is not None:
        return {"eligible":False,"feasible":None,"reason":"algebra_budget"}
    solution=job["solution"]
    if not solution.feasible:
        return {"eligible":False,"feasible":False,"reason":"exact_contradiction"}
    try:
        fields=[canonical_coset(f.plaintext_base,f.plaintext_columns,f.modulus) for f in (solution.field2,solution.field13)]
    except ValueError as error:
        return {"eligible":False,"feasible":True,"reason":str(error)}
    family={"alphabet":solution.alphabet,"fields":fields}
    mask=sorted(job.get("score_mask",job["known"]))
    scoring={"family_sha256":_hash(family),"model_sha256":job["model_sha256"],"excluded_positions":mask}
    return {"schema":"kryptos.affine-family-identity.v1","eligible":True,"feasible":True,
            **scoring,"scoring_family_sha256":_hash(scoring),"distinct_plaintext_count_decimal":str(solution.distinct_plaintext_count),
            "convention":"Same-alphabet plaintext coset equality; independent reduced F2/F13 spans. Same scoring mask and model required for ranking reuse."}

def _coordinates(field,letters,cap=5_000_000):
    prime=field.modulus
    columns=field.plaintext_columns
    width=len(columns)
    rows=[[c[i]%prime for c in columns]+[(letters[i]-field.plaintext_base[i])%prime] for i in range(len(letters))]
    pivots=[]
    top=work=0
    for col in range(width):
        pivot=next((i for i in range(top,len(rows)) if rows[i][col]),None)
        if pivot is None:
            continue
        rows[top],rows[pivot]=rows[pivot],rows[top]
        inv=pow(rows[top][col],-1,prime)
        rows[top]=[(x*inv)%prime for x in rows[top]]
        for i,row in enumerate(rows):
            if i!=top and row[col]:
                factor=row[col]
                rows[i]=[(x-factor*y)%prime for x,y in zip(row,rows[top])]
                work+=width+1
                if work>cap:
                    raise ValueError("Alias coordinate work cap exceeded")
        pivots.append(col)
        top+=1
    if any(not any(row[:-1]) and row[-1] for row in rows):
        raise ValueError("Candidate is outside the claimed affine family")
    result=[0]*width
    for i,col in enumerate(pivots):
        result[col]=rows[i][-1]
    return result

def replay_aliases(request,candidates):
    from .advanced_cli import _candidate
    from .next_cli import _verify
    from .score_sensitivity import report as sensitivity_report
    if not isinstance(candidates,list) or len(candidates)>100:
        raise ValueError("Supply at most100 candidate aliases")
    job=_job(request)
    if job["algebra_budget"] is not None or not job["solution"].feasible:
        raise ValueError("Alias family is unavailable")
    solution=job["solution"]
    retained=[]
    for saved in candidates:
        text=saved.get("plaintext")
        if not isinstance(text,str) or len(text)!=len(job["text"]) or any(c not in solution.alphabet for c in text):
            raise ValueError("Invalid alias plaintext")
        letters=[solution.alphabet.index(c) for c in text]
        a,b=(_coordinates(f,letters) for f in (solution.field2,solution.field13))
        candidate=solution.candidate(a,b)
        if candidate["plaintext"]!=text:
            raise AssertionError("Alias plaintext reconstruction mismatch")
        if job["layer_model"]=="general":
            candidate=_candidate(candidate,job["stages"],solution.alphabet,job["text"],job["known"])
        candidate=_verify(candidate,job["text"],job["known"])
        for name in ("score","score_exact","exact_objective_hex"):
            if name in saved:
                candidate[name]=saved[name]
        candidate["score_sensitivity"]=sensitivity_report(solution,job["model"],text,job["known"])
        candidate["technique"]="Equivalent affine family: reused ranking and reconstructed this recipe's own keys; independent literal replay"
        candidate["ranking_reused_from_equivalent_family"]=True
        retained.append(candidate)
    return {"candidates":retained,"alias_replay_complete":True,"authenticated_solution":False}
