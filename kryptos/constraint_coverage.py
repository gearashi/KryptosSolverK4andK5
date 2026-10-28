"""Exact overlap reuse across bounded, fully enumerated cipher families.

Every recipe is retained and replayed. Unique plaintexts share objective work
only when model bytes and score-mask positions agree. Materialization and alias
replay are preparation, never concealed as free search reduction.
"""
from collections import defaultdict
import hashlib
from pathlib import Path

from .constraint_lab import _int, ConstraintLimit


def run(request):
    from .__main__ import _target
    from .next_cli import _optimization_job, _verify
    from .advanced_cli import _candidate
    from .language import CharacterNgramModel
    if not isinstance(request,dict) or set(request)-{'families','top','max_assignments'}:
        raise ValueError('Coverage bank accepts families, top and max_assignments')
    families=request.get('families')
    if not isinstance(families,list) or not 1<=len(families)<=128:
        raise ValueError('Supply1..128 finite cipher families')
    top=_int(request.get('top',20),'top',1,100)
    maximum=_int(request.get('max_assignments',200000),'max_assignments',1,200000)
    jobs=[]
    total=0
    identity=None
    for family in families:
        if not isinstance(family,dict):
            raise ValueError('Each family must be an object')
        if set(family)=={'cipher_request'}:
            job=_optimization_job(family['cipher_request'],_target)
            if job['algebra_budget'] is not None:
                raise ConstraintLimit('One family exceeded its algebra budget')
            size=job['solution'].distinct_plaintext_count if job['solution'].feasible else 0
            job['kind']='affine'
        elif set(family)<= {'ciphertext','cribs','model_path','score_mask','candidates'} and 'candidates' in family:
            _,text,cribs,known=_target({'target':'custom','ciphertext':family.get('ciphertext'),'cribs':family.get('cribs',[])})
            candidates=family['candidates']
            if not isinstance(candidates,list) or len(candidates)>maximum:
                raise ValueError('Explicit bank must contain bounded candidate objects')
            raw=Path(family['model_path']).read_bytes()
            if len(raw)>32*1024*1024:
                raise ValueError('Model file exceeds32MiB')
            mask=family.get('score_mask',sorted(known))
            if not isinstance(mask,list) or any(type(i) is not int or not 0<=i<len(text) for i in mask) or len(set(mask))!=len(mask) or not set(known)<=set(mask):
                raise ValueError('Mask must contain all crib positions')
            job={'kind':'explicit','text':text,'known':known,'score_mask':sorted(mask),'model':CharacterNgramModel.from_json(raw.decode('utf-8-sig')),
                'model_sha256':hashlib.sha256(raw).hexdigest(),'candidates':candidates}
            size=len(candidates)
        else:
            raise ValueError('Each family supplies a cipher_request or an explicit replayable candidate bank')
        signature=(job['model_sha256'],tuple(job['score_mask']),len(job['text']))
        if identity is None:
            identity=signature
        elif signature!=identity:
            raise ValueError('Coverage scoring reuse requires identical model bytes, mask and text length')
        total+=size
        if total>maximum:
            raise ConstraintLimit('Total declared family materialization exceeds max_assignments')
        jobs.append(job)
    owners={}
    by_family=[{} for job in jobs]
    aliases=defaultdict(set)
    preparation={'enumerated_assignments':0,'literal_replays':0,'candidate_reconstruction_replays':0,
        'recipe_conversion_replays':0,'final_verification_replays':0,
        'algebra_scalar_operations':sum(job['solution'].work for job in jobs if job['kind']=='affine')}
    for index,job in enumerate(jobs):
        if job['kind']=='affine':
            solution=job['solution']
            if not solution.feasible:
                continue
            iterator=(solution.candidate(a,b) for a,b,text in solution.enumerate_plaintexts(maximum))
        else:
            iterator=iter(job['candidates'])
        for candidate in iterator:
            preparation['enumerated_assignments']+=1
            if job['kind']=='affine':
                preparation['candidate_reconstruction_replays']+=1
                preparation['literal_replays']+=1
            else:
                # Imported evidence/score/authentication fields are not trusted.
                if not isinstance(candidate,dict):
                    raise ValueError('Explicit bank candidates must be objects')
                candidate={'plaintext':candidate.get('plaintext'),'encryption_recipe':candidate.get('encryption_recipe')}
            if job['kind']=='affine' and job['layer_model']=='general':
                candidate=_candidate(candidate,job['stages'],job['solution'].alphabet,job['text'],job['known'])
                preparation['recipe_conversion_replays']+=1
                preparation['literal_replays']+=1
            candidate=_verify(candidate,job['text'],job['known'])
            candidate['authenticated_solution']=False
            preparation['final_verification_replays']+=1
            preparation['literal_replays']+=1
            text=candidate.get('plaintext')
            if not isinstance(text,str) or len(text)!=len(job['text']):
                raise ValueError('Explicit candidate must contain a full plaintext')
            owners.setdefault(text,index)
            aliases[text].add(index)
            by_family[index].setdefault(text,candidate)
    model=jobs[0]['model']
    mask=set(jobs[0]['score_mask'])
    p,q=model.alpha.as_integer_ratio()
    scores={}
    window_evaluations=0
    for text in sorted(owners):
        value=1
        for start in range(len(text)-model.order+1):
            if any(i in mask for i in range(start,start+model.order)):
                continue
            value*=model.counts.get(text[start:start+model.order],0)*q+p
            window_evaluations+=1
        scores[text]=value
    ranked=sorted(scores,key=lambda text:(-scores[text],text))
    results=[]
    for index,candidates in enumerate(by_family):
        selected=[text for text in ranked if text in candidates][:top]
        results.append({'family_index':index,'complete':True,'distinct_plaintexts':len(candidates),
            'candidates':[{**candidates[text],'exact_objective_hex':hex(scores[text]),'score_owner_family':owners[text],
                'technique':'Exact overlapping-family coverage: score each distinct plaintext once, retain and replay each original recipe'} for text in selected]})
    return {'schema':'kryptos.disjoint-family-coverage.v1','complete':True,'families':results,
        'candidates':[{'plaintext':text,'exact_objective_hex':hex(scores[text]),'recipe_families':sorted(aliases[text])} for text in ranked[:top]],
        'work':{'complete_candidate_evaluations':len(scores),'independent_family_evaluations':sum(len(x) for x in by_family),
            'duplicate_score_evaluations_avoided':sum(len(x) for x in by_family)-len(scores),'scored_windows':window_evaluations},
        'preparation':preparation,'model_file_sha256':identity[0],'score_mask':list(identity[1]),'authenticated_solution':False,
        'interpretation':'Finite complete families only. Unique objective work is reused across overlaps; all enumeration and literal recipe replays are separately counted. No unknown Kryptos family is excluded.'}
