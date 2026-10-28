"""Bounded symbolic recipe grammar and counterexample-guided synthesis.

All substitution keys are independent, unknown, and uniformly unrestricted.
Only a shared known alphabet and explicit bijective gathers are supported.
Merging a prefix preserves its affine transformation relation for EVERY input
text, not just one ciphertext. Original syntax paths remain in a provenance DAG.
"""
import hashlib
from itertools import product
import json
import math

from .recipe_algebra import compile_recipe, compiled_encrypt
from .family_identity import canonical_coset
from .constraint_algebra import IncrementalField


def integer(value,name,low,high):
    if type(value) is not int or not low<=value<=high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)


def description_cost(stages):
    """Explicit syntax priority only; nothing is excluded by this heuristic."""
    if not isinstance(stages,list) or not 1<=len(stages)<=16:
        raise ValueError("Supply1..16 explicit stages")
    periods=sum(integer(s.get('period',1),'period',1,256) for s in stages if s.get('operation')=='substitution')
    route_entries=sum(len(s.get('permutation',[])) for s in stages if s.get('operation')=='gather')
    return (len(stages),periods,route_entries,len(canonical(stages)))


def priority_bank(recipes):
    if not isinstance(recipes,list) or not 1<=len(recipes)<=10000:
        raise ValueError("Supply1..10000 recipes")
    rows=[]
    for i,stages in enumerate(recipes):
        rows.append({'input_index':i,'stages':stages,'description_cost':list(description_cost(stages))})
    return {'complete':True,'recipes':sorted(rows,key=lambda r:(r['description_cost'],r['input_index'])),
            'work':{'priority_evaluations':len(rows)},
            'interpretation':'Order-only preference for fewer stages, key slots, route entries and serialized bytes. Every original recipe remains present.'}


def transformation_signature(compiled,work=None):
    columns=list(map(list,zip(*compiled['key_coefficients_mod26'])))
    fields=[canonical_coset([0]*len(compiled['source_positions']),columns,p) for p in (2,13)]
    if work is not None:
        work['canonicalization_calls']+=2
        work['canonicalization_input_coefficients']+=2*len(columns)*len(compiled['source_positions'])
    return canonical({'alphabet':compiled['alphabet'],'source':compiled['source_positions'],
                      'signs':compiled['plaintext_signs'],'offset_spaces':fields})


def generate(request):
    allowed={'length','alphabet','slots','max_nodes','max_transitions'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError("Unknown symbolic grammar field")
    length=integer(request.get('length'),'length',1,512)
    slots=request.get('slots')
    if not isinstance(slots,list) or not 1<=len(slots)<=12 or any(not isinstance(slot,list) or not 1<=len(slot)<=64 for slot in slots):
        raise ValueError("Supply1..12 grammar positions, each with1..64 explicit stage choices")
    max_nodes=integer(request.get('max_nodes',10000),'max_nodes',1,100000)
    max_transitions=integer(request.get('max_transitions',50000),'max_transitions',1,1000000)
    alphabet=request.get('alphabet','standard')
    worst_slots=0
    # Validate all symbols before any partial search is emitted.
    for slot in slots:
        slot_widths=[]
        for stage in slot:
            symbol=compile_recipe(length,[stage],alphabet=alphabet)
            slot_widths.append(sum(size for _,_,size in symbol['key_layout']))
        worst_slots+=max(slot_widths)
    if worst_slots>256:
        raise ValueError("A grammar path could exceed256 original key slots; reduce the declared grammar so every syntax witness remains reconstructible")
    nodes=[{'id':0,'depth':0,'representative':[],'incoming':[],'represented_paths':1}]
    frontier=[0];work={'symbolic_transitions':0,'compiled_scalar_operations':0,'merged_prefixes':0,
                       'canonicalization_calls':0,'canonicalization_input_coefficients':0}
    for depth,slot in enumerate(slots,1):
        next_nodes={}
        for parent in frontier:
            for choice,stage in enumerate(slot):
                if work['symbolic_transitions']>=max_transitions:
                    return {'complete':False,'stop_reason':'max_transitions','nodes':nodes,'leaves':[],
                            'work':work,'represented_complete_recipes':0}
                work['symbolic_transitions']+=1
                stages=nodes[parent]['representative']+[stage]
                compiled=compile_recipe(length,stages,alphabet=alphabet)
                work['compiled_scalar_operations']+=compiled['scalar_operations']
                signature=transformation_signature(compiled,work)
                if signature in next_nodes:
                    node=nodes[next_nodes[signature]]
                    work['merged_prefixes']+=1
                else:
                    if len(nodes)>=max_nodes:
                        return {'complete':False,'stop_reason':'max_nodes','nodes':nodes,'leaves':[],
                                'work':work,'represented_complete_recipes':0}
                    node={'id':len(nodes),'depth':depth,'representative':stages,'incoming':[],
                          'represented_paths':0,'transformation_sha256':hashlib.sha256(signature.encode()).hexdigest()}
                    next_nodes[signature]=node['id'];nodes.append(node)
                node['incoming'].append({'parent':parent,'choice':choice})
                node['represented_paths']+=nodes[parent]['represented_paths']
                if (description_cost(stages),canonical(stages))<(description_cost(node['representative']),canonical(node['representative'])):
                    node['representative']=stages
        frontier=list(next_nodes.values())
    return {'schema':'kryptos.symbolic-grammar.v1','complete':True,'nodes':nodes,'leaves':frontier,
            'represented_complete_recipes':math.prod(map(len,slots)),
            'retained_transformation_classes':len(frontier),'work':work,'slots':slots,
            'work_accounting_limits':'RREF and hashing scalar operations are not instrumented; their calls and input coefficients are counted separately. Symbol-validation compilation is preprocessing, outside transition counts.',
            'assumptions':'Independent unrestricted substitution keys; one shared known alphabet; explicit gathers. Source permutation and plaintext signs must match before key-offset subspaces may merge.',
            'class_count_interpretation':'Conservative signature classes; different classes may still describe equal transformation families.',
            'proof':'A prefix is y=D*P*x+A*k. Equal D,P and equal column images of A over F2 and F13 give the same offset set over Z/26 by CRT. Applying the same subsequent gather or independent substitution preserves this equality. Keys remain reconstructible through each original recipe.'}


def expand_paths(grammar,node_id,maximum=10000):
    """Bounded syntax reconstruction from a completed trusted grammar result."""
    integer(maximum,'maximum',1,100000)
    nodes=grammar['nodes'];node=nodes[node_id]
    if node['represented_paths']>maximum:
        raise ValueError("Syntax reconstruction exceeds maximum")
    def expand(index):
        current=nodes[index]
        if not index:
            yield []
        else:
            for edge in current['incoming']:
                for prefix in expand(edge['parent']):
                    yield prefix+[grammar['slots'][current['depth']-1][edge['choice']]]
    return list(expand(node_id))


def literal_encrypt(plaintext,stages,keys,alphabet):
    from .general_layers import _stages
    normalized,width=_stages(stages,len(plaintext),256)
    if len(keys)!=width:raise ValueError("Key count mismatch")
    offset=0;text=plaintext
    for stage in normalized:
        if stage.operation=='gather':text=''.join(text[i] for i in stage.permutation)
        else:
            key=keys[offset:offset+stage.period];offset+=stage.period
            out=[]
            for i,c in enumerate(text):
                p,k=alphabet.index(c),key[i%stage.period]
                value=k-p if stage.cipher=='beaufort' else p-k if stage.cipher=='variant' else p+k
                out.append(alphabet[value%26])
            text=''.join(out)
    return text


def synthesize(request):
    """CEGIS over an explicit bounded recipe bank with keys shared across pairs.

    A key witness is proposed from active examples. Each literal counterexample
    adds constraints and causes another exact solve. Only a contradiction under
    the accumulating examples excludes a recipe. All supplied pairs are checked
    before acceptance; no examples are inferred from claimed K4 plaintext.
    """
    allowed={'recipes','examples','alphabet','priority','initial_examples','max_checks','max_equations','stop_after_first'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError("Unknown recipe synthesis field")
    recipes=request.get('recipes');examples=request.get('examples')
    if not isinstance(recipes,list) or not 1<=len(recipes)<=1000:
        raise ValueError("Supply1..1000 explicit recipe candidates")
    if not isinstance(examples,list) or not 1<=len(examples)<=100:
        raise ValueError("Supply1..100 explicitly sourced plaintext/ciphertext examples")
    from .ciphers import get_alphabet
    alphabet=get_alphabet(request.get('alphabet','standard'))
    n=None
    for pair in examples:
        if not isinstance(pair,dict) or set(pair)!={'plaintext','ciphertext','source'} or not isinstance(pair['source'],str) or not pair['source'].strip():
            raise ValueError("Every example requires plaintext, ciphertext and a source label")
        if any(not isinstance(pair[k],str) or not pair[k] or any(c not in alphabet for c in pair[k]) for k in ('plaintext','ciphertext')):
            raise ValueError("Examples must contain exact alphabet letters")
        n=n or len(pair['plaintext'])
        if len(pair['plaintext'])!=n or len(pair['ciphertext'])!=n or n>512:
            raise ValueError("All examples must have the same length, at most512")
    first=integer(request.get('initial_examples',1),'initial_examples',1,len(examples))
    maximum=integer(request.get('max_checks',100000),'max_checks',1,1000000)
    max_equations=integer(request.get('max_equations',200000),'max_equations',1,2000000)
    priority=request.get('priority',True)
    if type(priority) is not bool:raise ValueError("priority must be Boolean")
    first_witness=request.get('stop_after_first',False)
    if type(first_witness) is not bool:raise ValueError("stop_after_first must be Boolean")
    order=priority_bank(recipes)['recipes'] if priority else [{'input_index':i,'stages':s} for i,s in enumerate(recipes)]
    active=set(range(first));accepted=[];rejected=[]
    work={'recipe_candidates':0,'literal_pair_checks':0,'equation_rows':0,'solver_scalar_operations':0,'counterexamples':0,'key_proposals':0,'compiled_scalar_operations':0}
    for row in order:
        work['recipe_candidates']+=1
        compiled=compile_recipe(n,row['stages'],alphabet=alphabet)
        work['compiled_scalar_operations']+=compiled['scalar_operations']
        width=sum(size for _,_,size in compiled['key_layout'])
        fields=[IncrementalField(width,p) for p in (2,13)]
        added=set();valid=False
        while True:
            for index in sorted(active-added):
                pair=examples[index]
                for j,(source,sign,coeffs) in enumerate(zip(compiled['source_positions'],compiled['plaintext_signs'],compiled['key_coefficients_mod26'])):
                    if work['equation_rows']+2>max_equations:
                        work['solver_scalar_operations']+=sum(f.work for f in fields)
                        return {'complete':False,'stop_reason':'max_equations','accepted':accepted,'rejected':rejected,'work':work}
                    rhs=(alphabet.index(pair['ciphertext'][j])-sign*alphabet.index(pair['plaintext'][source]))%26
                    for field in fields:field.add(coeffs,rhs)
                    work['equation_rows']+=2
                added.add(index)
            if any(field.conflict is not None for field in fields):
                rejected.append({'input_index':row['input_index'],'contradiction_examples':sorted(added)})
                break
            solutions=[field.solution() for field in fields]
            keys=[(13*a+14*b)%26 for a,b in zip(solutions[0]['base'],solutions[1]['base'])][:width]
            work['key_proposals']+=1;failed=None
            for index,pair in enumerate(examples):
                if work['literal_pair_checks']>=maximum:
                    work['solver_scalar_operations']+=sum(f.work for f in fields)
                    return {'complete':False,'stop_reason':'max_checks','accepted':accepted,'rejected':rejected,'work':work}
                work['literal_pair_checks']+=1
                if literal_encrypt(pair['plaintext'],row['stages'],keys,alphabet)!=pair['ciphertext']:
                    failed=index;break
            if failed is None:
                valid=True;break
            if failed in active:raise AssertionError("Matrix key witness failed an active literal example")
            active.add(failed);work['counterexamples']+=1
        work['solver_scalar_operations']+=sum(f.work for f in fields)
        if valid:
            accepted.append({'input_index':row['input_index'],'stages':row['stages'],'key_values':keys,
                             'literal_replay_pairs':len(examples),'technique':'Counterexample-guided recipe/key synthesis with incremental F2/F13 equations and independent literal stage replay'})
            if first_witness:
                return {'schema':'kryptos.recipe-cegis.v1','complete':False,'criterion_first_witness_satisfied':True,
                        'stop_reason':'first_verified_witness','accepted':accepted,'rejected':rejected,'work':work,
                        'interpretation':'Every supplied example is verified. The remaining recipe bank has not been searched or excluded.'}
    return {'schema':'kryptos.recipe-cegis.v1','complete':True,'accepted':accepted,'rejected':rejected,
            'active_examples':sorted(active),'work':work,'authenticated_solution':False,
            'assumptions':'The SAME unknown keys explain every supplied pair. Examples are caller-supplied constraints, not established Kryptos facts.'}


def run(request):
    if not isinstance(request,dict) or set(request)!={'method','parameters'}:
        raise ValueError("Grammar lab requires method and parameters")
    methods={'generate':generate,'synthesize':synthesize,'priority':priority_bank}
    if request['method'] not in methods:raise ValueError("Unknown grammar method")
    return methods[request['method']](request['parameters'])
