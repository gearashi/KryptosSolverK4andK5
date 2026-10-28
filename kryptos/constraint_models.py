"""Explicit conditional cipher adapters for finite relation/algebra backends."""
from itertools import product
from math import prod

from .constraint_algebra import IncrementalField
from .constraint_lab import ConstraintLimit, _int, run as run_relations
from .general_layers import ALPHABETS, SIGNS
from .recipe_algebra import compile_autokey


def autokey(request):
    allowed={'ciphertext','cribs','seed_length','feedback','cipher','alphabet','max_candidates'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError('Unknown autokey field')
    from .columnar import _inputs
    text,known,_,_,_=_inputs(request.get('ciphertext'),request.get('cribs',[]),1,None,'top_to_bottom')
    n=len(text)
    if n>256:
        raise ValueError('Autokey adapter supports at most256 symbols')
    alphabet=ALPHABETS.get(request.get('alphabet','standard'),request.get('alphabet','standard'))
    if not isinstance(alphabet,str) or len(alphabet)!=26 or set(alphabet)!=set(ALPHABETS['standard']):
        raise ValueError('One known A-Z alphabet required')
    seed=request.get('seed_length',1)
    compiled=compile_autokey(n,seed,feedback=request.get('feedback','plaintext'),cipher=request.get('cipher','vigenere'))
    width=n+seed
    equations=[(row,alphabet.index(c)) for row,c in zip(compiled['rows_mod26'],text)]
    for i,c in known.items():
        row=[0]*width
        row[i]=1
        equations.append((row,alphabet.index(c)))
    systems=[]
    for p in (2,13):
        system=IncrementalField(width,p)
        for row,rhs in equations:
            system.add(row,rhs)
        systems.append(system)
    if any(s.conflict is not None for s in systems):
        return {'schema':'kryptos.autokey-search.v1','feasible':False,'complete':True,'candidates':[],
            'conflicts':[s.conflict for s in systems if s.conflict is not None]}
    fields=[s.solution() for s in systems]
    count=prod(p**len(f['basis']) for p,f in zip((2,13),fields))
    maximum=_int(request.get('max_candidates',676),'max_candidates',1,200000)
    result={'schema':'kryptos.autokey-search.v1','feasible':True,'complete':count<=maximum,'candidate_count':count,
        'scalar_operations':sum(s.work for s in systems),'candidates':[],'authenticated_solution':False,
        'assumptions':{'feedback':compiled['feedback'],'cipher':compiled['cipher'],'alphabet':alphabet,'seed_length':seed}}
    if count>maximum:
        result['limit']='Exact family exceeds max_candidates; no arbitrary partial sample emitted'
        return result
    for aa in product(range(2),repeat=len(fields[0]['basis'])):
        for bb in product(range(13),repeat=len(fields[1]['basis'])):
            residues=[]
            for p,f,values in zip((2,13),fields,(aa,bb)):
                residues.append([(x+sum(row[i]*v for row,v in zip(f['basis'],values)))%p for i,x in enumerate(f['base'])])
            values=[(13*a+14*b)%26 for a,b in zip(*residues)]
            plain=''.join(alphabet[x] for x in values[:n])
            key=''.join(alphabet[x] for x in values[n:])
            # Literal feedback replay is independent of the compiled matrix.
            output=[]
            s,k=SIGNS[compiled['cipher']]
            for i,c in enumerate(plain):
                keyletter=key[i] if i<seed else (plain if compiled['feedback']=='plaintext' else ''.join(output))[i-seed]
                output.append(alphabet[(s*alphabet.index(c)+k*alphabet.index(keyletter))%26])
            if ''.join(output)!=text or any(plain[i]!=c for i,c in known.items()):
                raise AssertionError('Autokey candidate failed literal feedback replay')
            result['candidates'].append({'plaintext':plain,'seed_key':key,'reencrypted_ciphertext':text,'reencryption_matches':True,
                'technique':'Exact F2/F13 feedback equations followed by literal autokey replay'})
    return result


def fractionation_relation(input_variables, output_variables, *, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ', rows=2, columns=13, max_rows=200000):
    """A whole-block correlated relation, never independent digit marginals."""
    from .fractionation import fractionate_encrypt
    if not input_variables or len(input_variables)!=len(output_variables) or len(set(input_variables+output_variables))!=len(input_variables+output_variables):
        raise ValueError('Distinct equal-length input/output variable lists required')
    n=len(input_variables)
    count=len(alphabet)**n
    if count>max_rows:
        raise ConstraintLimit('Fractionation block relation cap')
    tuples=[]
    for values in product(range(len(alphabet)),repeat=n):
        plain=''.join(alphabet[x] for x in values)
        encoded=fractionate_encrypt(plain,alphabet=alphabet,rows=rows,columns=columns,period=n)
        tuples.append(list(values)+[alphabet.index(c) for c in encoded])
    return {'scope':list(input_variables)+list(output_variables),'rows':tuples}


def null_padding(request):
    """Joint pad placement/key recovery for explicit insertion-before-key model.

    Ciphertext positions retain key phases. A monotone cursor counts retained
    letters; supplied cribs refer to that unpadded stream. Dropped letters must
    belong to the explicitly supplied null-symbol alphabet.
    """
    allowed={'ciphertext','cribs','period','null_count','null_symbols','cipher','alphabet','options','top','max_work','max_solutions'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError('Unknown null-padding field')
    from .columnar import _letters
    ciphertext=_letters(request.get('ciphertext'),'ciphertext')
    n=len(ciphertext)
    if n>128:
        raise ValueError('Null-padding messages are capped at128 symbols')
    null_count=_int(request.get('null_count',1),'null_count',0,n-1)
    length=n-null_count
    period=_int(request.get('period',1),'period',1,min(n,32))
    alphabet=ALPHABETS.get(request.get('alphabet','standard'),request.get('alphabet','standard'))
    if not isinstance(alphabet,str) or len(alphabet)!=26 or set(alphabet)!=set(ALPHABETS['standard']):
        raise ValueError('One known A-Z alphabet required')
    null_symbols=request.get('null_symbols')
    if not isinstance(null_symbols,str) or not null_symbols or any(c not in alphabet for c in null_symbols):
        raise ValueError('Explicit null symbols are required')
    cipher=request.get('cipher','vigenere')
    if cipher not in SIGNS:
        raise ValueError('Unsupported substitution equation')
    known={}
    for crib in request.get('cribs',[]):
        if not isinstance(crib,dict) or set(crib)!={'start','text'}:
            raise ValueError('Cribs require one-based start and text')
        start=_int(crib['start'],'crib start',1,length)-1
        text=_letters(crib['text'],'crib text')
        if start+len(text)>length:
            raise ValueError('Crib extends past the unpadded message')
        for i,c in enumerate(text,start):
            if i in known and known[i]!=c:
                raise ValueError('Contradictory unpadded cribs')
            known[i]=c
    cursors=[f'p{i:04d}' for i in range(n+1)]
    keys=[f'k{i:04d}' for i in range(period)]
    domains={v:list(range(26)) for v in keys}
    domains.update({v:list(range(max(0,i-null_count),min(i,length)+1)) for i,v in enumerate(cursors)})
    domains[cursors[0]]=[0]
    domains[cursors[-1]]=[length]
    relations=[]
    rows_built=0
    def decode(c,key):
        value=alphabet.index(c)
        return alphabet[(key-value if cipher=='beaufort' else value+key if cipher=='variant' else value-key)%26]
    for i,c in enumerate(ciphertext):
        rows=[]
        for before in domains[cursors[i]]:
            for after in domains[cursors[i+1]]:
                if after-before not in (0,1):
                    continue
                for key in range(26):
                    plain=decode(c,key)
                    if (after==before and plain in null_symbols) or (after==before+1 and (before not in known or known[before]==plain)):
                        rows.append([before,after,key])
        rows_built+=len(rows)
        if rows_built>200000:
            raise ConstraintLimit('Null-padding transition-table cap')
        relations.append({'scope':[cursors[i],cursors[i+1],keys[i%period]],'rows':rows})
    result=run_relations({'domains':domains,'relations':relations,
        **{k:v for k,v in request.items() if k in ('options','top','max_work','max_solutions')}})
    candidates=[]
    for row in result['candidates']:
        values=row['assignment']
        key=''.join(alphabet[values[v]] for v in keys)
        padded=''.join(decode(c,values[keys[i%period]]) for i,c in enumerate(ciphertext))
        removed=[i for i in range(n) if values[cursors[i]]==values[cursors[i+1]]]
        plain=''.join(c for i,c in enumerate(padded) if i not in removed)
        s,k=SIGNS[cipher]
        replay=''.join(alphabet[(s*alphabet.index(c)+k*alphabet.index(key[i%period]))%26] for i,c in enumerate(padded))
        if replay!=ciphertext or len(removed)!=null_count or any(padded[i] not in null_symbols for i in removed) or any(plain[i]!=c for i,c in known.items()):
            raise AssertionError('Null-placement/key witness failed literal replay')
        candidates.append({'plaintext':plain,'padded_plaintext':padded,'removed_positions_zero_based':removed,'key':key,
            'reencryption_matches':True,'reencrypted_ciphertext':replay,'technique':'Joint cursor/phase relation propagation and literal null insertion replay'})
    result.update(schema='kryptos.null-padding-search.v1',candidates=candidates,preparation={'transition_rows':rows_built},
        assumptions={'insertion_before_substitution':True,'null_count':null_count,'null_symbols':null_symbols,'period':period,'cipher':cipher})
    return result


def unknown_alphabet_routes(request):
    """Joint SMT model of a bijective alphabet, finite route bank, and key.

    Only the supplied route bank is searched. No arbitrary alphabet ordering is
    fixed by a hidden gauge assumption. Returned full texts are literal replayed.
    """
    try:
        import z3
    except ImportError as exc:
        raise ValueError('Install requirements-sat.txt for unknown-alphabet routes') from exc
    allowed={'ciphertext','cribs','routes','period','cipher','max_candidates','timeout_ms','alphabet_known'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError('Unknown alphabet/route field')
    from .columnar import _inputs
    text,known,_,_,_=_inputs(request.get('ciphertext'),request.get('cribs',[]),1,None,'top_to_bottom')
    n=len(text)
    period=_int(request.get('period',1),'period',1,min(n,64))
    cipher=request.get('cipher','vigenere')
    if cipher not in SIGNS:
        raise ValueError('Unsupported cipher')
    routes=request.get('routes')
    if not isinstance(routes,list) or not 1<=len(routes)<=128 or any(not isinstance(r,list) or sorted(r)!=list(range(n)) for r in routes):
        raise ValueError('Supply1..128 complete gather permutations')
    maximum=_int(request.get('max_candidates',20),'max_candidates',1,1000)
    solver=z3.Solver()
    solver.set(timeout=_int(request.get('timeout_ms',10000),'timeout_ms',1,600000))
    alphabet={c:z3.Int(f'a{i}') for i,c in enumerate(ALPHABETS['standard'])}
    key=[z3.Int(f'k{i}') for i in range(period)]
    route=z3.Int('route')
    solver.add(z3.Distinct(*alphabet.values()),route>=0,route<len(routes))
    for value in list(alphabet.values())+key:
        solver.add(value>=0,value<26)
    partial=request.get('alphabet_known',{})
    if not isinstance(partial,dict) or any(c not in alphabet or type(value) is not int or not 0<=value<26 for c,value in partial.items()):
        raise ValueError('alphabet_known maps explicit letters to residues0..25')
    for c,value in partial.items():
        solver.add(alphabet[c]==value)
    s,k=SIGNS[cipher]
    for index,permutation in enumerate(routes):
        constraints=[]
        for j,i in enumerate(permutation):
            if i in known:
                constraints.append(alphabet[text[j]]==(s*alphabet[known[i]]+k*key[i%period])%26)
        solver.add(z3.Implies(route==index,z3.And(*constraints)))
    candidates=[]
    checks=0
    complete=False
    reason=None
    while len(candidates)<maximum:
        checks+=1
        status=solver.check()
        if status==z3.unsat:
            complete=True
            break
        if status!=z3.sat:
            reason=solver.reason_unknown()
            break
        model=solver.model()
        table={c:model.eval(x).as_long() for c,x in alphabet.items()}
        letters=''.join(sorted(table,key=table.get))
        residues=[model.eval(x,model_completion=True).as_long() for x in key]
        selected=model.eval(route).as_long()
        plain=['']*n
        for j,i in enumerate(routes[selected]):
            plain[i]=letters[(s*(table[text[j]]-k*residues[i%period]))%26]
        plain=''.join(plain)
        replay=''.join(letters[(s*table[plain[i]]+k*residues[i%period])%26] for i in routes[selected])
        if replay!=text or any(plain[i]!=c for i,c in known.items()):
            raise AssertionError('Unknown alphabet/route witness failed literal replay')
        candidates.append({'plaintext':plain,'alphabet':letters,'key':''.join(letters[x] for x in residues),
            'route_index':selected,'permutation':routes[selected],'reencrypted_ciphertext':replay,'reencryption_matches':True,
            'technique':'Joint finite-bank route, bijective-alphabet and repeating-key SMT constraints'})
        solver.add(z3.Or(route!=selected,*(x!=table[c] for c,x in alphabet.items()),*(x!=v for x,v in zip(key,residues))))
    if len(candidates)==maximum:
        reason='max_candidates (exhaustion not checked)'
    return {'schema':'kryptos.unknown-alphabet-routes.v1','candidates':candidates,'complete':complete,'limit':reason,
        'work':{'solver_checks':checks,'full_candidate_replays':len(candidates)},'authenticated_solution':False,
        'assumptions':{'stage_order':'substitution then gather','route_count':len(routes),'period':period,'cipher':cipher,'alphabet_known':partial}}
