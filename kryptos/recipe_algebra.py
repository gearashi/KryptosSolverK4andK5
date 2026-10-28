"""Exact symbolic normal forms for declared substitution/gather recipes.

Compiling never erases shared-key dependencies: every original key residue has
one symbolic column. Substitution signs and transported phase schedules combine
in that same column. Family signatures quotient only independent key freedoms;
the original recipe and its key reconstruction remain separate witnesses.
"""
from itertools import product
from math import prod

from .constraint_lab import ConstraintLimit, digest
from .family_identity import canonical_coset
from .general_layers import ALPHABETS, SIGNS, _stages
from .scheduled_layers import normalize_stages


def compile_recipe(length, stages, *, alphabet="standard", scheduled=False):
    if type(length) is not int or not 1 <= length <= 512:
        raise ValueError("Symbolic recipes require1..512 positions")
    alphabet = ALPHABETS.get(alphabet,alphabet)
    if len(alphabet)!=26 or set(alphabet)!=set(ALPHABETS['standard']):
        raise ValueError("One known shared A-Z alphabet is required")
    if scheduled:
        normalized,layout=normalize_stages(length,stages,default_alphabet=alphabet)
        if any(s.operation=='substitution' and s.alphabet!=alphabet for s in normalized):
            raise ValueError("Symbolic linear compilation requires a shared alphabet")
        offsets={key:(start,size) for key,start,size in layout}
        width=sum(size for key,start,size in layout)
    else:
        normalized,width=_stages(stages,length,256)
        layout=[]
        cursor=0
        for i,stage in enumerate(normalized):
            if stage.operation=='substitution':
                layout.append((f'stage{i}',cursor,stage.period))
                cursor+=stage.period
        offsets={}
    if length*(width+1)>262144:
        raise ConstraintLimit("Symbolic recipe matrix cap")
    source=list(range(length))
    signs=[1]*length
    matrix=[[0]*width for _ in range(length)]
    cursor=work=0
    for stage in normalized:
        if stage.operation=='gather':
            source=[source[i] for i in stage.permutation]
            signs=[signs[i] for i in stage.permutation]
            matrix=[matrix[i] for i in stage.permutation]
            work+=length*(width+2)
        else:
            s,k=SIGNS[stage.cipher]
            start=offsets[stage.key_id][0] if scheduled else cursor
            phases=stage.phases if scheduled else tuple(i%stage.period for i in range(length))
            for i,phase in enumerate(phases):
                signs[i]*=s
                matrix[i]=[(s*x)%26 for x in matrix[i]]
                matrix[i][start+phase]=(matrix[i][start+phase]+k)%26
            if not scheduled:
                cursor+=stage.period
            work+=length*(width+2)
    return {"schema":"kryptos.symbolic-recipe.v1", "alphabet":alphabet,"source_positions":source,
        "plaintext_signs":signs,"key_coefficients_mod26":matrix,"key_layout":[list(x) for x in layout],
        "scalar_operations":work,"original_stages":stages,"scheduled":scheduled,
        "equation":"ciphertext[j] = sign[j]*plaintext[source[j]] + sum(coeff[j,k]*key[k]) mod26"}


def compiled_encrypt(plaintext, key_values, compiled):
    alphabet=compiled['alphabet']
    width=sum(size for key,start,size in compiled['key_layout'])
    if len(plaintext)!=len(compiled['source_positions']) or any(c not in alphabet for c in plaintext):
        raise ValueError("Compiled plaintext length/alphabet mismatch")
    if len(key_values)!=width or any(type(x) is not int or not 0<=x<26 for x in key_values):
        raise ValueError("Supply every original key residue")
    return ''.join(alphabet[(sign*alphabet.index(plaintext[i])+sum(c*k for c,k in zip(row,key_values)))%26]
        for i,sign,row in zip(compiled['source_positions'],compiled['plaintext_signs'],compiled['key_coefficients_mod26']))


def family_from_compiled(ciphertext, compiled):
    alphabet=compiled['alphabet']
    n=len(compiled['source_positions'])
    if len(ciphertext)!=n or any(c not in alphabet for c in ciphertext):
        raise ValueError("Compiled ciphertext length/alphabet mismatch")
    base=[0]*n
    width=sum(size for key,start,size in compiled['key_layout'])
    columns=[[0]*n for _ in range(width)]
    for j,(i,sign,row) in enumerate(zip(compiled['source_positions'],compiled['plaintext_signs'],compiled['key_coefficients_mod26'])):
        base[i]=sign*alphabet.index(ciphertext[j])%26
        for k,coeff in enumerate(row):
            columns[k][i]=-sign*coeff%26
    fields=[canonical_coset(base,columns,p) for p in (2,13)]
    family={"alphabet":alphabet,"fields":fields}
    return {**family,"identity":digest(family),"distinct_plaintext_count":prod(f['prime']**len(f['basis']) for f in fields),
        "interpretation":"Exact uncribbed plaintext-set identity for this fixed ciphertext; identical subsequent literal cribs preserve equality."}


def canonical_phase_partition(phases):
    """Canonical equality partition; also return an inverse label witness."""
    labels={}
    inverse=[]
    canonical=[]
    for value in phases:
        if type(value) is not int or value<0:
            raise ValueError("Phase labels must be nonnegative integers")
        if value not in labels:
            labels[value]=len(labels)
            inverse.append(value)
        canonical.append(labels[value])
    return {"phases":canonical,"original_labels":inverse}


def primitive_key_bank(periods, alphabet, *, max_keys=200000):
    """Enumerate each infinite repeating key once, retaining requested aliases.

    Only divisors of each requested period can be duplicate shorter periods.
    Unrelated periods are never excluded by a period-multiple heuristic.
    """
    if not alphabet or len(set(alphabet))!=len(alphabet) or not periods or any(type(p) is not int or not 1<=p<=128 for p in periods):
        raise ValueError("Explicit distinct key alphabet and periods1..128 required")
    count=sum(len(alphabet)**p for p in periods)
    if count>max_keys:
        raise ConstraintLimit("Primitive key-bank materialization cap")
    keys={}
    for period in periods:
        for symbols in product(alphabet,repeat=period):
            word=''.join(symbols)
            short=next(d for d in range(1,period+1) if period%d==0 and word==word[:d]*(period//d))
            primitive=word[:short]
            keys.setdefault(primitive,set()).add(period)
    return {"keys":[{"primitive":key,"declared_periods":sorted(values)} for key,values in sorted(keys.items(),key=lambda x:(len(x[0]),x[0]))],
        "expanded_keys":count,"distinct_infinite_keys":len(keys),"duplicate_key_evaluations_avoided":count-len(keys)}


def alphabet_affine_equivalence(left,right):
    """Find an invertible numeric relabeling, or decline nonlinear reuse."""
    left=ALPHABETS.get(left,left)
    right=ALPHABETS.get(right,right)
    if len(left)!=26 or len(right)!=26 or set(left)!=set(right) or len(set(left))!=26:
        raise ValueError("Two known A-Z permutation alphabets required")
    images=[right.index(c) for c in left]
    shift=images[0]
    scale=(images[1]-shift)%26
    if scale%2==0 or scale%13==0 or any((scale*i+shift)%26!=x for i,x in enumerate(images)):
        return {"equivalent":False,"reason":"Numeric alphabet relation is not affine modulo26"}
    return {"equivalent":True,"scale":scale,"shift":shift,"inverse_scale":pow(scale,-1,26),
        "convention":"right_index(letter)=scale*left_index(letter)+shift mod26; all key and plaintext coefficients must be transformed as well"}


def compile_autokey(length, seed_length, *, feedback="plaintext", cipher="vigenere"):
    """Linear recurrence for explicit plaintext/ciphertext autokey hypotheses.

    Returns encryption rows in plaintext symbols then seed residues. This
    supports exact equation construction without guessing feedback symbols.
    """
    if type(length) is not int or not 1<=length<=512 or type(seed_length) is not int or not 1<=seed_length<=length:
        raise ValueError("Autokey length1..512 and seed length1..message length required")
    if feedback not in ('plaintext','ciphertext') or cipher not in SIGNS:
        raise ValueError("Explicit autokey feedback and substitution equation required")
    width=length+seed_length
    rows=[]
    s,k=SIGNS[cipher]
    for i in range(length):
        row=[0]*width
        row[i]=s%26
        if i<seed_length:
            row[length+i]=k%26
        elif feedback=='plaintext':
            row[i-seed_length]=(row[i-seed_length]+k)%26
        else:
            row=[(a+k*b)%26 for a,b in zip(row,rows[i-seed_length])]
        rows.append(row)
    return {"schema":"kryptos.autokey-linear.v1","length":length,"seed_length":seed_length,"feedback":feedback,"cipher":cipher,
        "rows_mod26":rows,"convention":"Each output row multiplies [all plaintext symbols, seed residues]. This is an explicit conditional model."}
