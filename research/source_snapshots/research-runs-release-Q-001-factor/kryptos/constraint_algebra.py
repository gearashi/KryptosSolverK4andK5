"""Exact finite-field reductions with explicit scope and reconstructible lifts."""
from dataclasses import replace
from itertools import product
from math import prod

from .constraint_lab import ConstraintLimit
from .family_identity import canonical_coset


class IncrementalField:
    """Incrementally reduce equations over F2/F13, retaining row certificates."""
    def __init__(self, width, prime):
        if type(width) is not int or not 0 <= width <= 512 or prime not in (2, 13):
            raise ValueError("Expected width0..512 and prime2 or13")
        self.width, self.prime = width, prime
        self.rows = {}
        self.equations = []
        self.conflict = None
        self.work = 0

    def add(self, coefficients, rhs):
        if len(coefficients) != self.width or any(type(x) is not int for x in coefficients) or type(rhs) is not int:
            raise ValueError("Malformed integer equation")
        p = self.prime
        row = [x % p for x in coefficients]+[rhs % p]
        ordinal = len(self.equations)
        self.equations.append((tuple(coefficients), rhs))
        weights = {ordinal:1}
        for pivot in sorted(self.rows):
            basis, proof = self.rows[pivot]
            factor = row[pivot]
            if not factor:
                continue
            row = [(a-factor*b) % p for a,b in zip(row,basis)]
            for i,value in proof.items():
                weights[i] = (weights.get(i,0)-factor*value) % p
            self.work += self.width+1+len(proof)
        pivot = next((i for i,x in enumerate(row[:-1]) if x), None)
        weights = {i:x for i,x in weights.items() if x}
        if pivot is None:
            if row[-1] and self.conflict is None:
                self.conflict = {"prime":p, "weights":weights, "residue":row[-1]}
            return self.conflict is None
        inverse = pow(row[pivot], -1, p)
        row = [x*inverse % p for x in row]
        weights = {i:x*inverse % p for i,x in weights.items()}
        self.work += self.width+1+len(weights)
        self.rows[pivot] = (row, weights)
        return self.conflict is None

    def solution(self):
        if self.conflict is not None:
            return None
        p = self.prime
        def back(values, homogeneous):
            values = list(values)
            for pivot in sorted(self.rows, reverse=True):
                row = self.rows[pivot][0]
                values[pivot] = ((0 if homogeneous else row[-1])-sum(row[i]*values[i] for i in range(pivot+1,self.width))) % p
            return values
        base = back([0]*self.width, False)
        basis = []
        for free in range(self.width):
            if free not in self.rows:
                vector = [0]*self.width
                vector[free] = 1
                basis.append(back(vector,True))
        return {"base":base, "basis":basis, "prime":p}


def choose_field(equations, width):
    """Resolve the smaller predicted residual first, while checking both fields.

    Pilot elimination is fully charged. This is a search-order choice, not a
    claim that one modular projection replaces CRT consistency.
    """
    systems = {}
    for p in (2,13):
        system = IncrementalField(width,p)
        for row,rhs in equations:
            if not system.add(row,rhs):
                break
        systems[p] = system
    order = sorted(systems, key=lambda p:(systems[p].conflict is None,
        p**(width-len(systems[p].rows)),p))
    return {"order":order, "scalar_operations":sum(s.work for s in systems.values()),
        "fields":{str(p):{"solution":s.solution(), "conflict":s.conflict} for p,s in systems.items()}}


def crib_difference_constraints(equations, modulus=26):
    """Subtract pairs with identical coefficient support to expose cancellations.

    All original equations are retained. Derived rows are redundant necessary
    constraints, never a guessed key or a replacement for coupled equations.
    """
    if type(modulus) is not int or modulus < 2:
        raise ValueError("modulus must be at least2")
    derived = []
    for i,(left,a) in enumerate(equations):
        for j,(right,b) in enumerate(equations[:i]):
            if len(left) != len(right):
                raise ValueError("Equation widths differ")
            row = [(x-y) % modulus for x,y in zip(left,right)]
            if sum(bool(x) for x in row) < min(sum(bool(x % modulus) for x in left),sum(bool(x % modulus) for x in right)):
                derived.append({"coefficients":row, "rhs":(a-b)%modulus,
                    "source_weights":[[i,1],[j,modulus-1]]})
    return derived


def _member(vector, canonical):
    p = canonical["prime"]
    reduced = [x % p for x in vector]
    for row in canonical["basis"]:
        pivot = next(i for i,x in enumerate(row) if x)
        factor = reduced[pivot]
        reduced = [(x-factor*y)%p for x,y in zip(reduced,row)]
    return not any(reduced)


def affine_relation(left, right, prime):
    """Exact inclusion and intersection of two finite affine plaintext sets.

    Inputs have base and basis (generator rows). The returned intersection is
    canonical and can be empty. Different alphabets must be converted by the
    caller only when the conversion is proved affine.
    """
    a = canonical_coset(left["base"],left.get("basis",[]),prime)
    b = canonical_coset(right["base"],right.get("basis",[]),prime)
    if len(a["base"]) != len(b["base"]):
        raise ValueError("Affine ambient dimensions differ")
    left_in_right = _member([x-y for x,y in zip(a["base"],b["base"])],b) and all(_member(row,b) for row in a["basis"])
    right_in_left = _member([x-y for x,y in zip(b["base"],a["base"])],a) and all(_member(row,a) for row in b["basis"])
    system = IncrementalField(len(a["basis"])+len(b["basis"]),prime)
    for i in range(len(a["base"])):
        system.add([row[i] for row in a["basis"]]+[-row[i] for row in b["basis"]], b["base"][i]-a["base"][i])
    solution = system.solution()
    intersection = None
    if solution is not None:
        def image(values):
            return [sum(row[i]*x for row,x in zip(a["basis"],values))%prime for i in range(len(a["base"]))]
        base = [(x+y)%prime for x,y in zip(a["base"],image(solution["base"]))]
        intersection = canonical_coset(base,[image(vector) for vector in solution["basis"]],prime)
    return {"left_subset_right":left_in_right, "right_subset_left":right_in_left,
        "intersection":intersection, "intersection_size":0 if intersection is None else prime**len(intersection["basis"]),
        "scalar_operations":system.work}


def sparse_field(field, max_trials=10000):
    """Invertible elementary basis changes, with exactly corresponding key lifts.

    A replacement col_i <- col_i+t col_j is invertible. Accept it only if it
    strictly lowers total nonzero plaintext coefficients. This is local sparsity
    optimization, not a minimum-basis certificate.
    """
    if type(max_trials) is not int or not 0 <= max_trials <= 1000000:
        raise ValueError("max_trials must be0..1000000")
    if not field.feasible:
        return field, {"trials":0,"before":0,"after":0,"changes":[]}
    columns = [list(x) for x in field.plaintext_columns]
    lifts = [list(x) for x in field.key_lifts]
    p = field.modulus
    before = sum(bool(x) for row in columns for x in row)
    changes, trials = [], 0
    changed = True
    while changed and trials < max_trials:
        changed = False
        for i in range(len(columns)):
            for j in range(len(columns)):
                if i == j:
                    continue
                for t in range(1,p):
                    if trials >= max_trials:
                        break
                    trials += 1
                    candidate = [(x+t*y)%p for x,y in zip(columns[i],columns[j])]
                    if sum(bool(x) for x in candidate) < sum(bool(x) for x in columns[i]):
                        columns[i] = candidate
                        lifts[i] = [(x+t*y)%p for x,y in zip(lifts[i],lifts[j])]
                        changes.append([i,j,t])
                        changed = True
    result = replace(field, plaintext_columns=tuple(tuple(x) for x in columns),key_lifts=tuple(tuple(x) for x in lifts))
    return result, {"trials":trials,"before":before,"after":sum(bool(x) for row in columns for x in row),"changes":changes}


def plaintext_coordinate_field(field):
    """Use selected plaintext residues as independent field coordinates.

    Full Gauss-Jordan elimination acts on generator rows and their key lifts
    together. The base is shifted along these rows so every pivot plaintext
    coordinate equals its new search variable. The affine set is unchanged.
    """
    if not field.feasible:
        return field, {'positions':[],'scalar_operations':0}
    p=field.modulus
    columns=[list(x) for x in field.plaintext_columns]
    lifts=[list(x) for x in field.key_lifts]
    pivots=[]
    top=work=0
    for position in range(len(field.plaintext_base)):
        pivot=next((i for i in range(top,len(columns)) if columns[i][position]),None)
        if pivot is None:
            continue
        columns[top],columns[pivot]=columns[pivot],columns[top]
        lifts[top],lifts[pivot]=lifts[pivot],lifts[top]
        inverse=pow(columns[top][position],-1,p)
        columns[top]=[x*inverse%p for x in columns[top]]
        lifts[top]=[x*inverse%p for x in lifts[top]]
        work+=len(columns[top])+len(lifts[top])
        for i in range(len(columns)):
            if i==top:
                continue
            factor=columns[i][position]
            if factor:
                columns[i]=[(a-factor*b)%p for a,b in zip(columns[i],columns[top])]
                lifts[i]=[(a-factor*b)%p for a,b in zip(lifts[i],lifts[top])]
                work+=len(columns[i])+len(lifts[i])
        pivots.append(position)
        top+=1
        if top==len(columns):
            break
    base=list(field.plaintext_base)
    key_base=list(field.key_base)
    for position,column,lift in zip(pivots,columns,lifts):
        shift=base[position]
        base=[(a-shift*b)%p for a,b in zip(base,column)]
        key_base=[(a-shift*b)%p for a,b in zip(key_base,lift)]
        work+=len(base)+len(key_base)
    result=replace(field,plaintext_base=tuple(base),key_base=tuple(key_base),
        plaintext_columns=tuple(tuple(x) for x in columns),key_lifts=tuple(tuple(x) for x in lifts))
    return result, {'positions':pivots,'scalar_operations':work,'convention':'field plaintext residue at each selected position equals the corresponding search coordinate'}


def disjoint_finite_cover(families, *, max_points=200000):
    """Canonical disjoint ownership of explicit small affine families.

    This bounded path materializes points; it is useful only for repeated,
    heavily overlapping small families. Algebraic intersection is separate.
    """
    counts = [f["prime"]**len(f["basis"]) for f in families]
    if sum(counts) > max_points:
        raise ConstraintLimit("Finite cover materialization cap")
    owners = {}
    aliases = {}
    for label,family in enumerate(families):
        p = family["prime"]
        for values in product(range(p), repeat=len(family["basis"])):
            point = tuple((x+sum(row[i]*v for row,v in zip(family["basis"],values)))%p for i,x in enumerate(family["base"]))
            owners.setdefault(point,label)
            aliases.setdefault(point,[]).append(label)
    return {"blocks":[{"owner":i,"points":[list(p) for p,owner in sorted(owners.items()) if owner==i]} for i in range(len(families))],
        "aliases":[{"point":list(p),"families":sorted(set(ids))} for p,ids in sorted(aliases.items())],
        "input_assignments":sum(counts),"distinct_points":len(owners),"duplicate_evaluations_avoided":sum(counts)-len(owners)}
