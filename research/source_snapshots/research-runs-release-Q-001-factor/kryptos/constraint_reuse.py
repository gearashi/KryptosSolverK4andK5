"""Certified bounded reuse primitives for finite relation experiments."""
from itertools import permutations, product
from math import factorial, prod

from .constraint_lab import normalize, ConstraintLimit, digest, RelationSearch


def residual_signature(names, domains, relations, *, isomorphic=False, charge=lambda *args:None):
    """Hash the exact remaining hard relation function, with optional renaming.

    All fixed coordinates are substituted before canonicalization. Automatic
    isomorphism tries every variable renaming only for at most6 variables; it
    falls back to a fixed order otherwise. Variable value labels are retained.
    """
    remaining=tuple(v for v in names if len(domains[v])>1)
    reduced=[]
    for relation in relations:
        scope=tuple(v for v in relation['scope'] if v in remaining)
        indices=[relation['scope'].index(v) for v in scope]
        rows=set()
        for row in relation['rows']:
            charge('residual_signature_rows')
            if all(x in domains[v] for v,x in zip(relation['scope'],row)):
                rows.add(tuple(row[i] for i in indices))
        if len(rows)==prod(len(domains[v]) for v in scope):
            continue
        reduced.append((scope,rows))
    orders=permutations(remaining) if isomorphic and len(remaining)<=6 else (remaining,)
    best=None
    for order in orders:
        charge('residual_renamings')
        index={v:i for i,v in enumerate(order)}
        tables=[]
        for scope,rows in reduced:
            positions=sorted(range(len(scope)),key=lambda i:index[scope[i]])
            tables.append((tuple(index[scope[i]] for i in positions),tuple(sorted(tuple(row[i] for i in positions) for row in rows))))
        representation=(tuple(domains[v] for v in order),tuple(sorted(set(tables))))
        if best is None or representation<best:
            best=representation
    return digest(best)


def transfer_conflicts(source_request, learned, target_request, rename=None):
    """Reverify source clauses then transfer only to a structurally stronger model.

    Target domains may narrow and target rows may be subsets of source rows;
    every source relation must be covered. Arbitrary missing hypotheses fail.
    """
    source=RelationSearch({**source_request,'learned':learned})
    names,domains,relations,factors=normalize(target_request)
    rename=rename or {v:v for v in source.names}
    if set(rename)!=set(source.names) or len(set(rename.values()))!=len(rename) or any(v not in domains for v in rename.values()):
        raise ValueError('Conflict transfer needs an injective explicit variable map')
    for v,values in source.domains.items():
        if not set(domains[rename[v]])<=set(values):
            raise ValueError('Target domain does not imply source domain')
    for relation in source.relations:
        scope=tuple(rename[v] for v in relation['scope'])
        source_rows=set(relation['rows'])
        covered=False
        for target in relations:
            if set(target['scope'])!=set(scope):
                continue
            positions=[target['scope'].index(v) for v in scope]
            rows={tuple(row[i] for i in positions) for row in target['rows']}
            if rows<=source_rows:
                covered=True
                break
        if not covered:
            raise ValueError('Target model does not structurally imply a required source relation')
    hard=digest({'domains':domains,'relations':relations})
    return {'hard_identity':hard,'nogoods':[[[rename[v],x] for v,x in clause] for clause in source.nogoods],
        'verification_work':dict(source.work),'guard':'Every source relation is implied by a target table; domains only narrow; original clauses independently reverified'}


def dominates_one_best(request, *, max_assignments=200000):
    """Bounded proof of value replacement for ONE best solution only.

    Every feasible assignment using the removed value must map to a feasible
    assignment using the kept value with a greater score, or an equal score
    with a lexicographically earlier complete assignment. Top-k/all-solution
    coverage is deliberately not asserted.
    """
    engine=RelationSearch(request)
    total=prod(len(v) for v in engine.domains.values())
    if total*sum(len(v)**2 for v in engine.domains.values())>max_assignments:
        raise ConstraintLimit('Dominance proof assignment cap')
    domains=dict(engine.domains)
    proofs=[]
    checks=0
    for variable in engine.names:
        others=[v for v in engine.names if v!=variable]
        for removed in tuple(domains[variable]):
            for kept in tuple(domains[variable]):
                if removed==kept or removed not in domains[variable]:
                    continue
                valid=True
                witnessed=False
                for values in product(*(domains[v] for v in others)):
                    assignment=dict(zip(others,values))
                    assignment[variable]=removed
                    checks+=1
                    if not engine.literal_feasible(assignment):
                        continue
                    witnessed=True
                    score=engine.score(assignment)
                    assignment[variable]=kept
                    if not engine.literal_feasible(assignment):
                        valid=False
                        break
                    replacement=engine.score(assignment)
                    if replacement<score or replacement==score and kept>removed:
                        valid=False
                        break
                if valid and witnessed:
                    domains[variable]=tuple(x for x in domains[variable] if x!=removed)
                    proofs.append({'variable':variable,'removed':removed,'kept':kept})
                    break
    restricted={k:v for k,v in request.items() if k!='learned'}
    restricted['domains']={v:list(x) for v,x in domains.items()}
    for kind in ('relations','factors'):
        restricted[kind]=[{**table,'rows':[row for row in table['rows'] if all(value in domains[v] for v,value in zip(table['scope'],row))]} for table in request.get(kind,[])]
    return {'domains':restricted['domains'],'problem':restricted,'proofs':proofs,'preparation_assignments':checks,
        'proof_work':dict(engine.work),'scope':'one-best only; not valid for top-k or all-solution enumeration'}


def score_projection_groups(affine, positions, *, max_assignments=200000):
    """Group score-invisible freedoms while preserving every full-text tie.

    This finite helper returns one score representative and all reconstruction
    coordinates per group. Ranking may score each representative once but must
    expand its ties before applying the caller's top-k convention.
    """
    count=prod(affine['domains'])
    if count>max_assignments:
        raise ConstraintLimit('Score projection materialization cap')
    if len(set(positions))!=len(positions) or any(type(i) is not int or not 0<=i<len(affine['base']) for i in positions):
        raise ValueError('Score projection positions must be distinct message positions')
    groups={}
    for values in product(*(range(size) for size in affine['domains'])):
        projected=tuple((affine['base'][i]+sum(col[i]*v for col,v in zip(affine['columns'],values)))%26 for i in positions)
        groups.setdefault(projected,[]).append(values)
    return {'groups':[{'projected_letters':list(p),'representative':list(v[0]),'all_tie_coordinates':[list(x) for x in v]} for p,v in sorted(groups.items())],
        'input_assignments':count,'scoring_evaluations':len(groups),'reconstruction_assignments':count,
        'scope':'Valid only for objectives depending exclusively on the declared positions; all ties retained'}


def enumerate_components(request, *, separator=(), max_rows=200000):
    """Exact separator decomposition of hard relations with explicit witnesses.

    A caller can reuse each component's conditional relation independently.
    Objective factors are intentionally rejected here: top-k score composition
    belongs to the factor optimizer, not a feasibility-only product.
    """
    names,domains,relations,factors=normalize(request)
    if factors:
        raise ValueError('Feasibility component enumeration does not accept score factors')
    if any(v not in domains for v in separator) or len(set(separator))!=len(separator):
        raise ValueError('Separator must name distinct declared variables')
    remaining=set(names)-set(separator)
    graph={v:set() for v in remaining}
    for relation in relations:
        scope=set(relation['scope'])&remaining
        for v in scope:
            graph[v]|=scope-{v}
    components=[]
    while remaining:
        todo=[min(remaining)]
        found=set()
        while todo:
            v=todo.pop()
            if v in found:
                continue
            found.add(v)
            todo.extend(graph[v]-found)
        remaining-=found
        components.append(tuple(sorted(found)))
    bound=(sum(prod(len(domains[v]) for v in tuple(separator)+component) for component in components)
        if components else prod(len(domains[v]) for v in separator))
    if bound>max_rows:
        raise ConstraintLimit('Component conditional enumeration cap')
    output=[]
    checks=0
    for component in components:
        scope=tuple(separator)+component
        local=[r for r in relations if set(r['scope'])<=set(scope)]
        rows=[]
        for values in product(*(domains[v] for v in scope)):
            assignment=dict(zip(scope,values))
            checks+=1
            if all(tuple(assignment[v] for v in relation['scope']) in relation['rows'] for relation in local):
                rows.append(list(values))
        output.append({'scope':list(scope),'rows':rows})
    if not components:
        scope=tuple(separator)
        rows=[]
        for values in product(*(domains[v] for v in scope)):
            assignment=dict(zip(scope,values))
            checks+=1
            if all(tuple(assignment[v] for v in r['scope']) in r['rows'] for r in relations):
                rows.append(list(values))
        output.append({'scope':list(scope),'rows':rows})
    return {'components':output,'separator':list(separator),'component_assignment_checks':checks,
        'full_cartesian_reference':prod(map(len,domains.values())),
        'combination':'Natural join on separator values; relations and all witnesses retained'}
