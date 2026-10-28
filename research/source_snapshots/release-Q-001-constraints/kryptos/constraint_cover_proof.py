"""Portable exact subtree-coverage proofs for separate finite-model runs.

Artifacts are data, not trusted cache hits. Every contradiction, split, bound
and candidate is checked again before a later run may suppress that region.
Reverification work is reported separately and can outweigh saved decisions.
"""
from .constraint_lab import RelationSearch, ConstraintLimit, _int


def _assumptions(engine, values):
    if not isinstance(values,dict) or any(v not in engine.domains or type(x) is not int or x not in engine.domains[v] for v,x in values.items()):
        raise ValueError('Coverage assumptions must assign declared variable values')
    return {v:values[v] for v in sorted(values)}


def _rank(engine, row):
    return -row[0],row[1]


def create(request):
    if not isinstance(request,dict) or set(request)-{'problem','assumptions','max_proof_nodes'}:
        raise ValueError('Coverage proof needs problem and optional assumptions/max_proof_nodes')
    problem=request.get('problem')
    if not isinstance(problem,dict) or 'coverage' in problem or 'learned' in problem:
        raise ValueError('Generate coverage from the original explicit problem without imported artifacts')
    engine=RelationSearch(problem)
    assumptions=_assumptions(engine,request.get('assumptions',{}))
    maximum=_int(request.get('max_proof_nodes',100000),'max_proof_nodes',1,200000)
    nodes=0
    def walk(domains):
        nonlocal nodes
        nodes+=1
        engine.tick('coverage_generation_nodes')
        if nodes>maximum:
            raise ConstraintLimit('max_proof_nodes')
        domains=engine.propagate(domains,use_clauses=False)
        if domains is None:
            return {'kind':'conflict'}
        threshold=engine.retained[-1][0] if len(engine.retained)==engine.top else None
        if threshold is not None and engine.upper(domains)<threshold:
            return {'kind':'bound'}
        unknown=[v for v in engine.names if len(domains[v])>1]
        if not unknown:
            assignment={v:domains[v][0] for v in engine.names}
            engine.tick('coverage_generation_complete_evaluations')
            if not engine.literal_feasible(assignment):
                raise AssertionError('Propagated coverage leaf failed literal constraints')
            score=engine.score(assignment)
            engine.retained.append((score,tuple(assignment[v] for v in engine.names)))
            engine.retained.sort(key=lambda row:_rank(engine,row))
            del engine.retained[engine.top:]
            return {'kind':'leaf'}
        variable=unknown[0]
        children=[]
        for value in domains[variable]:
            child=dict(domains)
            child[variable]=(value,)
            engine.tick('coverage_generation_branch_decisions')
            children.append([value,walk(child)])
        return {'kind':'split','variable':variable,'children':children}
    domains=dict(engine.domains)
    domains.update({v:(x,) for v,x in assumptions.items()})
    try:
        tree=walk(domains)
    except ConstraintLimit as error:
        return {'schema':'kryptos.subtree-coverage-generation.v1','complete':False,'limit':str(error),'coverage':None,'work':dict(engine.work)}
    artifact={'schema':'kryptos.subtree-coverage.v1','hard_identity':engine.hard_identity,'objective_identity':engine.objective_identity,
        'assumptions':assumptions,'top':engine.top,'tree':tree,
        'candidates':[{'assignment':dict(zip(engine.names,values)),'score':score} for score,values in engine.retained]}
    return {'schema':'kryptos.subtree-coverage-generation.v1','complete':True,'coverage':artifact,'work':dict(engine.work),
        'authenticated_solution':False,'interpretation':'A complete finite-model subtree proof. Later runs must revalidate this JSON artifact before reusing coverage.'}


def verify(engine, artifact):
    if not isinstance(artifact,dict) or set(artifact)!={'schema','hard_identity','objective_identity','assumptions','top','tree','candidates'}:
        raise ValueError('Malformed subtree coverage artifact')
    if artifact['schema']!='kryptos.subtree-coverage.v1' or artifact['hard_identity']!=engine.hard_identity or artifact['objective_identity']!=engine.objective_identity:
        raise ValueError('Coverage belongs to another hard model or objective')
    top=_int(artifact['top'],'coverage top',1,1000)
    if top<engine.top:
        raise ValueError('Coverage stores fewer ranked candidates than this run requests')
    assumptions=_assumptions(engine,artifact['assumptions'])
    raw=artifact['candidates']
    if not isinstance(raw,list) or len(raw)>top:
        raise ValueError('Coverage candidate count exceeds its rank limit')
    declared=[]
    for row in raw:
        if not isinstance(row,dict) or set(row)!={'assignment','score'}:
            raise ValueError('Malformed coverage candidate')
        assignment=row['assignment']
        _assumptions(engine,assignment)
        if set(assignment)!=set(engine.names) or any(assignment[v]!=x for v,x in assumptions.items()):
            raise ValueError('Coverage candidate lies outside its region')
        engine.tick('coverage_candidate_reverification')
        if not engine.literal_feasible(assignment):
            raise ValueError('Coverage candidate violates a hard relation')
        score=engine.score(assignment)
        if type(row['score']) is not int or row['score']!=score:
            raise ValueError('Coverage candidate score is invalid')
        declared.append((score,tuple(assignment[v] for v in engine.names)))
    if len(set(declared))!=len(declared) or declared!=sorted(declared,key=lambda row:_rank(engine,row)):
        raise ValueError('Coverage candidates must be unique and canonically ranked')
    threshold=declared[-1][0] if len(declared)==top else None
    leaves=[]
    nodes=0
    def walk(domains,node,depth=0):
        nonlocal nodes
        nodes+=1
        engine.tick('coverage_proof_reverification_nodes')
        if nodes>200000 or depth>len(engine.names):
            raise ValueError('Coverage proof shape exceeds its bounds')
        if not isinstance(node,dict) or not isinstance(node.get('kind'),str):
            raise ValueError('Malformed coverage proof node')
        domains=engine.propagate(domains,use_clauses=False)
        kind=node['kind']
        if kind=='conflict':
            if set(node)!={'kind'} or domains is not None:
                raise ValueError('Coverage conflict node is not contradictory')
            return
        if domains is None:
            raise ValueError('Coverage proof node shape disagrees with contradiction')
        if kind=='bound':
            if set(node)!={'kind'} or threshold is None or engine.upper(domains)>=threshold:
                raise ValueError('Coverage bound cannot exclude this region at the stored threshold')
            return
        if kind=='leaf':
            if set(node)!={'kind'} or any(len(values)!=1 for values in domains.values()):
                raise ValueError('Coverage leaf is not a complete assignment')
            assignment={v:domains[v][0] for v in engine.names}
            engine.tick('coverage_leaf_reverification')
            if not engine.literal_feasible(assignment):
                raise ValueError('Coverage leaf violates a hard relation')
            leaves.append((engine.score(assignment),tuple(assignment[v] for v in engine.names)))
            return
        if kind!='split' or set(node)!={'kind','variable','children'}:
            raise ValueError('Unknown coverage proof node')
        variable=node['variable']
        if not isinstance(variable,str) or variable not in domains or len(domains[variable])<=1:
            raise ValueError('Coverage split must choose an unresolved variable')
        children=node['children']
        if not isinstance(children,list) or any(not isinstance(pair,list) or len(pair)!=2 or type(pair[0]) is not int for pair in children):
            raise ValueError('Malformed coverage split children')
        values=[pair[0] for pair in children]
        if values!=list(domains[variable]):
            raise ValueError('Coverage split omits or repeats domain values')
        for value,child in children:
            narrowed=dict(domains)
            narrowed[variable]=(value,)
            walk(narrowed,child,depth+1)
    domains=dict(engine.domains)
    domains.update({v:(x,) for v,x in assumptions.items()})
    walk(domains,artifact['tree'])
    # Every declared candidate must occur at a checked leaf: no copied ranking
    # row can smuggle an unvisited assumption or manufacture a score threshold.
    expected=sorted(set(leaves),key=lambda row:_rank(engine,row))[:top]
    if expected!=declared:
        raise ValueError('Coverage ranking does not match its complete proof leaves')
    return assumptions,declared
