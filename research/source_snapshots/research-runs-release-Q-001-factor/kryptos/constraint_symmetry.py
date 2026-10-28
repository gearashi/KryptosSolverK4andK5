"""Conservative certified finite variable/value symmetry quotient.

Only explicit bijections preserving every hard table and the complete score
factor multiset are admitted. All orbit members remain reconstructible; a
single score per orbit never silently discards top-k ties.
"""
from collections import Counter
from itertools import product
from math import prod

from .constraint_lab import normalize, RelationSearch, ConstraintLimit, _int


def _canonical(table, scored):
    order=sorted(range(len(table['scope'])),key=lambda i:table['scope'][i])
    scope=tuple(table['scope'][i] for i in order)
    rows=tuple(sorted(tuple(row[i] for i in order)+(row[-1:] if scored else ()) for row in table['rows']))
    return scope,rows,table['default'] if scored else 0


def certify(request, generators):
    names,domains,relations,factors=normalize(request)
    if not isinstance(generators,list) or not 1<=len(generators)<=32:
        raise ValueError('Supply1..32 explicit symmetry generators')
    normalized=[]
    hard=Counter(_canonical(t,False) for t in relations)
    objective=Counter(_canonical(t,True) for t in factors)
    for generator in generators:
        if not isinstance(generator,dict) or set(generator)-{'variables','values'}:
            raise ValueError('Symmetry generator has unknown fields')
        variable_map=generator.get('variables',{v:v for v in names})
        if not isinstance(variable_map,dict) or set(variable_map)!=set(names) or set(variable_map.values())!=set(names):
            raise ValueError('Symmetry variable map must be a complete bijection')
        raw_values=generator.get('values',{})
        if not isinstance(raw_values,dict) or set(raw_values)-set(names):
            raise ValueError('Unknown symmetry value-map variable')
        maps={}
        for v in names:
            entries=raw_values.get(v,[[x,x] for x in domains[v]])
            if not isinstance(entries,list) or any(not isinstance(pair,list) or len(pair)!=2 or any(type(x) is not int for x in pair) for pair in entries):
                raise ValueError('Value maps are explicit [source,target] integer pairs')
            mapping=dict(entries)
            if len(mapping)!=len(entries) or set(mapping)!=set(domains[v]) or set(mapping.values())!=set(domains[variable_map[v]]) or len(set(mapping.values()))!=len(mapping):
                raise ValueError('Value map must biject source and target domains')
            maps[v]=mapping
        def transform(t,scored):
            return {'scope':tuple(variable_map[v] for v in t['scope']),
                'rows':tuple(tuple(maps[v][x] for v,x in zip(t['scope'],row))+(row[-1:] if scored else ()) for row in t['rows']),
                'default':t['default']}
        if Counter(_canonical(transform(t,False),False) for t in relations)!=hard:
            raise ValueError('Proposed symmetry does not preserve the hard relation multiset')
        if Counter(_canonical(transform(t,True),True) for t in factors)!=objective:
            raise ValueError('Proposed symmetry does not preserve the objective factor multiset')
        normalized.append((variable_map,maps))
    return names,domains,normalized


def run(request):
    if not isinstance(request,dict) or set(request)-{'problem','generators','max_assignments','max_orbit_work'}:
        raise ValueError('Unknown symmetry-search field')
    problem=request.get('problem')
    names,domains,generators=certify(problem,request.get('generators'))
    maximum=_int(request.get('max_assignments',200000),'max_assignments',1,200000)
    work_cap=_int(request.get('max_orbit_work',2000000),'max_orbit_work',1,100000000)
    count=prod(map(len,domains.values()))
    if count>maximum:
        raise ConstraintLimit('Symmetry materialization cap')
    engine=RelationSearch(problem)
    visited=set()
    ranked=[]
    transformations=0
    representatives=0
    feasible_orbits=0
    expanded=0
    for point in product(*(domains[v] for v in names)):
        if point in visited:
            continue
        orbit={point}
        pending=[point]
        while pending:
            current=pending.pop()
            values=dict(zip(names,current))
            for variables,maps in generators:
                transformed={variables[v]:maps[v][values[v]] for v in names}
                target=tuple(transformed[v] for v in names)
                transformations+=1
                if transformations>work_cap:
                    raise ConstraintLimit('Symmetry orbit work cap')
                if target not in orbit:
                    orbit.add(target)
                    pending.append(target)
        visited.update(orbit)
        representative=min(orbit)
        assignment=dict(zip(names,representative))
        representatives+=1
        if not engine.literal_feasible(assignment):
            continue
        feasible_orbits+=1
        score=engine.score(assignment)
        expanded+=len(orbit)
        ranked.extend((score,row) for row in orbit)
    ranked.sort(key=lambda row:(-row[0],row[1]))
    return {'schema':'kryptos.certified-symmetry-search.v1','complete':True,
        'candidates':[{'assignment':dict(zip(names,values)),'score':score} for score,values in ranked[:engine.top]],
        'work':{'orbit_transformations':transformations,'complete_candidate_evaluations':representatives,
            'complete_score_evaluations':feasible_orbits,'expanded_feasible_assignments':expanded,'cartesian_reference_assignments':count,
            **dict(engine.work)},'authenticated_solution':False,
        'interpretation':'Certified variable/value symmetries only; exact factor multiset invariant. One feasibility/score evaluation per orbit; all tied assignments reconstructed before top-k.'}
