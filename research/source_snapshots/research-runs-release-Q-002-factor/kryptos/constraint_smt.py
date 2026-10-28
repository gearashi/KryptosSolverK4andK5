"""Optional incremental Z3 backend for explicit finite relation hypotheses.

Incremental assumptions preserve the underlying model; lazy relations are
added only after a concrete model violates them.  A solver `unknown` result is
inconclusive. CPU/GPU language scoring elsewhere does not depend on Z3.
"""
from itertools import product

from .constraint_lab import normalize, _int


class IncrementalSMT:
    def __init__(self, request, *, lazy=False, timeout_ms=10000):
        try:
            import z3
        except ImportError as exc:
            raise ValueError('Optional SMT backend unavailable; install requirements-sat.txt') from exc
        self.z3=z3
        self.names,self.domains,self.relations,self.factors=normalize(request)
        if self.factors:
            raise ValueError('Incremental SMT adapter is feasibility-only; use the relation or affine optimizer for objective factors')
        self.variables={v:z3.Int(f'v{i}') for i,v in enumerate(self.names)}
        self.solver=z3.Solver()
        self.solver.set(timeout=_int(timeout_ms,'timeout_ms',1,600000))
        for v,domain in self.domains.items():
            self.solver.add(z3.Or(*(self.variables[v]==x for x in domain)))
        self.pending=set(range(len(self.relations)))
        self.work={'solver_checks':0,'candidate_relation_checks':0,'activated_relations':0,'counterexamples':0}
        if not lazy:
            for i in tuple(self.pending):
                self.activate(i)

    def activate(self, index):
        z3=self.z3
        relation=self.relations[index]
        expression=z3.Or(*(z3.And(*(self.variables[v]==x for v,x in zip(relation['scope'],row))) for row in relation['rows']))
        self.solver.add(expression)
        self.pending.remove(index)
        self.work['activated_relations']+=1

    def check(self, assumptions=None):
        assumptions=assumptions or {}
        if not isinstance(assumptions,dict) or any(v not in self.domains or type(x) is not int or x not in self.domains[v] for v,x in assumptions.items()):
            raise ValueError('Assumptions must assign declared variable/domain values')
        literals=[self.variables[v]==x for v,x in sorted(assumptions.items())]
        z3=self.z3
        while True:
            self.work['solver_checks']+=1
            result=self.solver.check(*literals)
            if result==z3.unsat:
                core=set(map(str,self.solver.unsat_core()))
                return {'status':'unsat','core':[[v,x] for (v,x),literal in zip(sorted(assumptions.items()),literals) if str(literal) in core]}
            if result!=z3.sat:
                return {'status':'unknown','reason':self.solver.reason_unknown()}
            model=self.solver.model()
            assignment={v:model.eval(self.variables[v],model_completion=True).as_long() for v in self.names}
            violated=None
            for index in sorted(self.pending):
                self.work['candidate_relation_checks']+=1
                relation=self.relations[index]
                if tuple(assignment[v] for v in relation['scope']) not in relation['rows']:
                    violated=index
                    break
            if violated is None:
                return {'status':'sat','assignment':assignment}
            self.work['counterexamples']+=1
            self.activate(violated)


def run(request):
    allowed={'problem','queries','lazy','timeout_ms','enumerate','max_models'}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError('Unknown incremental SMT field')
    lazy=request.get('lazy',False)
    enumerate_models=request.get('enumerate',False)
    if type(lazy) is not bool or type(enumerate_models) is not bool:
        raise ValueError('lazy and enumerate must be Boolean')
    engine=IncrementalSMT(request.get('problem'),lazy=lazy,timeout_ms=request.get('timeout_ms',10000))
    queries=request.get('queries',[{}])
    if not isinstance(queries,list) or not 1<=len(queries)<=10000:
        raise ValueError('Supply1..10000 assumption queries')
    maximum=_int(request.get('max_models',100000),'max_models',1,1000000)
    results=[]
    for assumptions in queries:
        if not enumerate_models:
            results.append(engine.check(assumptions))
            continue
        # Blocking clauses belong only to this query. Lazy hard constraints
        # activated in this scope are re-added outside it after pop.
        engine.solver.push()
        initial_pending=set(engine.pending)
        models=[]
        complete=False
        reason=None
        while len(models)<maximum:
            result=engine.check(assumptions)
            if result['status']=='unsat':
                complete=True
                break
            if result['status']=='unknown':
                reason=result['reason']
                break
            assignment=result['assignment']
            models.append(assignment)
            engine.solver.add(engine.z3.Or(*(engine.variables[v]!=x for v,x in assignment.items())))
        if len(models)==maximum:
            reason='max_models (exhaustion not checked)'
        activated=initial_pending-engine.pending
        engine.solver.pop()
        for index in sorted(activated):
            engine.pending.add(index)
            engine.activate(index)
        models.sort(key=lambda a:tuple(a[v] for v in engine.names))
        results.append({'status':'enumerated','complete':complete,'limit':reason,'assignments':models})
    complete=all(row.get('complete',row['status'] in ('sat','unsat')) for row in results)
    return {'schema':'kryptos.incremental-smt.v1','queries':results,'work':engine.work,'complete':complete,
        'backend_version':engine.z3.get_version_string(),'lazy':lazy,'authenticated_solution':False,
        'interpretation':'Exact declared finite relations only. Incremental assumptions and lazily activated constraints preserve the model; unknown is inconclusive.'}
