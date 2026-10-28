import copy
from itertools import product
import random
import unittest

from kryptos.constraint_lab import run, relational_join, disjunctive_relation
from kryptos.constraint_algebra import IncrementalField, affine_relation, sparse_field, disjoint_finite_cover
from kryptos.general_layers import solve_layers


def oracle(request):
    names = sorted(request['domains'])
    result = []
    for values in product(*(request['domains'][v] for v in names)):
        assignment = dict(zip(names,values))
        if not all([assignment[v] for v in r['scope']] in r['rows'] for r in request.get('relations',[])):
            continue
        score = 0
        for factor in request.get('factors',[]):
            key = [assignment[v] for v in factor['scope']]
            score += next((r[-1] for r in factor['rows'] if r[:-1] == key),factor.get('default',0))
        result.append((score,values))
    result.sort(key=lambda x:(-x[0],x[1]))
    return [{'score':s,'assignment':dict(zip(names,v))} for s,v in result[:request.get('top',20)]]


class RelationTests(unittest.TestCase):
    def test_random_finite_oracles(self):
        rng = random.Random(90371)
        for case in range(50):
            domains = {v:[0,1,2] for v in 'abcd'}
            relations=[]
            for scope in [('a','c'),('b','c'),('b','d')]:
                relations.append({'scope':list(scope),'rows':[list(r) for r in product(range(3),repeat=2) if rng.random()<0.65]})
            factors=[{'scope':['c','d'],'rows':[[a,b,rng.randrange(-3,10)] for a,b in product(range(3),repeat=2)],'default':-10}]
            request={'domains':domains,'relations':relations,'factors':factors,'top':5}
            expected=oracle(request)
            for options in ({'propagation':False}, {}, {'learning':True,'minimize_conflicts':True,'backjump':True},
                    {'learning':True,'minimize_conflicts':True,'backjump':True,'probing':True,'memoize':True,'score_exclusions':True,'branching':'smallest'}):
                result=run({**request,'options':options})
                self.assertTrue(result['complete'],result)
                self.assertEqual(expected,result['candidates'],(case,options))

    def test_imported_conflicts_reverified_and_guarded(self):
        request={'domains':{'a':[0,1],'b':[0,1],'c':[0,1]},'relations':[
            {'scope':['a','b'],'rows':[[0,0],[1,1]]},
            {'scope':['b','c'],'rows':[[0,0],[1,1]]},
            {'scope':['a','c'],'rows':[[0,1],[1,0]]}],
            'options':{'learning':True,'minimize_conflicts':True}}
        first=run(request)
        self.assertEqual(first['candidates'],[])
        second=run({**request,'learned':first['learned']})
        self.assertTrue(second['complete'])
        self.assertGreater(second['work'].get('proof_reverification_assignments',0),0)
        with self.assertRaises(ValueError):run({**request,'learned':{'hard_identity':'bad','nogoods':[]}})
        easy={'domains':{'a':[0,1]}}
        identity=run(easy)['hard_identity']
        with self.assertRaises(ValueError):run({**easy,'learned':{'hard_identity':identity,'nogoods':[[['a',0]]]}})

    def test_correlation_reduces_complete_assignments(self):
        request={'domains':{v:[0,1,2] for v in 'abcd'},'relations':[
            {'scope':['a','b','c','d'],'rows':[[i,i,i,i] for i in range(3)]}]}
        plain=run({**request,'options':{'propagation':False}})
        reduced=run(request)
        self.assertEqual(plain['candidates'],reduced['candidates'])
        self.assertEqual(plain['work']['complete_candidate_evaluations'],81)
        self.assertEqual(reduced['work']['complete_candidate_evaluations'],3)

    def test_limits_do_not_claim_completeness(self):
        result=run({'domains':{'a':list(range(10)),'b':list(range(10))},'max_work':5})
        self.assertFalse(result['complete'])
        self.assertEqual(result['limit'],'max_work')

    def test_join_and_disjunction(self):
        result=relational_join(['a','m'],[[0,1],[1,2]],['m','b'],[[1,3],[2,4],[9,9]])
        self.assertEqual(result['rows'],[[0,1,3],[1,2,4]])
        self.assertEqual(result['work']['matched_pairs'],2)
        self.assertEqual(result['work']['all_pairs_reference'],6)
        relation,witnesses=disjunctive_relation(['a'],{'literal':[[0]],'speculative':[[0],[1]]})
        self.assertEqual(relation['rows'],[[0],[1]])
        self.assertEqual(witnesses[0]['hypotheses'],['literal','speculative'])


class AlgebraTests(unittest.TestCase):
    def test_incremental_equations_and_conflict_certificates(self):
        for p in (2,13):
            system=IncrementalField(3,p)
            equations=[([1,1,0],1),([0,1,1],0),([1,0,-1],1),([1,0,-1],2)]
            for index,(row,rhs) in enumerate(equations):
                actual=system.add(row,rhs)
                candidates=[v for v in product(range(p),repeat=3) if all(sum(x*y for x,y in zip(r,v))%p==b%p for r,b in equations[:index+1])]
                self.assertEqual(actual,bool(candidates))
                solution=system.solution()
                if solution:
                    generated={tuple((x+sum(r[i]*v for r,v in zip(solution['basis'],values)))%p for i,x in enumerate(solution['base'])) for values in product(range(p),repeat=len(solution['basis']))}
                    self.assertEqual(generated,set(candidates))
                else:
                    proof=system.conflict
                    for col in range(3):
                        self.assertEqual(sum(equations[int(i)][0][col]*weight for i,weight in proof['weights'].items())%p,0)
                    self.assertEqual(sum(equations[int(i)][1]*weight for i,weight in proof['weights'].items())%p,proof['residue'])

    def test_affine_set_relations_against_enumeration(self):
        rng=random.Random(132)
        def points(f,p):
            return {tuple((x+sum(r[i]*v for r,v in zip(f['basis'],values)))%p for i,x in enumerate(f['base'])) for values in product(range(p),repeat=len(f['basis']))}
        for p in (2,13):
            for case in range(24):
                a={'base':[rng.randrange(p) for _ in range(3)],'basis':[[rng.randrange(p) for _ in range(3)] for _ in range(case%3)]}
                b={'base':[rng.randrange(p) for _ in range(3)],'basis':[[rng.randrange(p) for _ in range(3)] for _ in range((case+1)%3)]}
                aa,bb=points(a,p),points(b,p)
                result=affine_relation(a,b,p)
                self.assertEqual(result['left_subset_right'],aa<=bb)
                self.assertEqual(result['right_subset_left'],bb<=aa)
                self.assertEqual(result['intersection_size'],len(aa&bb))
                self.assertEqual(set() if result['intersection'] is None else points(result['intersection'],p),aa&bb)

    def test_sparse_basis_preserves_replay_and_plaintext_set(self):
        solution=solve_layers('ABCDEFGH',{},[{'operation':'substitution','period':2},{'operation':'substitution','period':3}])
        from dataclasses import replace
        a,report=sparse_field(solution.field2)
        altered=replace(solution,field2=a)
        self.assertLessEqual(report['after'],report['before'])
        before={solution.plaintext(values,(0,)*solution.dimensions_mod13) for values in product(range(2),repeat=solution.dimensions_mod2)}
        after=set()
        for values in product(range(2),repeat=altered.dimensions_mod2):
            candidate=altered.candidate(values,(0,)*altered.dimensions_mod13)
            self.assertTrue(candidate['reencryption_matches'])
            after.add(candidate['plaintext'])
        self.assertEqual(before,after)

    def test_disjoint_cover_keeps_aliases(self):
        families=[{'prime':2,'base':[0,0],'basis':[[1,0]]},{'prime':2,'base':[0,0],'basis':[[0,1]]}]
        result=disjoint_finite_cover(families)
        self.assertEqual(result['input_assignments'],4)
        self.assertEqual(result['distinct_points'],3)
        self.assertEqual(result['duplicate_evaluations_avoided'],1)
        self.assertEqual(result['aliases'][0]['families'],[0,1])

    def test_finite_cover_rejects_invalid_public_json_domains(self):
        valid={'prime':2,'base':[0],'basis':[[1]]}
        invalid=[
            [{**valid,'prime':-1}], [{**valid,'prime':True}], [{**valid,'prime':3}],
            [{**valid,'base':[]}], [{**valid,'base':[0.0]}], [{**valid,'basis':[[1,0]]}],
            [{**valid,'basis':[[True]]}], [valid,{**valid,'prime':13}],
            [valid,{'prime':2,'base':[0,0],'basis':[]}], []]
        for families in invalid:
            with self.subTest(families=families),self.assertRaises(ValueError):
                run({'method':'tools','parameters':{'operation':'disjoint_affine_cover','parameters':{'families':families}}})
        for cap in (0,-1,True,200001):
            with self.assertRaises(ValueError):disjoint_finite_cover([valid],max_points=cap)

    def test_score_projection_rejects_invalid_public_json_domains(self):
        from kryptos.constraint_reuse import score_projection_groups
        valid={'base':[0,0],'columns':[[13,0]],'domains':[2]}
        invalid=[{**valid,'domains':[-1]}, {**valid,'domains':[0]}, {**valid,'domains':[True]},
            {**valid,'domains':[27]}, {**valid,'domains':[2,2]}, {**valid,'columns':[[1]]},
            {**valid,'columns':[[1.0,0]]}, {**valid,'base':[]}, {**valid,'base':[0,False]},
            {**valid,'alphabet':'ABC'}, {**valid,'extra':'unsupported'}]
        for affine in invalid:
            with self.subTest(affine=affine),self.assertRaises(ValueError):
                run({'method':'tools','parameters':{'operation':'score_projection','parameters':{'affine':affine,'positions':[0]}}})
        for positions in ([[0]],[True],[0,0],[2],None):
            with self.assertRaises(ValueError):score_projection_groups(valid,positions)
        result=score_projection_groups({'base':[0],'columns':[],'domains':[]},[])
        self.assertEqual((result['input_assignments'],result['scoring_evaluations']),(1,1))


if __name__=='__main__':unittest.main()
