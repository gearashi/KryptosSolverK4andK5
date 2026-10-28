import copy
from dataclasses import replace
from itertools import product
import json
from pathlib import Path
import unittest

from kryptos.constraint_lab import run
from kryptos.constraint_algebra import plaintext_coordinate_field, choose_field, crib_difference_constraints
from kryptos.constraint_reuse import residual_signature
from kryptos.general_layers import solve_layers
from kryptos.joint_ranked_helpers import reduce_joint, FULL
from kryptos.joint_ranked import _Budget, rank_joint_columnar
from kryptos.language import CorpusDocument, train_ngram_model


def conflict_case():
    domains={v:[0,1] for v in 'abcde'}
    relations=[]
    for left,right,parity in [('c','d',0),('d','e',0),('c','e',1)]:
        relations.append({'scope':['a',left,right],'rows':[[a,x,y] for a,x,y in product(range(2),repeat=3) if a or (x+y)%2==parity]})
    return {'domains':domains,'relations':relations,'top':100}


class ConstraintIntegrationTests(unittest.TestCase):
    def test_conflict_resolution_jumps_over_irrelevant_variable(self):
        problem=conflict_case()
        baseline=run(problem)
        advanced=run({**problem,'options':{'learning':True,'minimize_conflicts':True,'backjump':True}})
        self.assertEqual(baseline['candidates'],advanced['candidates'])
        self.assertLess(advanced['work']['branch_decisions'],baseline['work']['branch_decisions'])
        self.assertGreater(advanced['work'].get('backjumps',0),0)
        repeated=run({**problem,'learned':advanced['learned']})
        self.assertEqual(baseline['candidates'],repeated['candidates'])
        self.assertLess(repeated['work']['branch_decisions'],baseline['work']['branch_decisions'])

    def test_score_exclusions_are_reverified_and_not_hard_conflicts(self):
        problem={'domains':{'a':[0,1,2],'b':[0,1]},'top':1,
            'factors':[{'scope':['a'],'rows':[[0,8],[1,2],[2,1]]}],
            'options':{'score_exclusions':True}}
        baseline=run(problem)
        self.assertTrue(baseline['score_exclusions'])
        self.assertFalse(baseline['learned']['nogoods'])
        repeated=run({**problem,'learned':baseline['learned']})
        self.assertEqual(baseline['candidates'],repeated['candidates'])
        self.assertGreater(repeated['work'].get('score_exclusion_reuses',0),0)
        corrupt=copy.deepcopy(baseline['learned'])
        corrupt['score_exclusions'][0]['upper']=-100
        with self.assertRaises(ValueError):run({**problem,'learned':corrupt})
        changed=copy.deepcopy(problem)
        changed['factors'][0]['rows'][0][-1]=1
        with self.assertRaises(ValueError):run({**changed,'learned':baseline['learned']})

    def test_relational_route_pairs_preserve_correlations(self):
        requirements={(slot,col):{0:(slot+col)%2,1:((slot+col)%2)^(slot//2)} for slot in range(4) for col in range(4)}
        independent,_=reduce_joint([tuple(range(4))]*4,[FULL,FULL],requirements,_Budget(100000,10),fixed_point=True)
        correlated,_=reduce_joint([tuple(range(4))]*4,[FULL,FULL],requirements,_Budget(100000,10),fixed_point=True,pair_consistency=True)
        self.assertIsNotNone(independent)
        self.assertIsNone(correlated)
        valid={(slot,col):{0:(slot+col)%2,1:(slot+col)%2} for slot in range(4) for col in range(4)}
        result,_=reduce_joint([tuple(range(4))]*4,[FULL,FULL],valid,_Budget(100000,10),fixed_point=True,pair_consistency=True)
        self.assertIsNotNone(result)

    def test_actual_joint_relational_and_matching_bounds_vs_literal_oracle(self):
        from test_joint_ranked import oracle
        for order in (1,2):
            model=train_ngram_model([CorpusDocument('ABACABADABACABAEABCDEFFEDCBA','q-independent-synthetic')],label='Q fixture',order=order)
            for layer,cipher in product(('ST','TS'),('vigenere','beaufort','variant')):
                expected,_,_=oracle('DBFHCAE',{0:'A'},4,2,model,layer,cipher)
                result=rank_joint_columnar('DBFHCAE',[{'start':1,'text':'A'}],model=model,period=2,width=4,
                    order=layer,cipher=cipher,alphabet='standard',propagation='relational',branching='constrained',
                    pruning='admissible',score_bound='matching',top=8,max_states=2000000,time_limit_seconds=30)
                self.assertTrue(result['complete'],result['stop_reason'])
                self.assertEqual([c['plaintext'] for c in result['candidates']],[p for p,_ in expected[:8]])
                self.assertEqual([int(c['score_exact'],16) for c in result['candidates']],[r[0] for _,r in expected[:8]])

    def test_plaintext_coordinates_have_exact_pivots_and_key_lifts(self):
        original=solve_layers('ABCDEFGH',{},[{'operation':'substitution','period':2},{'operation':'substitution','period':3}])
        fields=[]
        reports=[]
        for field in (original.field2,original.field13):
            new,report=plaintext_coordinate_field(field)
            fields.append(new)
            reports.append(report)
            for i,position in enumerate(report['positions']):
                self.assertEqual(new.plaintext_base[position],0)
                self.assertEqual([row[position] for row in new.plaintext_columns],[int(j==i) for j in range(len(new.plaintext_columns))])
        solution=replace(original,field2=fields[0],field13=fields[1])
        for values in product(range(2),repeat=solution.dimensions_mod2):
            self.assertTrue(solution.candidate(values,(0,)*solution.dimensions_mod13)['reencryption_matches'])

    def test_residual_isomorphism_is_conservative(self):
        a={'scope':('a','b'),'rows':((0,0),(1,1)),'default':0}
        b={'scope':('x','y'),'rows':((0,0),(1,1)),'default':0}
        c={'scope':('x','y'),'rows':((0,0),(1,0)),'default':0}
        x=residual_signature(('a','b'),{'a':(0,1),'b':(0,1)},(a,),isomorphic=True)
        y=residual_signature(('x','y'),{'x':(0,1),'y':(0,1)},(b,),isomorphic=True)
        z=residual_signature(('x','y'),{'x':(0,1),'y':(0,1)},(c,),isomorphic=True)
        self.assertEqual(x,y)
        self.assertNotEqual(x,z)

    def test_symmetry_reconstructs_all_ties_and_rejects_false_transform(self):
        request=json.loads(Path('examples/constraint-Q-symmetry.json').read_text())
        result=run(request)
        expected=run(request['parameters']['problem'])
        self.assertEqual(result['candidates'],expected['candidates'])
        self.assertEqual(result['work']['cartesian_reference_assignments'],9)
        self.assertEqual(result['work']['complete_candidate_evaluations'],6)
        request['parameters']['problem']['factors'][0]['rows'][0][-1]=100
        with self.assertRaises(ValueError):run(request)

    def test_family_cover_replays_aliases_and_uses_each_score_once(self):
        request=json.loads(Path('examples/constraint-Q-family-cover.json').read_text())
        result=run(request)
        self.assertTrue(result['complete'])
        self.assertEqual(result['work']['independent_family_evaluations'],52)
        self.assertEqual(result['work']['complete_candidate_evaluations'],26)
        self.assertEqual(result['preparation']['final_verification_replays'],52)
        self.assertEqual(result['preparation']['literal_replays'],156)
        self.assertTrue(all(c['evidence']['literal_reencryption_matches'] for family in result['families'] for c in family['candidates']))
        wrong=copy.deepcopy(request)
        wrong['parameters']['families'][1]['cipher_request']['score_mask']=[0,1]
        with self.assertRaises(ValueError):run(wrong)

    def test_modular_order_and_crib_cancellation(self):
        result=choose_field([([2],1)],1)
        self.assertEqual(result['order'][0],2)
        self.assertIsNotNone(result['fields']['2']['conflict'])
        self.assertIsNotNone(result['fields']['13']['solution'])
        differences=crib_difference_constraints([([1,1],3),([1,2],4)])
        self.assertTrue(differences)
        for point in product(range(26),repeat=2):
            if (point[0]+point[1])%26==3 and (point[0]+2*point[1])%26==4:
                for row in differences:
                    self.assertEqual(sum(a*b for a,b in zip(row['coefficients'],point))%26,row['rhs'])

    def test_cross_run_subtree_coverage_is_reverified_before_skipping(self):
        problem={'domains':{'a':[0,1,2],'b':[0,1],'c':[0,1]},'top':3,
            'factors':[{'scope':['a','b'],'rows':[[a,b,a*4+b] for a,b in product(range(3),range(2))]}]}
        baseline=run(problem)
        artifact=run({'method':'coverage_proof','parameters':{'problem':problem,'assumptions':{'a':2}}})
        self.assertTrue(artifact['complete'])
        second=run({**problem,'coverage':[artifact['coverage']]})
        self.assertEqual(second['candidates'],baseline['candidates'])
        self.assertGreater(second['work'].get('covered_subtrees_reused',0),0)
        self.assertGreater(second['work'].get('coverage_leaf_reverification',0),0)
        self.assertLess(second['work']['branch_decisions'],baseline['work']['branch_decisions'])
        damaged=copy.deepcopy(artifact['coverage'])
        damaged['tree']['children'].pop()
        with self.assertRaises(ValueError):run({**problem,'coverage':[damaged]})
        changed=copy.deepcopy(problem)
        changed['factors'][0]['rows'][0][-1]=999
        with self.assertRaises(ValueError):run({**changed,'coverage':[artifact['coverage']]})
        omitted=copy.deepcopy(artifact['coverage'])
        omitted['candidates'].pop()
        with self.assertRaises(ValueError):run({**problem,'coverage':[omitted]})

    def test_coverage_zero_ties_and_entire_domain(self):
        for objective in ('sum','product'):
            for top in (1,3,20):
                problem={'domains':{'a':[0,1],'b':[0,1]},'objective':objective,'top':top,
                    'factors':[{'scope':['a'],'rows':[[0,0],[1,0]]}]}
                artifact=run({'method':'coverage_proof','parameters':{'problem':problem}})
                self.assertTrue(artifact['complete'])
                result=run({**problem,'coverage':[artifact['coverage']]})
                self.assertEqual(result['candidates'],run(problem)['candidates'])
                self.assertEqual(result['work']['covered_subtrees_reused'],1)
                self.assertEqual(result['work'].get('branch_decisions',0),0)


if __name__=='__main__':unittest.main()
