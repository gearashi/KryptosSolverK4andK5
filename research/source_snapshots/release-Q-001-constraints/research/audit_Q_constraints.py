"""Frozen bounded evidence for the phase-Q constraint/recipe implementations.

Run under the project's computation runner or record its source/input closure.
Outputs must be new. Zero exit establishes only these finite assertions.
"""
import argparse
import copy
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))

from kryptos.constraint_lab import run
from kryptos.constraint_algebra import affine_relation
from kryptos.hypotheses import generate_configs
from test_constraint_integration_q import conflict_case


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    path=Path(args.output)
    if path.exists():
        raise ValueError('Audit output exists; use a fresh result path')
    suites=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in
        ('test_constraint_lab','test_recipe_algebra','test_constraint_integration_q'))
    tested=unittest.TextTestRunner(verbosity=2).run(suites)
    if not tested.wasSuccessful():
        raise AssertionError('Focused finite audit tests failed')
    rows={}
    problem=conflict_case()
    for label,options in (
        ('baseline',{}),
        ('learn_backjump',{'learning':True,'minimize_conflicts':True,'backjump':True}),
        ('probing',{'probing':True}),
        ('residual_dag',{'memoize':True}),
        ('isomorphic_residual_dag',{'memoize':True,'isomorphic_cache':True})):
        report=run({**problem,'options':options})
        assert report['complete']
        if rows:
            assert report['candidates']==rows['baseline']['candidates']
        rows[label]=report
    resumed=run({**problem,'learned':rows['learn_backjump']['learned']})
    assert resumed['candidates']==rows['baseline']['candidates']
    rows['reverified_deductions']=resumed
    coverage_problem={'domains':{'a':[0,1,2],'b':[0,1],'c':[0,1]},'top':3,
        'factors':[{'scope':['a','b'],'rows':[[a,b,a*4+b] for a,b in product(range(3),range(2))]}]}
    coverage_baseline=run(coverage_problem)
    coverage_created=run({'method':'coverage_proof','parameters':{'problem':coverage_problem,'assumptions':{'a':2}}})
    assert coverage_created['complete']
    coverage_reused=run({**coverage_problem,'coverage':[coverage_created['coverage']]})
    assert coverage_reused['candidates']==coverage_baseline['candidates']
    correlated={'domains':{v:[0,1,2] for v in 'abcd'},'relations':[
        {'scope':['a','b','c','d'],'rows':[[i,i,i,i] for i in range(3)]}]}
    correlation_reports={name:run({**correlated,'options':{'propagation':value}}) for name,value in [('off',False),('on',True)]}
    assert correlation_reports['off']['candidates']==correlation_reports['on']['candidates']
    examples={}
    for name in ('affine','autokey','smt','null-padding','family-cover','symmetry'):
        request=json.loads((ROOT/f'examples/constraint-Q-{name}.json').read_text(encoding='utf-8'))
        report=run(request)
        assert report['complete']
        examples[name]=report
    base={'kind':'accelerated','command':'optimize-plus','backend':'cpu','request':{
        'target':'custom','ciphertext':'TEST','alphabet':'standard','model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json',
        'stages':[{'operation':'substitution','period':1}]}}
    settings={'patterns':['S','SS','SSS'],'periods':[1],'ciphers':['vigenere','beaufort','variant'],'routes':['identity']}
    old,old_info=generate_configs(base,settings)
    new,new_info=generate_configs(base,{**settings,'normalize_affine_families':True})
    assert sum(len(row['generation_aliases']) for row in new)==39
    # Distinct inclusion/intersection cases, independently materialized.
    affine_checks=[]
    for prime in (2,13):
        families=[{'base':[0,0,0],'basis':[[1,0,0]]},
            {'base':[0,0,0],'basis':[[1,0,0],[0,1,0]]},
            {'base':[0,0,0],'basis':[[0,1,0],[0,0,1]]},
            {'base':[0,0,1],'basis':[[1,0,0]]}]
        def points(f):
            return {tuple((b+sum(row[i]*v for row,v in zip(f['basis'],values)))%prime for i,b in enumerate(f['base']))
                for values in product(range(prime),repeat=len(f['basis']))}
        for i,left in enumerate(families):
            for j,right in enumerate(families):
                report=affine_relation(left,right,prime)
                a,b=points(left),points(right)
                assert report['left_subset_right']==(a<=b)
                assert report['right_subset_left']==(b<=a)
                assert report['intersection_size']==len(a&b)
                affine_checks.append({'prime':prime,'left':i,'right':j,**report})
    try:
        import z3
        z3_version=z3.get_version_string()
    except ImportError:
        z3_version=None
    result={'schema':'kryptos.phase-Q-constraint-audit.v1','assertion_tested':
        'Exact finite relation top-k, conflict preservation, symbolic recipe replay, F2/F13 family relations, joint ranked12 literal oracles and bounded conditional cipher adapters on the fixed controls.',
        'status':'completed','software':{'python':platform.python_version(),'z3':z3_version},
        'tests':{'run':tested.testsRun,'failures':len(tested.failures),'errors':len(tested.errors),'skipped':len(tested.skipped),
            'random_relation_models':50,'variants_per_random_model':4,'random_seed':90371,
            'additional_random_affine_pairs':48,'additional_explicit_affine_pairs':len(affine_checks),'literal_joint_oracle_cases':12},
        'conflict_controls':rows,'correlation_controls':correlation_reports,'example_reports':examples,
        'cross_run_coverage':{'baseline':coverage_baseline,'created':coverage_created,'reused':coverage_reused},
        'hypothesis_bank':{'baseline_jobs':len(old),'normalized_jobs':len(new),'preserved_parameter_recipes':39,'normalization':new_info},
        'affine_set_checks':affine_checks,
        'non_claims':['No K4/K5 plaintext authenticated','No universal reduction in decisions or candidate evaluations',
            'Relation/table materialization, proof replay, bound rows and basis preparation are counted in addition to primary search work',
            'Finite helpers have explicit model/range scope; persisted deductions are not a resumable frontier',
            'Cross-family finite-bank reuse is not an arbitrary persistent campaign subtree cache']}
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    compact={label:{name:r['work'].get(name,0) for name in ('branch_decisions','complete_candidate_evaluations','total_work','proof_reverification_assignments')}
        for label,r in rows.items()}
    print(json.dumps({'output':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'conflict_work':compact,
        'family_cover':examples['family-cover']['work'],'normalized_jobs':[len(old),len(new)]},sort_keys=True))


if __name__=='__main__':
    main()
