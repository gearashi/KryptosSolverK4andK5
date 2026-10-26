"""Frozen finite P7/P8 controls; no GPU, reserved corpus, or Kryptos scan.

Canonical invocation: python -B research/factor_P.py --output FRESH.json
The protocol is saved before experiments. All unfavorable comparisons remain.
"""
import argparse
import hashlib
from itertools import product
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.factor_decomposition import ResidualComponentCache
from kryptos.search_runtime import SCHEMA, _Evaluator, optimize_lazy


def input_paths():
    return sorted([p.relative_to(ROOT).as_posix() for p in (ROOT/'kryptos').glob('*.py')]+[
        'research/factor_P.py','research/factor_P_protocol.json','tests/test_factor_P.py',
        'tests/test_factor_decomposition.py','tests/test_search_enhancements.py','tests/test_search_O.py'])


def table(scope,values,power=1):
    return dict(kind='table',scope=scope,values=values,power=power)


def literal(problem,point):
    result=1
    for factor in problem['factors']:
        number=0
        for v in factor['scope']:
            number=number*problem['domains'][v]+point[v]
        result*=factor['values'][number]**factor.get('power',1)
    return result


def oracle(problem,partial=None):
    partial=[-1]*len(problem['domains']) if partial is None else partial
    points=product(*(range(d) if v<0 else (v,) for d,v in zip(problem['domains'],partial)))
    point=min(points,key=lambda p:(-literal(problem,p),p))
    return point,literal(problem,point)


def checked_search(problem,**options):
    result=optimize_lazy(problem,**options)
    point,value=oracle(problem)
    assert result['complete'] and result['tie_break_proven']
    assert (tuple(result['assignment']),result['score'])==(point,value)
    return {k:result[k] for k in ('assignment','score','nodes','leaf_nodes','pruned_nodes','work','residual_cache','decomposition','bounds','complete','tie_break_proven')}


def original_factor_work(report):
    # Full residual witness checks already appear in evaluator.factor_evaluations.
    # Do not count that named subset twice. Max-table reads, planning and cache
    # lookups are different costs, retained in their own fields, not hidden here.
    cache=report['residual_cache']['work']
    return (report['work']['factor_evaluations']+report['work']['elimination_factor_evaluations']
            +report['decomposition']['factor_evaluations']
            +cache.get('factor_evaluations',0)+cache.get('witness_factor_evaluations',0))


def run():
    before={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in input_paths()}
    protocol=json.loads((ROOT/'research/factor_P_protocol.json').read_text())
    rng=random.Random(protocol['seed']); specification=protocol['random_oracle']
    partial_checks=search_checks=0
    for _ in range(specification['cases']):
        domains=specification['domains']
        factors=[table(scope,[rng.choice(specification['values']) for _ in product(*(range(domains[v]) for v in scope))],
                       rng.choice(specification['powers'])) for scope in specification['factor_scopes']]
        problem=dict(schema=SCHEMA,domains=domains,factors=factors)
        memo=ResidualComponentCache(problem)
        for partial in product(*(range(-1,d) for d in domains)):
            point,value=oracle(problem,partial); result=memo.solve(partial)
            assert result['complete'] and (tuple(result['assignment']),result['score'])==(point,value)
            partial_checks+=1
        for options in ({},{'residual_cache':'components'},{'cheap_bound_first':True},
                        {'residual_cache':'components','cheap_bound_first':True}):
            checked_search(problem,**options); search_checks+=1
    settings=protocol['named_control_settings']
    repeated=dict(schema=SCHEMA,domains=settings['repeated_component_domains'],factors=[
        table(s,v) for s,v in zip(settings['repeated_component_scopes'],settings['repeated_component_values'])])
    direct=[]
    for capacity in (0,256):
        memo=ResidualComponentCache(repeated,max_entries=capacity,max_assignments=4)
        outputs=[]
        for partial in [(-1,)*5,(0,-1,-1,-1,-1),(1,-1,-1,-1,-1)]:
            result=memo.solve(partial)
            if result['complete']:
                expected,value=oracle(repeated,partial)
                assert (tuple(result['assignment']),result['score'])==(expected,value)
            outputs.append(result)
        direct.append(dict(capacity=capacity,outputs=outputs,work=dict(memo.stats)))
    assert direct[0]['outputs']==direct[1]['outputs']
    reuse=[checked_search(repeated,ordering='natural',**options) for options in ({},
        dict(residual_cache='components',residual_cache_max_entries=0,residual_cache_max_assignments=4),
        dict(residual_cache='components',residual_cache_max_entries=256,residual_cache_max_assignments=4))]
    boundary=dict(schema=SCHEMA,domains=[2,2],factors=[table([0,1],[9,1,1,8])])
    memo=ResidualComponentCache(boundary)
    for partial in ((0,-1),(1,-1)):
        expected,value=oracle(boundary,partial);result=memo.solve(partial)
        assert (tuple(result['assignment']),result['score'])==(expected,value)
    no_overlap=dict(work=dict(memo.stats),expected_hits=0)
    assert memo.stats['cache_hits']==0
    zero=dict(schema=SCHEMA,domains=[2,2,3],factors=[table([0],[1,9]),table([1],[0,0])])
    zero_result=checked_search(zero,residual_cache='components')
    assert zero_result['score']==0 and zero_result['assignment']==[0,0,0]
    fallback=[checked_search(repeated,residual_cache='components',**options) for options in (
        {'residual_cache_max_assignments':1},{'residual_cache_max_operations':1})]
    triangle=dict(schema=SCHEMA,domains=[2]*4,factors=[table([0],[100,1]),table([1,2],[9,1,1,9]),
        table([2,3],[9,1,1,9]),table([1,3],[1,9,9,1])])
    common=dict(ordering='natural',factor_group_size=2,max_cache_entries=0,
                elimination_bound='mini_bucket',elimination_bucket_entries=1)
    cheap=[checked_search(triangle,cheap_bound_first=enabled,**common) for enabled in (False,True)]
    flat=dict(schema=SCHEMA,domains=[2],factors=[table([0],[5,5])])
    unfavorable=[checked_search(flat,cheap_bound_first=enabled) for enabled in (False,True)]
    base=ROOT/'research/manual-checks';base.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='factor-P-',dir=base) as folder:
        previous=None;slices=[]
        options=dict(ordering='natural',factor_group_size=2,cheap_bound_first=True,
                     residual_cache='components',residual_cache_max_assignments=1)
        whole=checked_search(triangle,**options)
        for number in range(protocol['limits']['maximum_resume_slices']):
            path=Path(folder)/f'{number}.json'
            result=optimize_lazy(triangle,max_nodes=1,resume_path=previous,checkpoint_path=path,**options)
            payload=json.loads(path.read_text())['payload']; evaluator=_Evaluator(triangle,0,64,2)
            for row in payload['frontier']:
                assert row['upper_hex']==hex(evaluator.upper(tuple(row['assignment'])))
            slices.append(dict(nodes=result['nodes'],work=result['work'],residual_work=result['residual_cache']['work']))
            previous=path
            if result['complete']:break
        assert result['complete'] and (result['score'],result['assignment'])==(whole['score'],whole['assignment'])
        continuation=dict(complete=True,slices=slices,whole=whole,source_and_options_pinned=True)
    saved_factors=direct[0]['work']['factor_evaluations']-direct[1]['work']['factor_evaluations']
    cheap_saved=original_factor_work(cheap[0])-original_factor_work(cheap[1])
    integrated_comparison=dict(modes=['default_off','components_no_storage','components_cached'],
        nodes=[r['nodes'] for r in reuse],original_factor_evaluations=[original_factor_work(r) for r in reuse],
        cached_nodes_saved_vs_default=reuse[0]['nodes']-reuse[2]['nodes'],
        cached_original_factor_evaluations_saved_vs_default=original_factor_work(reuse[0])-original_factor_work(reuse[2]),
        interpretation='Compare all three integrated runs. Helper-only reuse is not automatically an improvement over default-off; snapshot/planning/cache work is separately reported.')
    after={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in input_paths()}
    assert before==after
    return dict(schema='kryptos.factor-P-audit.v1',protocol=protocol,
        oracle=dict(partial_checks=partial_checks,whole_search_checks=search_checks,all_exact_scores_and_ties=True),
        component_reuse=dict(direct=direct,optimizer=reuse,integrated_comparison=integrated_comparison,
            original_factor_evaluations_saved=saved_factors),
        changing_boundary_control=no_overlap,zero_score_control=zero_result,budget_fallbacks=fallback,
        cheap_gate=dict(comparisons=cheap,original_factor_evaluations_saved=cheap_saved),
        unfavorable_cheap_control=unfavorable,continuation=continuation,
        passed=saved_factors>0 and cheap_saved>0,
        integrated_cache_benefit_observed=(integrated_comparison['cached_nodes_saved_vs_default']>0
            or integrated_comparison['cached_original_factor_evaluations_saved_vs_default']>0),
        input_sha256_before=before,input_sha256_after=after,
        interpretation='Solved exact factor contexts only. No hard cipher contradictions or nogood learning; zeros remain feasible. Savings are finite work counts with overhead included separately.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--inputs',action='store_true')
    args=parser.parse_args()
    if args.inputs:
        print(json.dumps(input_paths(),indent=2));raise SystemExit(0)
    if args.output is None or args.output.exists():parser.error('--output must be a fresh path')
    result=run();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2,allow_nan=False);stream.write('\n')
    print(json.dumps(dict(passed=result['passed'],oracle=result['oracle'],
        component_saved=result['component_reuse']['original_factor_evaluations_saved'],
        cheap_saved=result['cheap_gate']['original_factor_evaluations_saved'])))
