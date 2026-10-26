import copy
from itertools import product
import unittest

from kryptos.grid_paths import generate_path_routes,path_route,replay_path
from kryptos.hypotheses import generate_configs


class GridPathTests(unittest.TestCase):
    def test_hand_spiral_and_wrap_are_literal_bijections(self):
        cells=[divmod(i,3) for i in range(9)]
        params={'start_index':0,'direction':'east','turn':'right','wrap':'none'}
        expected=[0,1,2,5,8,7,6,3,4]
        self.assertEqual(path_route(cells,params)['permutation'],expected)
        self.assertTrue(replay_path(cells,params,expected)['verified'])
        ring=[(2,4),(2,5),(2,6)]
        p={'start_index':1,'direction':'east','turn':'right','wrap':'toroidal'}
        self.assertEqual(path_route(ring,p)['permutation'],[1,2,0])
        self.assertTrue(replay_path(ring,p,[1,2,0])['verified'])
        self.assertFalse(path_route(ring,dict(p,wrap='none'))['complete'])

    def test_holes_cannot_be_filled_and_trapped_walk_has_witness(self):
        cells=[(0,0),(0,2)]
        p={'start_index':0,'direction':'east','turn':'right','wrap':'none'}
        result=path_route(cells,p)
        self.assertFalse(result['complete']);self.assertIsNone(result['permutation'])
        self.assertEqual(result['visited_prefix'],[0]);self.assertEqual(result['unvisited_indices'],[1])
        with self.assertRaises(ValueError):replay_path(cells,p,[0,1])

    def test_complete_declared_product_and_alias_replay(self):
        cells=[(0,2),(1,0),(1,1),(1,2),(2,0),(2,1),(2,2)]
        settings={'start_indices':list(range(7)),'directions':['north','east','south','west'],
                  'turns':['right','left'],'wraps':['none','toroidal']}
        generated=generate_path_routes(cells,settings)
        self.assertEqual((generated['raw_hypotheses'],generated['bijective_hypotheses'],
                          generated['nonbijective_hypotheses'],generated['distinct_routes']),(112,43,69,25))
        for route in generated['routes']:
            for parameters in route['parameter_aliases']:
                self.assertTrue(replay_path(cells,parameters,route['permutation'])['verified'])
        self.assertEqual(sum(len(r['parameter_aliases']) for r in generated['routes']),43)

    def test_generator_merges_before_cipher_work_and_preserves_multiplicity(self):
        base={'kind':'accelerated','command':'optimize-plus','backend':'cpu','request':{
              'target':'custom','ciphertext':'ABCDEFG','cribs':[],'alphabet':'standard'}}
        settings={'patterns':['ST'],'periods':[1],'routes':['paths'],'width':3,
                  'path_parameters':{'start_indices':[0,6],'directions':['east','south'],
                                     'turns':['right','left'],'wraps':['none','toroidal']}}
        original=copy.deepcopy(base)
        configs,report=generate_configs(base,settings)
        self.assertEqual(base,original)
        self.assertEqual(len(configs),5)
        self.assertEqual(report['expanded_recipes_before_path_dedup'],11)
        self.assertEqual(report['path_duplicate_recipe_expansions_avoided'],6)
        self.assertEqual(sum(a['parameter_multiplicity'] for r in configs for a in r['generation_aliases']),11)
        self.assertEqual(report['path_generation'][0]['raw_hypotheses'],16)
        for row in configs:
            for alias in row['generation_aliases']:
                self.assertTrue(alias['route_choices'][0]['parameter_aliases'])

    def test_input_and_work_bounds_fail_before_sampling(self):
        cells=[divmod(i,3) for i in range(9)]
        for settings in ({'start_indices':[True]},{'directions':['east','east']},{'turns':['random']},
                         {'wraps':['skip-holes']},{'max_hypotheses':True},{'start_indices':[9]},
                         {'start_indices':[0,1],'directions':['east','south'],'max_hypotheses':3}):
            with self.subTest(settings=settings),self.assertRaises(ValueError):generate_path_routes(cells,settings)
        with self.assertRaises(ValueError):generate_path_routes([(i,0) for i in range(4096)],{
            'start_indices':list(range(32)),'directions':['north','east','south','west'],'turns':['left','right'],'wraps':['none','toroidal']})


if __name__=='__main__':unittest.main()
