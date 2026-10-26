"""Managed boundaries for opt-in search reductions, including sliced counts."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kryptos.app_jobs import RunManager, validate_start
from kryptos.app_worker import execute

MODEL='research/models/multilingual-001/artifacts/pg1342-english-trigram.json'


def body():
    return {'kind':'exact','command':'joint-ranked','backend':'cpu','max_batches':2,
        'time_limit_seconds':10,'request':{'target':'custom','ciphertext':'BCDEFG','cribs':[],
        'alphabet':'standard','width':2,'period':1,'order':'ST','top':5,
        'pruning':'admissible','propagation':'fixed_point','early_segmentation':True,
        'branching':'constrained','score_bound':'shared_key','symmetry':'identical_chunks',
        'max_orders':2,'max_evaluations':3,'max_states':100000,
        'time_limit_seconds':2,'model_path':MODEL}}


class AppPTests(unittest.TestCase):
    def test_strategy_validation_rejects_wrong_types_and_excessive_limits(self):
        validate_start(body())
        for field,value in [('propagation',True),('early_segmentation',1),('branching','auto'),
                            ('score_bound',[]),('symmetry',None),('max_bound_cache_entries',10001)]:
            config=body();config['request'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_start(config)
        for field,value in [('residual_cache',True),('cheap_bound_first','true'),
                            ('residual_cache_max_entries',1025),('residual_cache_max_assignments',0),
                            ('residual_cache_max_operations',200001)]:
            config=body();config['command']='optimize-plus';config['request'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_start(config)

    def test_interleaved_route_block_budget_survives_restart(self):
        Path('runtime').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir='runtime',prefix='app-P-') as temp:
            manager=RunManager(Path(temp)/'runs')
            try:
                def launch(key,job):return execute(job)
                with patch.object(manager,'_launch',side_effect=launch):
                    started=manager.start(body());manager.thread.join(10)
                self.assertFalse(manager.thread.is_alive())
                first=manager.view();self.assertEqual(first['state'],'limited',first.get('error'))
                self.assertIsNone(first['result']['column_orders_visited'])
                self.assertLessEqual(first['result']['route_completion_blocks'],2)
                manager.close();manager=RunManager(Path(temp)/'runs');previous=first
                with patch.object(manager,'_launch',side_effect=launch):
                    for _ in range(60):
                        manager.control('resume',started['id']);manager.thread.join(10)
                        self.assertFalse(manager.thread.is_alive())
                        current=manager.view();result=current['result']
                        self.assertLessEqual(result['route_completion_blocks']-previous['result']['route_completion_blocks'],2)
                        self.assertLessEqual(result['evaluated']-previous['result']['evaluated'],3)
                        previous=current
                        if current['state']!='limited':break
                self.assertEqual(current['state'],'completed',current.get('error'))
                request=copy.deepcopy(body()['request']);request.update(max_orders=5000,max_evaluations=100000)
                whole=execute({'kind':'exact','command':'joint-ranked','request':request})
                self.assertTrue(whole['complete'])
                self.assertEqual(current['candidates'],whole['candidates'])
                self.assertTrue(result['top_k_exact'])
            finally:manager.close()


if __name__=='__main__':unittest.main()
