import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from kryptos.app_jobs import RunManager
from kryptos.app_worker import execute


def body():
    return {'kind':'exact','command':'joint-ranked','backend':'cpu','max_batches':2,
        'time_limit_seconds':10,'request':{'ciphertext':'BCDEFG','cribs':[],
        'alphabet':'standard','width':2,'period':1,'order':'ST','top':5,
        'pruning':'admissible','max_evaluations':7,'max_states':100000,
        'time_limit_seconds':2,'model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json'}}


class JointAppResumeTests(unittest.TestCase):
    def setUp(self):
        Path('runtime').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir='runtime',prefix='joint-resume-')
        self.folder=Path(self.temp.name)
        self.manager=RunManager(self.folder/'runs')

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def wait(self):
        self.manager.thread.join(10)
        self.assertFalse(self.manager.thread.is_alive())
        return self.manager.view()

    def launch(self,key,job):
        return execute(job)

    def test_activation_limits_restart_and_exact_continuation(self):
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            first=self.manager.start(body())
            first=self.wait()
        self.assertEqual(first['state'],'limited',first.get('error'))
        self.assertLessEqual(first['result']['evaluated_this_run'],7)
        self.assertTrue(first['exact_checkpoint'])
        self.manager.close()
        self.manager=RunManager(self.folder/'runs')
        previous=first
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            for _ in range(25):
                self.manager.control('resume',first['id'])
                current=self.wait()
                self.assertLessEqual(current['result']['evaluated']-previous['result']['evaluated'],7)
                self.assertGreaterEqual(current['progress']['completed'],previous['progress']['completed'])
                previous=current
                if current['state']!='limited':
                    break
        self.assertEqual(current['state'],'completed',current.get('error'))
        config=body()
        config['request']['max_evaluations']=100000
        whole=execute({'kind':'exact','command':'joint-ranked','request':config['request']})
        self.assertTrue(whole['complete'],whole['stop_reason'])
        self.assertEqual(current['candidates'],whole['candidates'])
        self.assertTrue(current['result']['top_k_exact'])
        self.assertNotIn('checkpoint_path',json.dumps(current))
        self.assertNotIn('resume_path',json.dumps(current))

    def test_pause_commits_but_stop_and_failed_commit_do_not_advance(self):
        for action in ('pause','stop'):
            entered,release=threading.Event(),threading.Event()
            def launch(key,job):
                result=execute(job)
                entered.set()
                release.wait(5)
                return result
            with patch.object(self.manager,'_launch',side_effect=launch):
                started=self.manager.start(body())
                self.assertTrue(entered.wait(5))
                self.assertTrue(self.manager.view()['can_pause'])
                self.manager.control(action,started['id'])
                release.set()
                result=self.wait()
            # A budget-limited committed slice may settle as limited before
            # the next pause boundary, but Stop always discards the slice.
            if action=='stop':
                self.assertEqual(result['state'],'stopped')
                self.assertIsNone(result['exact_checkpoint'])
                self.assertEqual(result['progress']['completed'],0)
            else:
                self.assertIsNotNone(result['exact_checkpoint'])
                self.assertGreater(result['progress']['completed'],0)
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            self.manager.start(body())
            first=self.wait()
        old=copy.deepcopy(first['exact_checkpoint'])
        original_save=self.manager._save
        def fail(record):
            if record['batches_committed']>first['batches_committed']:
                raise OSError('injected failed durable commit')
            original_save(record)
        with patch.object(self.manager,'_launch',side_effect=self.launch),patch.object(self.manager,'_save',side_effect=fail):
            self.manager.control('resume',first['id'])
            failed=self.wait()
        self.assertEqual(failed['state'],'failed')
        self.assertEqual(failed['exact_checkpoint'],old)
        self.assertEqual(failed['progress'],first['progress'])


if __name__=='__main__':
    unittest.main()
