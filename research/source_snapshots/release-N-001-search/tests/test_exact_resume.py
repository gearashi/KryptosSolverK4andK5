import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from kryptos.app_jobs import RunManager
from kryptos.app_worker import execute


def body():
    return {'kind':'exact','command':'optimize-plus','backend':'cpu','max_batches':100,'time_limit_seconds':30,
        'request':{'target':'custom','ciphertext':'ABCDEFGH','cribs':[],'alphabet':'standard',
        'stages':[{'operation':'substitution','period':1}],
        'model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json','max_nodes':1,'time_limit_seconds':2}}


class ExactResumeTests(unittest.TestCase):
    def setUp(self):
        self.folder=Path('runtime')/('test-exact-'+uuid.uuid4().hex)
        self.manager=RunManager(self.folder/'runs')

    def tearDown(self):
        self.manager.close()
        path=self.folder.resolve()
        assert path.parent==Path('runtime').resolve() and path.name.startswith('test-exact-')
        shutil.rmtree(path)

    def wait(self):
        self.manager.thread.join(timeout=15)
        self.assertFalse(self.manager.thread.is_alive())
        return self.manager.view()

    def launch(self,key,job):return execute(job)

    def test_resumed_real_optimizer_matches_uninterrupted_optimum(self):
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            self.manager.start(body());first=self.wait()
        self.assertEqual(first['state'],'limited',first.get('error'))
        self.assertEqual(first['progress']['completed'],1)
        saved=first['exact_checkpoint']
        self.manager.close();self.manager=RunManager(self.folder/'runs')
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            for _ in range(100):
                self.manager.control('resume',first['id']);result=self.wait()
                if result['state']!='limited':break
        self.assertEqual(result['state'],'completed',result.get('error'))
        self.assertGreater(result['progress']['completed'],1)
        self.assertGreater(result['exact_checkpoint']['sequence'],saved['sequence'])
        request=body()['request'];request['max_nodes']=10000;request['time_limit_seconds']=10
        whole=execute({'kind':'exact','command':'optimize-plus','request':request})['optimization']['search']
        resumed=result['result']['optimization']['search']
        self.assertEqual((resumed['assignment'],resumed['score']),(whole['assignment'],whole['score']))
        exported=json.dumps(result)
        self.assertNotIn('checkpoint_path',exported);self.assertNotIn('resume_path',exported)

    def test_pause_commits_slice_stop_preserves_previous_frontier(self):
        for action in ('pause','stop'):
            entered=threading.Event();release=threading.Event()
            def launch(key,job):
                result=execute(job);entered.set();release.wait(4);return result
            with patch.object(self.manager,'_launch',side_effect=launch):
                start=self.manager.start(body());self.assertTrue(entered.wait(4));self.assertTrue(self.manager.view()['can_pause'])
                self.manager.control(action,start['id']);release.set();result=self.wait()
            self.assertEqual(result['state'],'paused' if action=='pause' else 'stopped',result.get('error'))
            self.assertEqual(result['progress']['completed'],1 if action=='pause' else 0)
            self.assertEqual(result['exact_checkpoint'] is None,action=='stop')

    def test_corrupted_checkpoint_does_not_launch_or_advance(self):
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            self.manager.start(body());first=self.wait()
        path=self.manager.directory/first['id']/'checkpoints'/first['exact_checkpoint']['file']
        path.write_text('{}')
        with patch.object(self.manager,'_launch') as launch:
            self.manager.control('resume',first['id']);result=self.wait()
        launch.assert_not_called()
        self.assertEqual(result['state'],'failed');self.assertEqual(result['progress'],first['progress'])
        self.assertIn('integrity',result['error'])

    def test_checkpoint_commit_failure_keeps_previous_pointer(self):
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            self.manager.start(body());first=self.wait()
        real_save=self.manager._save
        def failing(record):
            if record['batches_committed']>first['batches_committed']:raise OSError('injected slice commit failure')
            return real_save(record)
        with patch.object(self.manager,'_launch',side_effect=self.launch),patch.object(self.manager,'_save',side_effect=failing):
            self.manager.control('resume',first['id']);result=self.wait()
        self.assertEqual(result['state'],'failed');self.assertEqual(result['exact_checkpoint'],first['exact_checkpoint'])
        self.assertEqual(result['progress'],first['progress'])

    @unittest.skipUnless(os.environ.get('KRYPTOS_TEST_CUDA')=='1','Actual CUDA seed provenance is opt-in')
    def test_real_cuda_seed_backend_survives_cpu_frontier_resume(self):
        request=body()
        request['request']['seed_scan']={'backend':'cuda','batch_size':26,'top':3}
        with patch.object(self.manager,'_launch',side_effect=self.launch):
            self.manager.start(request);first=self.wait()
        self.assertIn(first['state'],{'limited','completed'},first.get('error'))
        self.assertEqual(first['backends_used'],['cpu','cuda'])
        self.assertEqual(first['backend_actual'],'cpu')
        self.assertEqual(first['result']['optimization']['search']['seed_scan']['backend_used'],'cuda')
        if first['state']=='limited':
            with patch.object(self.manager,'_launch',side_effect=self.launch):
                self.manager.control('resume',first['id']);resumed=self.wait()
            self.assertEqual(resumed['backends_used'],['cpu','cuda'])
            self.assertEqual(resumed['result']['optimization']['search']['seed_scan']['status'],'skipped_resume')


if __name__=='__main__':unittest.main()
