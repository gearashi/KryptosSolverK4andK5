import copy
import hashlib
from pathlib import Path
import shutil
import unittest
from unittest.mock import Mock,patch
import uuid
from kryptos.app_jobs import RunManager
from kryptos.app_worker import execute
from kryptos.campaigns import CampaignManager,preview_campaign


def plan(cipher='vigenere'):
    return {'base':{'kind':'accelerated','command':'optimize-plus','backend':'cpu','batch_size':26,'max_batches':2,'time_limit_seconds':10,
        'request':{'target':'custom','ciphertext':'ABCDEF','cribs':[],'alphabet':'standard',
        'stages':[{'operation':'substitution','period':1,'cipher':cipher}],
        'model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json'}},'axes':[]}


class CampaignCacheTests(unittest.TestCase):
    def setUp(self):
        self.folder=Path('runtime')/('test-cache-'+uuid.uuid4().hex)
        self.manager=RunManager(self.folder/'runs');self.campaign=CampaignManager(self.manager)

    def tearDown(self):
        self.campaign.close();self.manager.close()
        path=self.folder.resolve();assert path.parent==Path('runtime').resolve() and path.name.startswith('test-cache-')
        shutil.rmtree(path)

    def run_plan(self,value):
        with patch.object(self.manager,'_launch',side_effect=lambda key,job:execute(job)),patch.object(self.campaign,'_task',side_effect=lambda key,job:execute(job)):
            self.campaign.start(value);self.campaign.thread.join(timeout=10)
            self.assertFalse(self.campaign.thread.is_alive())
        result=self.campaign.view();self.assertEqual(result['state'],'completed',result.get('error'));return result

    def test_cross_campaign_reuse_survives_restart_and_replays_own_recipe(self):
        first=self.run_plan(plan());source=first['jobs'][0]['run_id']
        self.campaign.close();self.manager.close()
        self.manager=RunManager(self.folder/'runs');self.campaign=CampaignManager(self.manager)
        second=self.run_plan(plan('variant'));alias=second['jobs'][0]
        self.assertEqual(alias['state'],'equivalent');self.assertEqual(alias['alias_campaign_id'],first['id'])
        self.assertEqual(alias['alias_run_id'],source);self.assertTrue(alias['cache_integrity_verified'])
        self.assertEqual(len(self.manager.records),1)
        for candidate in alias['candidates']:self.assertTrue(candidate['evidence']['literal_reencryption_matches'])

    def test_incomplete_approximate_stale_and_changed_bytes_do_not_reuse(self):
        first=self.run_plan(plan());job=first['jobs'][0];identity=job['family_identity'];key=job['run_id']
        self.assertIsNotNone(self.campaign._cached_completed(identity))
        with patch('kryptos.campaigns.source_identity',return_value={'changed':'bytes'}):
            self.assertIsNone(self.campaign._cached_completed(identity))
        raw=self.manager.records[key];original=copy.deepcopy(raw)
        for edits in ({'state':'limited'},{'ranking_exact_over_committed_pages':False},{'progress':{'completed':1,'total':26}}):
            raw.update(edits);self.manager._save(raw)
            path=self.manager.directory/key/'run.json'
            self.campaign.completed_cache[identity['scoring_family_sha256']]['run_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIsNone(self.campaign._cached_completed(identity))
            raw.clear();raw.update(copy.deepcopy(original))
        self.manager._save(raw)
        # A bit change after cache publication is rejected before a candidate is reused.
        path=self.manager.directory/key/'run.json';path.write_bytes(path.read_bytes()+b' ')
        self.assertIsNone(self.campaign._cached_completed(identity))
        other=dict(identity,scoring_family_sha256='different-mask-or-model')
        self.assertIsNone(self.campaign._cached_completed(other))

    def test_failed_pool_cleanup_retains_reference_until_retry(self):
        pool=Mock();pool.close.side_effect=[RuntimeError('live descendant'),None]
        self.campaign.preflight_pool=pool
        with self.assertRaisesRegex(RuntimeError,'live descendant'):self.campaign.close()
        self.assertIs(self.campaign.preflight_pool,pool)
        self.campaign.close();self.assertIsNone(self.campaign.preflight_pool)

    def test_protocols_are_not_ordinary_campaign_jobs(self):
        import json
        body={'kind':'exact','command':'validate-ablations','request':json.loads(Path('examples/validate-ablations.json').read_text())}
        with self.assertRaisesRegex(ValueError,'separately'):preview_campaign({'base':body,'axes':[]})


if __name__=='__main__':unittest.main()
