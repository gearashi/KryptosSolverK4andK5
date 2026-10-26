import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from kryptos.ablations import ablation_bank, run_ablations
from kryptos.next_cli import _stages
from kryptos.validation_protocols import select_family_bank

ROOT=Path(__file__).resolve().parents[1]
MODEL=str(ROOT/'research/runs/evaluation-J-001/artifacts/english-two-author-trigram.json')


def request(ciphertext,stages,layer_model='general'):
    return {'target':'custom','ciphertext':ciphertext,
            'cribs':[{'start':1,'text':'A'},{'start':2,'text':'B'}],
            'withheld_positions':[1],'model_paths':[MODEL],
            'model_bank':[{'id':'test','layer_model':layer_model,'alphabet':'standard','stages':stages}],
            'max_candidates_per_family':676,'max_total_candidates':3000,'time_limit_seconds':10}


class AblationTests(unittest.TestCase):
    def test_independent_essential_route_refit_loses_prediction(self):
        # ABCDEFGH gathered[0,2,1,3,4,5,6,7] is ACBDEFGH.
        body=request('ACBDEFGH',[{'operation':'gather','permutation':[0,2,1,3,4,5,6,7]}])
        value=run_ablations(body)
        base,removed=value['records']
        self.assertTrue(value['complete'])
        self.assertEqual(base['assessment']['top_matching_letters'],1)
        self.assertEqual(removed['assessment']['top_matching_letters'],0)
        self.assertEqual(removed['comparison_to_baseline']['top_match_delta'],-1)
        self.assertEqual(removed['comparison_to_baseline']['lost_plaintexts'],1)
        self.assertEqual(removed['comparison_to_baseline']['gained_plaintexts'],1)

    def test_shared_cancelling_stages_are_redundant_after_refitting(self):
        stages=[{'operation':'substitution','key_id':'same','key_length':1,'cipher':cipher}
                for cipher in ('vigenere','variant')]
        value=run_ablations(request('ABCDEFGH',stages,'scheduled'))
        self.assertTrue(value['complete'])
        for row in value['records']:
            self.assertTrue(row['comparison_to_baseline']['same_completed_plaintext_family'])
            self.assertEqual(row['selection']['distinct_completed_plaintexts'],1)
            self.assertTrue(row['assessment']['top_all_withheld_match'])

    def test_removing_only_substitution_uses_identity_and_can_contradict(self):
        value=run_ablations(request('BCDEFGHI',[{'operation':'substitution','period':1}]))
        removed=value['records'][1]
        self.assertEqual(removed['model']['stages'],[{'operation':'gather','permutation':list(range(8))}])
        self.assertTrue(removed['selection']['complete'])
        self.assertFalse(removed['selection']['model_records'][0]['feasible'])
        self.assertIsNone(removed['assessment']['top_matching_letters'])

    def test_withheld_labels_never_enter_any_refit(self):
        body=request('ACBDEFGH',[{'operation':'gather','permutation':[0,2,1,3,4,5,6,7]}])
        calls=[]
        def fit(cipher,training,mask,bank,models,bounds,deadline):
            self.assertEqual(training,{0:'A'})
            self.assertEqual(mask,[0,1])
            calls.append(copy.deepcopy(bank))
            return select_family_bank(cipher,training,mask,bank,models,bounds,deadline)
        with patch('kryptos.ablations.select_family_bank',side_effect=fit):
            first=run_ablations(body)
            body['cribs'][1]['text']='Z'
            second=run_ablations(body)
        self.assertEqual(calls[:2],calls[2:])
        self.assertEqual([r['selection'] for r in first['records']],[r['selection'] for r in second['records']])
        self.assertNotEqual(first['records'][0]['assessment'],second['records'][0]['assessment'])

    def test_censoring_suppresses_family_and_predictive_comparisons(self):
        body=request('ABCDEFGH',[{'operation':'substitution','period':3}])
        body['max_candidates_per_family']=1
        value=run_ablations(body)
        self.assertFalse(value['complete'])
        for row in value['records']:
            self.assertFalse(row['comparison_to_baseline']['complete_comparison'])
            self.assertIsNone(row['comparison_to_baseline']['same_completed_plaintext_family'])
            self.assertIsNone(row['comparison_to_baseline']['top_match_delta'])

    def test_schedule_freeze_and_recompute_have_explicit_different_frames(self):
        model={'id':'schedule','layer_model':'scheduled','alphabet':'standard',
               'cells':[[0,0],[0,1],[1,0],[1,1],[2,0],[2,1]],'stages':[
                   {'operation':'gather','permutation':[1,2,0,3,4,5]},
                   {'operation':'substitution','key_id':'x','key_length':2,
                    'schedule':{'kind':'row_reset','frame':'source'}}]}
        frozen=ablation_bank(model,6,[0],'freeze')[1]['model']
        recomputed=ablation_bank(model,6,[0],'recompute')[1]['model']
        a,_=_stages(frozen,'custom','AAAAAA');b,_=_stages(recomputed,'custom','AAAAAA')
        self.assertEqual(a[1]['phase_map'],[1,0,0,1,0,1])
        self.assertEqual(b[1]['phase_map'],[0,1,0,1,0,1])
        self.assertIn('schedule',model['stages'][1])

    def test_small_refits_match_independent_all_key_enumeration(self):
        # Encrypt independently from numeric letter arithmetic and an explicit
        # gather, then exhaust every two-letter key separately for each refit.
        plain='ABCDEFGH';route=[0,2,1,3,4,5,6,7]
        middle=''.join(chr(65+(ord(c)-65+[1,2][i%2])%26) for i,c in enumerate(plain))
        cipher=''.join(middle[i] for i in route)
        body=request(cipher,[{'operation':'substitution','period':2},{'operation':'gather','permutation':route}])
        value=run_ablations(body)
        for row in value['records']:
            possible=set()
            for x in range(26):
                for y in range(26):
                    text=cipher
                    for stage in reversed(row['model']['stages']):
                        if stage['operation']=='gather':
                            unpack=['']*8
                            for j,i in enumerate(stage['permutation']):unpack[i]=text[j]
                            text=''.join(unpack)
                        else:
                            text=''.join(chr(65+(ord(c)-65-[x,y][i%2])%26) for i,c in enumerate(text))
                    if text[0]=='A':possible.add(text)
            self.assertTrue(row['selection']['complete'])
            self.assertEqual(row['selection']['distinct_completed_plaintexts'],len(possible))
            self.assertEqual(row['assessment']['evaluated_candidates_matching_all'],sum(p[1]=='B' for p in possible))

    def test_request_limits_and_shared_visit_cap(self):
        body=request('ABCDEFGH',[{'operation':'substitution','period':2},{'operation':'gather','permutation':list(range(8))}])
        body['max_total_candidates']=26
        value=run_ablations(body)
        self.assertLessEqual(value['candidate_visits'],26)
        self.assertFalse(value['complete'])
        for change in ({'model_bank':body['model_bank']*2},{'ablation_stage_indices':[]},
                       {'ablation_stage_indices':[True]},{'schedule_semantics':'guess'}):
            with self.assertRaises(ValueError):run_ablations(dict(body,**change))


if __name__=='__main__':unittest.main()
