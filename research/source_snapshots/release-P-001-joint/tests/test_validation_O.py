import copy
import hashlib
from itertools import product
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kryptos.family_identity import canonical_coset
from kryptos.general_layers import solve_layers
from kryptos.language import CorpusDocument,train_ngram_model
from kryptos.validation_protocols import run_validation,select_family_bank,_configuration

ROOT=Path(__file__).resolve().parents[1]


class ValidationOTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.model=train_ngram_model([CorpusDocument('FEDCBAFEDCBAFEDCBAABCDEF','independent-unit-control')],label='unit',order=2)
        path=Path(self.folder.name)/'model.json';path.write_text(self.model.to_json(),encoding='utf-8')
        self.request={'model_paths':[str(path)],'model_bank':[
            {'id':'p3','alphabet':'standard','stages':[{'operation':'substitution','period':3}]},
            {'id':'p4','alphabet':'standard','stages':[{'operation':'substitution','period':4}]},
            {'id':'p3-alias','alphabet':'standard','stages':[{'operation':'gather','permutation':list(range(6))},{'operation':'substitution','period':3}]}],
            'cases':[{'id':'one','plaintext':'ABCDEF','source':'unit authored','generating_model_id':'p3','keys':['BCD']},
                     {'id':'two','plaintext':'FEDCBA','source':'independent unit authored','generating_model_id':'p4','keys':['EFGH']}],
            'crib_positions':[0,1],'seed':72,'null_replicates':2,'minimum_distinct_surviving_families':2,
            'decision_score_threshold':-4.0,'max_candidates_per_family':676,'max_total_candidates':1500,'time_limit_seconds':30}

    def oracle(self,cipher,truth):
        families=[]
        for period in (3,4):
            fixed=[(ord(cipher[i])-ord(truth[i]))%26 for i in (0,1)]
            words=set()
            for rest in product(range(26),repeat=period-2):
                key=fixed+list(rest)
                words.add(''.join(chr(65+(ord(c)-65-key[i%period])%26) for i,c in enumerate(cipher)))
            families.append(words)
        words=set.union(*families)
        best=max(self.model.score(word,[0,1]).mean_log_probability for word in words)
        return families,best

    def test_full_selection_null_rate_and_exact_family_aliases_match_oracle(self):
        result=run_validation('validate-controls',self.request)
        self.assertTrue(result['complete'])
        self.assertTrue(result['family_coverage']['criterion_satisfied'])
        self.assertEqual(result['summary']['candidate_visits'],4368)
        exceedances=0
        for pair in result['cases']:
            self.assertEqual(pair['null'],pair['null_replicates'][0])
            for value in [pair['positive']]+pair['null_replicates']:
                selection=value['selection'];families,best=self.oracle(value['ciphertext'],value['generating_plaintext'])
                self.assertEqual(selection['distinct_completed_families'],2)
                self.assertEqual([g['model_ids'] for g in selection['completed_family_groups']],[['p3','p3-alias'],['p4']])
                self.assertEqual(selection['distinct_evaluated_plaintexts'],len(set.union(*families)))
                self.assertEqual(selection['best_selected_score'],best)
                if 'replicate' in value:exceedances+=best>=self.request['decision_score_threshold']
        self.assertEqual(result['calibration']['completed_null_exceedances'],exceedances)
        self.assertEqual(result['calibration']['empirical_exceedance_rate'],exceedances/4)

    def test_censoring_suppresses_rate_and_never_hashes_unenumerated_families(self):
        result=run_validation('validate-controls',dict(self.request,max_candidates_per_family=25))
        self.assertFalse(result['complete']);self.assertFalse(result['calibration']['rate_available'])
        self.assertIsNone(result['calibration']['empirical_exceedance_rate'])
        self.assertFalse(result['family_coverage']['criterion_satisfied'])
        self.assertEqual(result['summary']['candidate_visits'],0)
        for row in result['cases'][0]['positive']['selection']['model_records']:
            self.assertNotIn('completed_family_sha256',row)

    def test_partial_candidates_do_not_enter_completed_union(self):
        models,bank,bounds=_configuration(self.request)
        times=iter([0,0])
        with patch('kryptos.validation_protocols.time.monotonic',side_effect=lambda:next(times,2)):
            selection,_=select_family_bank('XYZXYZ',{0:'A',1:'B'},[0,1],bank,models,bounds,1)
        self.assertEqual(selection['evaluated'],1)
        self.assertEqual(selection['distinct_evaluated_plaintexts'],1)
        self.assertEqual(selection['distinct_completed_plaintexts'],0)
        self.assertEqual(selection['distinct_completed_families'],0)
        self.assertFalse(selection['complete'])

    def test_global_protocol_cap_and_threshold_validation(self):
        result=run_validation('validate-controls',dict(self.request,max_protocol_candidates=1000))
        self.assertLessEqual(result['summary']['candidate_visits'],1000)
        self.assertFalse(result['complete']);self.assertIsNone(result['calibration']['empirical_exceedance_rate'])
        for change in ({'null_replicates':True},{'null_replicates':17},{'decision_score_threshold':float('nan')},
                       {'decision_score_threshold':False},{'minimum_distinct_surviving_families':0},{'max_protocol_candidates':0}):
            with self.subTest(change=change),self.assertRaises(ValueError):run_validation('validate-controls',dict(self.request,**change))

    def test_identity_shuffle_is_retained_not_selected_away(self):
        request=copy.deepcopy(self.request)
        request['cases'][0]['plaintext']='ABCCCC';request['cases'][1]['plaintext']='FEDDDD'
        result=run_validation('validate-controls',request)
        self.assertEqual(result['calibration']['null_trials'],4)
        self.assertTrue(all(not row['shuffle_changed'] for p in result['cases'] for row in p['null_replicates']))

    def test_reserved_hashes_and_three_structurally_distinct_families_without_scores(self):
        protocol=json.loads((ROOT/'research/protocol_O.json').read_text())
        for path,key in [('research/fixtures_O.json','fixture_sha256'),('examples/validate-campaign-null.json','request_sha256')]:
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),protocol[key])
        request=json.loads((ROOT/'examples/validate-campaign-null.json').read_text())
        from kryptos.data import K4_CRIBS
        mask=sorted(i for c in K4_CRIBS for i in range(c['start']-1,c['start']-1+len(c['text'])))
        self.assertEqual(request['crib_positions'],mask)
        known={i:'A' for i in mask};identities=[];counts=[]
        for row in request['model_bank']:
            solution=solve_layers('A'*97,known,row['stages'],'standard')
            counts.append(solution.distinct_plaintext_count)
            identities.append(json.dumps([canonical_coset(f.plaintext_base,f.plaintext_columns,f.modulus)
                                           for f in (solution.field2,solution.field13)],sort_keys=True))
        self.assertEqual(counts,[26,676,26]);self.assertEqual(len(set(identities)),3)


if __name__=='__main__':unittest.main()
