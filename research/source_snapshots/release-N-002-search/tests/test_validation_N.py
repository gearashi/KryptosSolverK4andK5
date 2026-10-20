from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import unittest

from kryptos.data import K4_CRIBS
from kryptos.general_layers import solve_layers
from kryptos.validation_protocols import run_validation

ROOT=Path(__file__).resolve().parents[1]


def frozen(name):
    return json.loads((ROOT/name).read_text(encoding='utf-8'))


class ReservedValidationTests(unittest.TestCase):
    def test_reservation_hashes_text_normalization_and_exact_k4_mask(self):
        protocol=frozen('research/protocol_N.json')
        fixture=frozen('research/fixtures_N.json')
        self.assertEqual(hashlib.sha256((ROOT/'research/fixtures_N.json').read_bytes()).hexdigest(),protocol['fixture_sha256'])
        for name,digest in protocol['requests'].items():
            self.assertEqual(hashlib.sha256((ROOT/'examples'/f'{name}.json').read_bytes()).hexdigest(),digest)
        mask=sorted(i for row in K4_CRIBS for i in range(row['start']-1,row['start']-1+len(row['text'])))
        self.assertEqual(mask,fixture['mask_zero_based'])
        self.assertEqual(Counter(p['language'] for p in fixture['passages']),{'en':2,'fr':2,'es':2})
        self.assertEqual(len(mask),24)
        self.assertNotEqual(mask,list(range(24)))
        for passage in fixture['passages']:
            self.assertEqual(passage['plaintext'],''.join(c for c in passage['source_text'].upper() if 'A'<=c<='Z')[:97])
            self.assertEqual(len(passage['plaintext']),97)

    def test_all_zero_structural_bank_counts_with_no_reserved_scoring(self):
        body=frozen('examples/validate-k4-shaped.json')
        known={i:'A' for i in body['crib_positions']}
        counts=[]
        for model in body['model_bank']:
            solved=solve_layers('A'*97,known,model['stages'],'standard')
            self.assertTrue(solved.feasible)
            counts.append(solved.distinct_plaintext_count)
        self.assertEqual(counts,[26,26,26,26,676,676])
        self.assertLessEqual(sum(counts),body['max_total_candidates'])
        self.assertEqual(len({c['generating_model_id'] for c in body['cases']}),6)
        self.assertEqual(len({tuple(s['permutation']) for model in body['model_bank'] for s in model['stages'] if s['operation']=='gather'}),2)

    def test_actual_mask_pipeline_on_unreserved_unit_texts(self):
        # Exercise full scoring on independent mechanical unit controls only;
        # the six reserved benchmark passages remain for the canonical run.
        body=frozen('examples/validate-k4-shaped.json')
        body['model_bank']=[body['model_bank'][0],body['model_bank'][-1]]
        body['cases']=[copy.deepcopy(body['cases'][0]),copy.deepcopy(body['cases'][-1])]
        for row,text in zip(body['cases'],('ABCDEFGHIJKLMNOPQRSTUVWXYZ','ZYXWVUTSRQPONMLKJIHGFEDCBA')):
            row['plaintext']=(text*4)[:97]
            row['source']='Mechanical unit-test sequence, not a reserved passage'
        body['model_paths']=[str(ROOT/p) for p in body['model_paths']]
        result=run_validation('validate-controls',body)
        self.assertTrue(result['complete'])
        self.assertEqual(result['summary']['completed_comparisons'],2)
        for pair in result['cases']:
            self.assertIn(pair['language'],('en','es'))
            for kind in ('positive','null'):
                self.assertTrue(pair[kind]['assessment']['truth_present_in_evaluated_candidates'])
                self.assertGreater(pair[kind]['assessment']['wrong_alternatives'],0)
                self.assertEqual(pair[kind]['selection']['score_mask'],body['crib_positions'])
            self.assertEqual(Counter(pair['positive']['generating_plaintext']),Counter(pair['null']['generating_plaintext']))


if __name__=='__main__':unittest.main()
