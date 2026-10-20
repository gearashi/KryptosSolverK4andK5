import copy
import unittest
from kryptos.campaigns import preview_campaign
from kryptos.hypotheses import generate_configs,simplify_routes
from kryptos.general_layers import literal_encrypt


def base():
    return {'kind':'accelerated','command':'optimize-plus','backend':'cpu','request':{
        'target':'custom','ciphertext':'ABCDEFGHI','cribs':[],'alphabet':'standard',
        'model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json',
        'stages':[{'operation':'substitution','period':1}]}}


class HypothesisTests(unittest.TestCase):
    def test_gather_composition_matches_literal_encryption(self):
        for p,q in [([1,2,3,4,5,6,7,8,0],[8,7,6,5,4,3,2,1,0]),
                    ([1,2,3,4,5,6,7,8,0],[8,0,1,2,3,4,5,6,7])]:
            stages=[{'operation':'substitution','period':2},
                    {'operation':'gather','permutation':p},{'operation':'gather','permutation':q},
                    {'operation':'substitution','period':3,'cipher':'beaufort'}]
            simplified=simplify_routes(stages,9)
            for keys in [('AB','XYZ'),('ZA','BCD')]:
                self.assertEqual(literal_encrypt('ABCDEFGHI',keys,stages),literal_encrypt('ABCDEFGHI',keys,simplified))
            self.assertEqual(sum(s['operation']=='substitution' for s in simplified),2)

    def test_expansion_keeps_simplified_recipe_aliases(self):
        config=base();original=copy.deepcopy(config)
        result=preview_campaign({'base':config,'generator':{'patterns':['S','ST','TS','STT'],
            'periods':[1],'alphabets':['standard'],'ciphers':['vigenere'],'routes':['identity','reverse']}})
        self.assertEqual(result['generation']['expanded_recipes'],9)
        self.assertEqual(sum(len(j['generation_aliases']) for j in result['jobs']),9)
        self.assertEqual(result['job_count'],3)
        self.assertEqual(config,original)

    def test_shape_routes_are_full_bijections_and_deterministic(self):
        config=base();settings={'patterns':['ST'],'periods':[1],'routes':['sculpture'],'width':3}
        a,info=generate_configs(config,settings);b,other=generate_configs(config,settings)
        self.assertEqual((a,info),(b,other))
        for r in info['routes']:self.assertEqual(sorted(r['permutation']),list(range(9)))
        config['request']={'target':'k4','model_path':base()['request']['model_path']}
        _,info=generate_configs(config,{'patterns':['ST'],'periods':[1],'routes':['sculpture']})
        for r in info['routes']:self.assertEqual(sorted(r['permutation']),list(range(97)))

    def test_declared_caps_reject_without_silent_truncation(self):
        for settings in [
            {'patterns':['STS'],'periods':[1,2],'routes':['reverse'],'max_expansions':3},
            {'patterns':['SSS'],'periods':[1,2,3,4,5,6,7,8]},
            {'patterns':['T']},{'periods':[True]},{'routes':['sculpture']},
            {'routes':[{'id':'bad','permutation':[0]*9}]}]:
            with self.subTest(settings=settings),self.assertRaises(ValueError):generate_configs(base(),settings)
        with self.assertRaises(ValueError):preview_campaign({'base':base(),'axes':[{'path':'request.alphabet','values':['standard']}],'generator':{}})


if __name__=='__main__':unittest.main()
