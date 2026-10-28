import itertools
import json
from pathlib import Path
import unittest

from kryptos.recipe_algebra import compile_recipe, compiled_encrypt, family_from_compiled, canonical_phase_partition, primitive_key_bank, alphabet_affine_equivalence, compile_autokey
from kryptos.general_layers import literal_encrypt
from kryptos.scheduled_layers import normalize_stages, expanded_recipe, replay_expanded
from kryptos.constraint_lab import run, run_affine
from kryptos.constraint_models import fractionation_relation
from kryptos.constraint_reuse import dominates_one_best, enumerate_components, score_projection_groups, transfer_conflicts
from kryptos.hypotheses import generate_configs


class RecipeAlgebraTests(unittest.TestCase):
    def test_compilation_preserves_independent_and_shared_keys(self):
        stages=[{'operation':'substitution','period':2,'cipher':'beaufort'},
            {'operation':'gather','permutation':[3,1,0,2]},
            {'operation':'substitution','period':3,'cipher':'variant'}]
        compiled=compile_recipe(4,stages)
        for values in itertools.product(range(2),repeat=5):
            keys=[''.join(chr(65+x) for x in values[:2]),''.join(chr(65+x) for x in values[2:])]
            self.assertEqual(compiled_encrypt('TEST',values,compiled),literal_encrypt('TEST',keys,stages))
        shared=[{'operation':'substitution','key_id':'shared','key_length':2,'cipher':'beaufort','phase_map':[0,1,0,1]},
            {'operation':'gather','permutation':[3,1,0,2]},
            {'operation':'substitution','key_id':'shared','key_length':2,'cipher':'variant','phase_map':[1,0,1,0]}]
        compiled=compile_recipe(4,shared,scheduled=True)
        normalized,_=normalize_stages(4,shared,default_alphabet='standard')
        for values in itertools.product(range(3),repeat=2):
            keys={'shared':''.join(chr(65+x) for x in values)}
            expected=replay_expanded('TEST',expanded_recipe(normalized,keys,4))['ciphertext']
            self.assertEqual(compiled_encrypt('TEST',values,compiled),expected)

    def test_family_normalization_and_generator_job_reduction(self):
        a=compile_recipe(4,[{'operation':'substitution','period':1}])
        b=compile_recipe(4,[{'operation':'substitution','period':1},{'operation':'substitution','period':1}])
        self.assertEqual(family_from_compiled('TEST',a)['identity'],family_from_compiled('TEST',b)['identity'])
        base={'kind':'accelerated','command':'optimize-plus','backend':'cpu','request':{
            'target':'custom','ciphertext':'TEST','alphabet':'standard','model_path':'research/models/multilingual-001/artifacts/pg1342-english-trigram.json',
            'stages':[{'operation':'substitution','period':1}]}}
        settings={'patterns':['S','SS','SSS'],'periods':[1],'ciphers':['vigenere','beaufort','variant'],'routes':['identity']}
        plain,_=generate_configs(base,settings)
        reduced,info=generate_configs(base,{**settings,'normalize_affine_families':True})
        self.assertLess(len(reduced),len(plain))
        self.assertEqual(sum(len(c['generation_aliases']) for c in reduced),39)
        self.assertTrue(info['affine_normalization_enabled'])

    def test_phase_primitive_and_alphabet_cases(self):
        self.assertEqual(canonical_phase_partition([7,3,7,9,3])['phases'],[0,1,0,2,1])
        bank=primitive_key_bank([1,2,4],'AB')
        self.assertEqual(bank['expanded_keys'],22)
        self.assertEqual(bank['distinct_infinite_keys'],16)
        standard='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        rotated=standard[1:]+standard[:1]
        self.assertTrue(alphabet_affine_equivalence(standard,rotated)['equivalent'])
        self.assertFalse(alphabet_affine_equivalence(standard,'KRYPTOSABCDEFGHIJLMNQUVWXZ')['equivalent'])

    def test_affine_adapter_literal_replay_and_product_score(self):
        request=json.loads(Path('examples/optimize-lazy.json').read_text())
        result=run({'method':'affine','parameters':{'cipher_request':request,'sparse_basis':True,'top':3}})
        self.assertTrue(result['complete'])
        self.assertEqual(result['candidates'][0]['plaintext'],'THISISASECRETTXT')
        self.assertLess(result['work']['complete_candidate_evaluations'],result['distinct_plaintext_count'])
        self.assertTrue(all(c['evidence']['literal_reencryption_matches'] for c in result['candidates']))
        self.assertGreater(result['preparation']['factor_table_rows'],0)

    def test_autokey_both_feedback_types_and_all_cipher_equations(self):
        plain='TESTTHIS'
        seed='BC'
        for feedback in ('plaintext','ciphertext'):
            for cipher in ('vigenere','beaufort','variant'):
                output=[]
                for i,c in enumerate(plain):
                    key=seed[i] if i<len(seed) else (plain if feedback=='plaintext' else ''.join(output))[i-len(seed)]
                    p,k=ord(c)-65,ord(key)-65
                    output.append(chr(65+(p+k if cipher=='vigenere' else k-p if cipher=='beaufort' else p-k)%26))
                result=run({'method':'autokey','parameters':{'ciphertext':''.join(output),'seed_length':2,'feedback':feedback,'cipher':cipher,
                    'cribs':[{'start':1,'text':'TE'}]}})
                self.assertTrue(result['complete'])
                self.assertEqual([(c['plaintext'],c['seed_key']) for c in result['candidates']],[(plain,seed)])

    def test_joint_null_padding_control(self):
        result=run({'method':'null_padding','parameters':{'ciphertext':'UFYTU','null_count':1,'null_symbols':'X','period':1,
            'cribs':[{'start':1,'text':'TEST'}],'options':{'probing':True,'learning':True},'top':100}})
        self.assertTrue(result['complete'])
        self.assertEqual([(c['plaintext'],c['key'],c['removed_positions_zero_based']) for c in result['candidates']],[('TEST','B',[2])])

    def test_fractionation_relation_keeps_full_blocks(self):
        relation=fractionation_relation(['a','b'],['x','y'],alphabet='ABCD',rows=2,columns=2)
        self.assertEqual(len(relation['rows']),16)
        self.assertEqual(len({tuple(row[2:]) for row in relation['rows']}),16)


class ReuseTests(unittest.TestCase):
    def test_component_join_is_exact_and_less_enumeration(self):
        request={'domains':{v:[0,1] for v in 'sabcd'},'relations':[
            {'scope':['s','a','b'],'rows':[[s,a,b] for s,a,b in itertools.product(range(2),repeat=3) if (s+a+b)%2==0]},
            {'scope':['s','c','d'],'rows':[[s,c,d] for s,c,d in itertools.product(range(2),repeat=3) if (s+c+d)%2==1]}]}
        result=enumerate_components(request,separator=['s'])
        self.assertEqual(result['component_assignment_checks'],16)
        self.assertEqual(result['full_cartesian_reference'],32)
        from kryptos.constraint_lab import relational_join
        a,b=result['components']
        joined=relational_join(a['scope'],a['rows'],b['scope'],b['rows'])
        self.assertEqual(len(joined['rows']),8)

    def test_onebest_dominance_scope_and_score_projection_ties(self):
        request={'domains':{'x':[0,1],'y':[0,1]},'factors':[{'scope':['x'],'rows':[[0,3],[1,2]]}]}
        result=dominates_one_best(request)
        self.assertEqual(result['domains']['x'],[0])
        a=run({**request,'top':1})['candidates']
        b=run({**result['problem'],'top':1})['candidates']
        self.assertEqual(a,b)
        groups=score_projection_groups({'base':[0,0],'columns':[[13,0],[0,13]],'domains':[2,2]},[0])
        self.assertEqual(groups['scoring_evaluations'],2)
        self.assertEqual(sum(len(g['all_tie_coordinates']) for g in groups['groups']),4)

    def test_guarded_transfer_refuses_missing_constraints(self):
        source={'domains':{'x':[0,1],'y':[0,1]},'relations':[{'scope':['x','y'],'rows':[[0,0]]}],
            'options':{'propagation':False,'learning':True},'top':10}
        result=run(source)
        target={'domains':{'a':[0,1],'b':[0,1]},'relations':[{'scope':['a','b'],'rows':[[0,0]]}]}
        proof=transfer_conflicts(source,result['learned'],target,{'x':'a','y':'b'})
        second=run({**target,'learned':proof})
        self.assertEqual(second['candidates'],[{'assignment':{'a':0,'b':0},'score':0}])
        with self.assertRaises(ValueError):transfer_conflicts(source,result['learned'],{**target,'relations':[]},{'x':'a','y':'b'})


try:
    import z3
except ImportError:
    z3=None


@unittest.skipIf(z3 is None,'Optional Z3 package unavailable')
class SMTTests(unittest.TestCase):
    def test_incremental_lazy_queries_match_explicit_oracle(self):
        problem={'domains':{'a':[0,1,2],'b':[0,1,2]},'relations':[{'scope':['a','b'],'rows':[[0,1],[1,2],[2,0]]}]}
        result=run({'method':'smt','parameters':{'problem':problem,'queries':[{}, {'a':1}, {'a':1,'b':1}], 'lazy':True,'enumerate':True}})
        self.assertEqual([len(r['assignments']) for r in result['queries']],[3,1,0])
        self.assertTrue(all(r['complete'] for r in result['queries']))
        self.assertGreater(result['work']['counterexamples'],0)

    def test_unknown_alphabet_route_replay_and_known_control(self):
        alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        result=run({'method':'unknown_alphabet_routes','parameters':{'ciphertext':'UFTU','period':1,
            'routes':[[0,1,2,3],[3,2,1,0]],'alphabet_known':{c:i for i,c in enumerate(alphabet)},
            'cribs':[{'start':1,'text':'TEST'}],'max_candidates':20}})
        self.assertTrue(result['complete'])
        self.assertEqual([(c['plaintext'],c['key'],c['route_index']) for c in result['candidates']],[('TEST','B',0)])


if __name__=='__main__':unittest.main()
