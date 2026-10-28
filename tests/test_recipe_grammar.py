import itertools
import unittest

from kryptos.recipe_grammar import generate,expand_paths,synthesize,priority_bank


def encrypt(text,stages,keys):
    offset=0
    for stage in stages:
        if stage['operation']=='gather':text=''.join(text[i] for i in stage['permutation'])
        else:
            period=stage['period'];key=keys[offset:offset+period];offset+=period
            text=''.join(chr(65+((key[i%period]-(ord(c)-65)) if stage.get('cipher')=='beaufort' else ((ord(c)-65)-key[i%period]) if stage.get('cipher')=='variant' else ((ord(c)-65)+key[i%period]))%26) for i,c in enumerate(text))
    return text


class GrammarTests(unittest.TestCase):
    def test_prefix_dag_reconstructs_all64_paths_without_eager_expansion(self):
        choices=[{'operation':'substitution','period':1,'cipher':cipher} for cipher in ('vigenere','variant')]
        result=generate({'length':4,'slots':[choices]*6})
        self.assertTrue(result['complete']);self.assertEqual(result['represented_complete_recipes'],64)
        self.assertEqual(result['retained_transformation_classes'],1)
        paths=expand_paths(result,result['leaves'][0])
        self.assertEqual(len(paths),64)
        self.assertEqual({tuple(s['cipher'] for s in path) for path in paths},set(itertools.product(('vigenere','variant'),repeat=6)))
        self.assertEqual(result['work']['symbolic_transitions'],12)
        self.assertLess(result['work']['symbolic_transitions'],sum(2**d for d in range(1,7)))

    def test_merged_prefixes_preserve_literal_key_images(self):
        choices=[{'operation':'substitution','period':1,'cipher':cipher} for cipher in ('vigenere','variant','beaufort')]
        result=generate({'length':2,'slots':[choices]*2})
        for leaf in result['leaves']:
            paths=expand_paths(result,leaf)
            for plaintext in ('AB','ZA','MM'):
                expected=None
                for stages in paths:
                    images={encrypt(plaintext,stages,keys) for keys in itertools.product(range(26),repeat=2)}
                    if expected is None:expected=images
                    self.assertEqual(images,expected)
        self.assertGreater(len(result['leaves']),1) # Signs must not collapse.

    def test_different_source_permutations_do_not_merge(self):
        routes=[{'operation':'gather','permutation':p} for p in ([0,1],[1,0])]
        self.assertEqual(generate({'length':2,'slots':[routes]})['retained_transformation_classes'],2)

    def test_cegis_matches_exhaustive_shared_key_feasibility(self):
        recipes=[[{'operation':'substitution','period':p,'cipher':cipher}] for p,cipher in ((1,'vigenere'),(1,'beaufort'),(2,'vigenere'))]
        recipes.append([{'operation':'gather','permutation':[2,1,0]}])
        examples=[{'plaintext':p,'ciphertext':encrypt(p,recipes[0],[1]),'source':'frozen authored control'} for p in ('AAA','ABC','XYZ')]
        expected=[]
        for i,recipe in enumerate(recipes):
            width=sum(s.get('period',0) for s in recipe)
            if any(all(encrypt(pair['plaintext'],recipe,keys)==pair['ciphertext'] for pair in examples) for keys in itertools.product(range(26),repeat=width)):
                expected.append(i)
        result=synthesize({'recipes':recipes,'examples':examples})
        self.assertTrue(result['complete'])
        self.assertEqual(sorted(row['input_index'] for row in result['accepted']),expected)
        self.assertGreater(result['work']['counterexamples'],0)
        for row in result['accepted']:
            self.assertTrue(all(encrypt(pair['plaintext'],row['stages'],row['key_values'])==pair['ciphertext'] for pair in examples))
        full=synthesize({'recipes':recipes,'examples':examples,'initial_examples':len(examples)})
        self.assertEqual({r['input_index'] for r in result['accepted']},{r['input_index'] for r in full['accepted']})

    def test_priority_keeps_every_recipe_and_only_changes_order(self):
        recipes=[[{'operation':'substitution','period':2}],[{'operation':'substitution','period':1}]]
        result=priority_bank(recipes)
        self.assertEqual([r['input_index'] for r in result['recipes']],[1,0])
        self.assertEqual(len(result['recipes']),len(recipes))

    def test_shorter_explanation_order_reduces_work_to_first_witness(self):
        recipes=[[{'operation':'substitution','period':2,'cipher':'beaufort'}],
                 [{'operation':'gather','permutation':[2,1,0]},{'operation':'substitution','period':2}],
                 [{'operation':'substitution','period':1}]]
        examples=[{'plaintext':p,'ciphertext':encrypt(p,recipes[-1],[1]),'source':'authored priority control'} for p in ('AAA','ABC','XYZ')]
        reports=[synthesize({'recipes':recipes,'examples':examples,'priority':enabled,'stop_after_first':True}) for enabled in (False,True)]
        for result in reports:
            self.assertFalse(result['complete']);self.assertTrue(result['criterion_first_witness_satisfied'])
            self.assertEqual(result['accepted'][0]['input_index'],2)
        self.assertEqual([r['work']['recipe_candidates'] for r in reports],[3,1])

    def test_caps_and_invalid_shared_key_fields(self):
        result=generate({'length':2,'slots':[[{'operation':'substitution','period':1}]],'max_nodes':1})
        self.assertFalse(result['complete']);self.assertEqual(result['leaves'],[])
        result=synthesize({'recipes':[[{'operation':'substitution','period':1}]],'examples':[{'plaintext':'AB','ciphertext':'BC','source':'control'}],'max_equations':1})
        self.assertFalse(result['complete']);self.assertEqual(result['accepted'],[])
        with self.assertRaises(ValueError):generate({'length':2,'slots':[[{'operation':'substitution','period':1,'key_id':'shared'}]]})
        with self.assertRaisesRegex(ValueError,'256'):
            generate({'length':2,'slots':[[{'operation':'substitution','period':129}]]*2})


if __name__=='__main__':unittest.main()
