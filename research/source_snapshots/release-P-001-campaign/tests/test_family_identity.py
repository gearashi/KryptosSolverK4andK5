import itertools
from pathlib import Path
import tempfile
import unittest

from kryptos.accelerated import scan_batch
from kryptos.explanations import replay_recipe
from kryptos.family_identity import canonical_coset,describe_family,replay_aliases
from kryptos.language import CorpusDocument,train_ngram_model


def points(base,columns,prime):
    return {tuple((x+sum(c[i]*v for c,v in zip(columns,values)))%prime for i,x in enumerate(base))
            for values in itertools.product(range(prime),repeat=len(columns))}


class FamilyIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent=Path(__file__).resolve().parents[1]/"research/manual-checks"
        cls.temp=tempfile.TemporaryDirectory(prefix="family-test-",dir=cls.parent)
        cls.paths=[]
        for label in ("first model","same counts different provenance"):
            model=train_ngram_model([CorpusDocument("ABACABADABCDEF","test:family-controls")],label=label,order=2)
            path=Path(cls.temp.name)/f"{len(cls.paths)}.json"
            path.write_text(model.to_json(),encoding="utf-8")
            cls.paths.append(str(path))

    @classmethod
    def tearDownClass(cls):
        assert Path(cls.temp.name).resolve().is_relative_to(cls.parent.resolve())
        cls.temp.cleanup()

    def request(self,**changes):
        return {"ciphertext":"BCDEFG","target":"custom","cribs":[],"alphabet":"standard",
                "stages":[{"operation":"substitution","period":1}],"model_path":self.paths[0],**changes}

    def test_exhaustive_f2_cosets_equal_exactly_when_canonical_forms_equal(self):
        vectors=list(itertools.product(range(2),repeat=3))
        identities={}
        for base in vectors:
            for columns in itertools.combinations_with_replacement(vectors,2):
                exact=frozenset(points(base,columns,2))
                form=canonical_coset(base,columns,2)
                key=(tuple(form["base"]),tuple(map(tuple,form["basis"])))
                self.assertEqual(identities.setdefault(key,exact),exact)
        self.assertEqual(len(identities),len(set(identities.values())))

    def test_f13_changed_basis_dependent_columns_and_coset_translation(self):
        base=(3,7,2)
        a,b=(1,0,4),(0,1,5)
        expected=points(base,[a,b],13)
        canonical=canonical_coset(base,[a,b],13)
        for scale in (1,2,5,12):
            columns=[tuple((x+scale*y)%13 for x,y in zip(a,b)),tuple(scale*x%13 for x in b),a]
            shifted=tuple((x+4*y+6*z)%13 for x,y,z in zip(base,a,b))
            self.assertEqual(points(shifted,columns,13),expected)
            self.assertEqual(canonical_coset(shifted,columns,13),canonical)
        self.assertNotEqual(canonical_coset((3,7,3),[a,b],13),canonical)

    def test_family_equality_distinct_model_mask_and_alphabet(self):
        first=describe_family(self.request())
        equivalent=describe_family(self.request(stages=[{"operation":"substitution","period":1}]*2))
        self.assertEqual(first["scoring_family_sha256"],equivalent["scoring_family_sha256"])
        for request in (self.request(model_path=self.paths[1]),self.request(score_mask=[0])):
            other=describe_family(request)
            self.assertEqual(first["family_sha256"],other["family_sha256"])
            self.assertNotEqual(first["scoring_family_sha256"],other["scoring_family_sha256"])
        for request in (self.request(cribs=[{"start":1,"text":"A"}]),self.request(alphabet="kryptos")):
            self.assertNotEqual(first["family_sha256"],describe_family(request)["family_sha256"])

    def test_alias_reconstructs_own_keys_and_supplied_assumptions(self):
        original=self.request(cribs=[{"start":1,"text":"A"}],score_mask=[0,1])
        alias=self.request(cribs=[{"start":1,"text":"AB"}],score_mask=[0,1],
                           stages=[{"operation":"substitution","period":1}]*2)
        self.assertEqual(describe_family(original)["scoring_family_sha256"],describe_family(alias)["scoring_family_sha256"])
        saved=scan_batch(original)["candidates"]
        rebuilt=replay_aliases(alias,saved)["candidates"]
        self.assertEqual([c["plaintext"] for c in saved],[c["plaintext"] for c in rebuilt])
        for candidate in rebuilt:
            self.assertEqual(replay_recipe(candidate["plaintext"],candidate["encryption_recipe"])["ciphertext"],alias["ciphertext"])
            self.assertTrue(candidate["evidence"]["literal_reencryption_matches"])
            self.assertEqual(candidate["score_sensitivity"]["supplied_positions_zero_based"],[0,1])
        self.assertEqual(saved[0]["score_sensitivity"]["supplied_positions_zero_based"],[0])


if __name__=="__main__":
    unittest.main()
