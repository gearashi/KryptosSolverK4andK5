import json
import string
import unittest

from kryptos.__main__ import _target
from kryptos.advanced_cli import run_advanced, json_safe_integers
from kryptos.explanations import replay_recipe
from kryptos.general_layers import literal_encrypt


def run(command, request):
    return run_advanced(command, request, _target)


class AdvancedCliTests(unittest.TestCase):
    def test_general_five_stage_trace_and_prime_counts(self):
        stages = [
            {"operation":"substitution","period":2},
            {"operation":"gather","permutation":[0,2,1,3,4,6,5,7]},
            {"operation":"substitution","period":2},
            {"operation":"gather","permutation":[0,4,2,6,1,5,3,7]},
            {"operation":"substitution","period":2}]
        plaintext = "ABCDEFGH"
        ciphertext = literal_encrypt(plaintext, ["BC","DE","FG"], stages)
        request = {"target":"custom","ciphertext":ciphertext,"alphabet":"standard","stages":stages,
                   "cribs":[{"start":i+1,"text":plaintext[i]} for i in (0,3,5,6)]}
        result = run("general",request)
        self.assertTrue(result["complete"])
        self.assertEqual(result["distinct_plaintext_count"],2)
        self.assertEqual(len(result["candidates"]),2)
        for candidate in result["candidates"]:
            self.assertEqual(len(candidate["evidence"]["stage_outputs"]),5)
            self.assertEqual(replay_recipe(candidate["plaintext"],candidate["encryption_recipe"])["ciphertext"],ciphertext)
        self.assertIn(plaintext,{c["plaintext"] for c in result["candidates"]})

    def test_general_cap_does_not_rank_arbitrary_subset(self):
        result = run("general",{"ciphertext":"ABCDEFGH","cribs":[],"alphabet":"standard",
            "stages":[{"operation":"substitution","period":2}],"max_candidates":2})
        self.assertEqual(result["distinct_plaintext_count"],676)
        self.assertFalse(result["complete"])
        self.assertEqual(result["candidates"],[])

    def test_column_candidates_replay(self):
        result = run("columns",{"ciphertext":"ACEBDF","cribs":[{"start":1,"text":"ABCDEF"}],"width":2})
        self.assertTrue(result["complete"])
        self.assertEqual(result["candidates"][0]["plaintext"],"ABCDEF")
        self.assertTrue(result["candidates"][0]["evidence"]["literal_reencryption_matches"])

    def test_default_column_geometry_is_verified_k4_only(self):
        result = run("columns",{})
        self.assertIn("default_geometry",result)
        self.assertEqual(result["assumptions"]["cells_in_plaintext_order"][0],[24,27])
        with self.assertRaises(ValueError):
            run("columns",{"ciphertext":"ABC","cribs":[]})

    def test_alphabet_fixed_indices_provenance(self):
        result = run("alphabet",{"ciphertext":"BCD","cribs":[{"start":1,"text":"ABC"}],"period":1,
                                  "fixed_indices":{c:i for i,c in enumerate(string.ascii_uppercase)}})
        self.assertEqual(result["candidates"][0]["key_pattern"],"B")
        self.assertIn("kryptos/keyed_alphabet.py",result["explanation"]["source_sha256"])

    def test_layout_sources_and_ordinal_cells(self):
        result = run("layout",{})
        self.assertEqual(len(result["text"]),97)
        self.assertEqual(len(result["cells"]),97)
        self.assertEqual(result["cells"][0]["row"],24)
        self.assertEqual(result["cells"][0]["column"],27)
        self.assertTrue(result["sources"])

    def test_optimization_has_bounds_and_replay(self):
        plaintext = "THISISASECRETTXT"
        stages = [{"operation":"substitution","period":2}]
        ciphertext = literal_encrypt(plaintext,["AB"],stages)
        result = run("optimize",{"ciphertext":ciphertext,"alphabet":"standard","stages":stages,
            "cribs":[{"start":1,"text":"T"}],
            "model_path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"})
        opt = result["optimization"]
        self.assertTrue(opt["search"]["optimal"])
        self.assertEqual(opt["search"]["lower_bound"],opt["search"]["upper_bound"])
        self.assertTrue(opt["candidate"]["evidence"]["literal_reencryption_matches"])
        self.assertEqual(opt["scoring"]["excluded_positions"],[0])

    def test_k5_and_unknown_fields_not_silently_accepted(self):
        for command in ("general","columns","alphabet","optimize"):
            with self.assertRaises(ValueError):
                run(command,{"target":"k5"})
            with self.assertRaises(ValueError):
                run(command,{"unknown":1})

    def test_hex_tag_roundtrip_for_large_exact_scores(self):
        n = 2**20000 + 13
        result = json.loads(json.dumps(json_safe_integers({"score":n,"other":42})))
        self.assertEqual(int(result["score"]["value"],16),n)
        self.assertEqual(result["score"]["encoding"],"exact_integer_hex")
        self.assertEqual(result["other"],42)


if __name__ == "__main__":
    unittest.main()
