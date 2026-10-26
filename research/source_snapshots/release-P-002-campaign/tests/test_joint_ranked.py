import itertools
import string
import unittest

from kryptos.joint_ranked import rank_joint_columnar
from kryptos.joint_columnar import recover_joint_columnar
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.explanations import replay_recipe

A = string.ascii_uppercase


def oracle(ciphertext, known, width, period, model, layer="ST", cipher="vigenere", alphabet=A, reverse=False, mask=None):
    """Enumerate every labelled order and key without the tested prefilter."""
    columns = [list(range(c, len(ciphertext), width)) for c in range(width)]
    if reverse:
        columns = [list(reversed(c)) for c in columns]
    excluded = set(known if mask is None else mask)
    windows = [i for i in range(len(ciphertext)-model.order+1)
               if not excluded.intersection(range(i, i+model.order))]
    numerator, denominator = model.alpha.as_integer_ratio()
    retained, assignments, orders = {}, 0, set()
    for order in itertools.permutations(range(width)):
        route = [i for col in order for i in columns[col]]
        for key in itertools.product(alphabet, repeat=min(period, len(ciphertext))):
            plain = [""] * len(ciphertext)
            for j, i in enumerate(route):
                c = alphabet.index(ciphertext[j])
                k = alphabet.index(key[(i if layer == "ST" else j) % period])
                value = c-k if cipher == "vigenere" else c+k if cipher == "variant" else k-c
                plain[i] = alphabet[value % 26]
            if any(plain[i] != c for i, c in known.items()):
                continue
            text = "".join(plain)
            score = 1
            for i in windows:
                score *= model.counts.get(text[i:i+model.order], 0)*denominator+numerator
            assignments += 1
            orders.add(order)
            representation = (order, "".join(key))
            if text not in retained or representation < retained[text][1]:
                retained[text] = (score, representation)
    return sorted(retained.items(), key=lambda row: (-row[1][0], row[0])), assignments, len(orders)


class RankedJointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = train_ngram_model([CorpusDocument("ABACABADABACABAEABCDEFFEDCBA", "synthetic-test-only")], label="Synthetic test", order=2)

    def check_oracle(self, text="DBFHCAE", known=None, layer="ST", cipher="vigenere", alphabet=A, reverse=False, mask=None):
        known = {0:"A"} if known is None else known
        cribs = [{"start": i+1, "text": c} for i,c in known.items()]
        expected, assignments, orders = oracle(text, known, 4, 2, self.model, layer, cipher, alphabet, reverse, mask)
        result = rank_joint_columnar(text, cribs, model=self.model, period=2, width=4,
            order=layer, cipher=cipher, alphabet=alphabet, score_mask=mask,
            column_direction="bottom_to_top" if reverse else "top_to_bottom",
            top=8, max_states=1000000, time_limit_seconds=10)
        self.assertTrue(result["complete"], result["stop_reason"])
        self.assertTrue(result["top_k_exact"])
        self.assertEqual(result["total_order_key_assignments"], assignments)
        self.assertEqual(result["total_column_orders"], orders)
        self.assertEqual([c["plaintext"] for c in result["candidates"]], [p for p,_ in expected[:8]])
        for candidate, (plaintext, (score, (order, key))) in zip(result["candidates"], expected):
            self.assertEqual(int(candidate["score_exact"],16), score)
            self.assertEqual((tuple(candidate["column_order"]), candidate["key_pattern"]), (order,key))
            self.assertEqual(replay_recipe(plaintext,candidate["encryption_recipe"])["ciphertext"],text)
        return result

    def test_four_column_period_two_all_equations_and_stage_orders(self):
        for layer,cipher in itertools.product(("ST","TS"),("vigenere","beaufort","variant")):
            with self.subTest(layer=layer,cipher=cipher):
                self.check_oracle(layer=layer,cipher=cipher)

    def test_nonstandard_alphabet_reverse_columns(self):
        self.check_oracle(layer="TS",cipher="beaufort",alphabet="BACDEFGHIJKLMNOPQRSTUVWXYZ",reverse=True)

    def test_ties_deduplicate_plaintexts_and_choose_representative(self):
        result=self.check_oracle(text="AAAAAAA",known={},mask=list(range(7)))
        self.assertFalse(result["scoring"]["score_available"])
        self.assertTrue(all(c["score"] is None for c in result["candidates"]))
        self.assertTrue(all(c["score_exact"]=="0x1" for c in result["candidates"]))

    def test_masks_do_not_join_gaps(self):
        result=self.check_oracle(mask=[0,2,4])
        self.assertEqual(result["scoring"]["windows"],1)  # Only positions5,6 survive.

    def test_counts_match_existing_joint_when_complete(self):
        text="DKBIJHIFGN";cribs=[{"start":1,"text":"AB"}]
        ranked=rank_joint_columnar(text,cribs,model=self.model,period=2,width=4,order="TS",alphabet="standard",max_states=1000000)
        old=recover_joint_columnar(text,cribs,period=2,width=4,order="TS",alphabet="standard")
        self.assertTrue(ranked["complete"] and old["complete"])
        self.assertEqual(ranked["total_order_key_assignments"],old["total_order_key_assignments"])
        self.assertEqual(ranked["total_column_orders"],old["total_column_orders"])

    def test_censoring_never_claims_global_ranking_or_exclusion(self):
        for bounds in ({"max_evaluations":3},{"max_orders":1},{"max_states":1},{"max_segmentations":1},{"time_limit_seconds":1e-12}):
            with self.subTest(bounds=bounds):
                r=rank_joint_columnar("DBFHCAE",[],model=self.model,period=2,width=4,alphabet="standard",**bounds)
                self.assertFalse(r["complete"])
                self.assertFalse(r["top_k_exact"])
                self.assertIsNone(r["total_order_key_assignments"])
                self.assertNotEqual(r["feasible"],False)
                self.assertLessEqual(r["evaluated"],r["compatible_assignment_lower_bound"])

    def test_unused_declared_key_slots_are_not_counted(self):
        r=rank_joint_columnar("BC",[{"start":1,"text":"AB"}],model=self.model,period=5,width=1,alphabet="standard")
        self.assertTrue(r["complete"])
        self.assertEqual(r["total_order_key_assignments"],1)
        self.assertEqual(r["unused_key_slots"],[2,3,4])
        self.assertEqual(r["candidates"][0]["key_pattern"],"BBAAA")

    def test_invalid_masks_and_settings(self):
        for kwargs in ({"score_mask":[]},{"score_mask":[0,0]},{"score_mask":[True]}, {"top":True},{"max_evaluations":0}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                rank_joint_columnar("BCDE",[{"start":1,"text":"A"}],model=self.model,period=2,width=2,**kwargs)


if __name__=="__main__":
    unittest.main()
