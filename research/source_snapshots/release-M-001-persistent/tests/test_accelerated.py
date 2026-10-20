import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kryptos.accelerated import _digits, probe_backend, scan_batch
from kryptos.general_layers import solve_layers
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.certified_scores import log2_interval, overlapping_indices


class CertifiedScoreTests(unittest.TestCase):
    def test_integer_power_oracle_including_coarse_intervals(self):
        wide = 0
        for bits in (0,1,4,8):
            for precision in (8,96):
                for value in range(1,201):
                    low, high = log2_interval(value,bits,precision)
                    floor = (value**(1<<bits)).bit_length()-1
                    self.assertLessEqual(low,floor)
                    self.assertGreaterEqual(high,floor+(value & (value-1) != 0))
                    wide += high-low > 1
        self.assertGreater(wide,0)  # Ambiguous digits widen, not guess.
        self.assertEqual(log2_interval(1<<19999),(19999<<32,19999<<32))

    def test_interval_cutoff_retains_every_tie_and_true_top(self):
        products = [3*7,7*3,5*4,2*11,17,23,23,2*2*2*2]
        intervals = [log2_interval(n,4,8) for n in products]
        selected, cutoff = overlapping_indices([a for a,b in intervals],[b for a,b in intervals],3)
        true_cutoff = sorted(products,reverse=True)[2]
        self.assertTrue(all(i in selected for i,p in enumerate(products) if p>=true_cutoff))
        self.assertTrue(all(intervals[i][1]<cutoff for i in range(len(products)) if i not in selected))
        self.assertEqual(overlapping_indices([7]*20,[7]*20,2)[0],list(range(20)))


class AcceleratedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Path(__file__).resolve().parents[1]
        cls.temp = tempfile.TemporaryDirectory(prefix="accelerated-test-", dir=cls.workspace/"research/manual-checks")
        cls.path = Path(cls.temp.name)/"model.json"
        cls.model = train_ngram_model([CorpusDocument("ABACABADABACABAE XYZXYXYZ AAAAA", "test:explicit-training")],
                                     label="tiny audit", order=2, alpha=0.25)
        cls.path.write_text(cls.model.to_json(), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        assert Path(cls.temp.name).resolve().is_relative_to(cls.workspace/"research/manual-checks")
        cls.temp.cleanup()

    def request(self, **changes):
        return {"ciphertext": "BCDEFG", "cribs": [], "alphabet": "standard",
                "stages": [{"operation": "substitution", "period": 1}],
                "model_path": str(self.path), **changes}

    def direct(self, request):
        known = {i: c for crib in request["cribs"] for i, c in enumerate(crib["text"], crib["start"]-1)}
        solution = solve_layers(request["ciphertext"], known, request["stages"], request["alphabet"])
        rows = []
        p, q = float(self.model.alpha).as_integer_ratio()
        for index, (_, _, text) in enumerate(solution.enumerate_plaintexts(676)):
            score = 1
            for start in range(len(text)-self.model.order+1):
                if not any(i in known for i in range(start, start+self.model.order)):
                    score *= self.model.counts.get(text[start:start+self.model.order], 0)*q+p
            rows.append((score, text, index))
        return sorted(rows, key=lambda row: (-row[0], row[1], row[2]))

    def test_cpu_matches_independent_direct_objective_all_equations(self):
        for cipher in ("vigenere", "beaufort", "variant"):
            with self.subTest(cipher=cipher):
                request = self.request(stages=[{"operation": "substitution", "period": 2, "cipher": cipher},
                    {"operation": "gather", "permutation": [2, 0, 5, 1, 3, 4]}],
                    cribs=[{"start": 2, "text": "A"}])
                result = scan_batch(request, batch_size=676, top=26)
                expected = self.direct(request)
                self.assertEqual([(int(c["score_exact"], 16), c["plaintext"], c["index"]) for c in result["candidates"]], expected)
                self.assertEqual(result["evaluated"], len(expected))
                self.assertTrue(result["ranking_exact_within_page"])
                self.assertTrue(all(c["evidence"]["literal_reencryption_matches"] for c in result["candidates"]))

    def test_pages_are_disjoint_and_match_full_run(self):
        request = self.request(alphabet="BACDEFGHIJKLMNOPQRSTUVWXYZ")
        rows, offset = [], 0
        while True:
            result = scan_batch(request, offset=offset, batch_size=7, top=7)
            rows.extend(result["candidates"])
            self.assertEqual(result["offset_decimal"], str(offset))
            offset = result["next_offset"]
            if result["complete"]:
                break
        self.assertEqual(sorted(c["index"] for c in rows), list(range(26)))
        expected = self.direct(request)
        actual = sorted(((int(c["score_exact"], 16), c["plaintext"], c["index"]) for c in rows), key=lambda r: (-r[0], r[1], r[2]))
        self.assertEqual(actual, expected)
        self.assertEqual(scan_batch(request, offset=26)["evaluated"], 0)

    def test_scheduled_shared_key_and_recipe(self):
        result = scan_batch(self.request(layer_model="scheduled", cells=[[0, i] for i in range(6)],
            stages=[{"operation": "substitution", "key_id": "k", "key_length": 2},
                    {"operation": "gather", "permutation": [2, 0, 5, 1, 3, 4]},
                    {"operation": "substitution", "key_id": "k", "key_length": 2, "cipher": "variant",
                     "schedule": {"kind": "row_reset", "frame": "source"}}]), top=3)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["candidates"][0]["encryption_recipe"]["schema"], "kryptos.expanded-recipe.v1")
        self.assertTrue(result["candidates"][0]["evidence"]["literal_reencryption_matches"])

    def test_mask_breaks_windows_and_ties_are_plaintext_lexical(self):
        request = self.request(cribs=[{"start": 1, "text": "A"}, {"start": 3, "text": "C"}, {"start": 5, "text": "E"}],
                               stages=[{"operation": "substitution", "period": 2}])
        result = scan_batch(request, top=26)
        self.assertEqual(result["scoring"]["windows"], 0)
        self.assertTrue(all(c["score"] is None and c["score_exact"] == "0x1" for c in result["candidates"]))
        self.assertEqual([c["plaintext"] for c in result["candidates"]], sorted(c["plaintext"] for c in result["candidates"]))

    def test_contradiction_and_budget_are_distinct(self):
        contradiction = scan_batch(self.request(ciphertext="AB", cribs=[{"start": 1, "text": "AA"}]))
        self.assertFalse(contradiction["feasible"])
        self.assertEqual(contradiction["total"], 0)
        self.assertTrue(contradiction["complete"])
        budget = scan_batch(self.request(max_operations=1))
        self.assertIsNone(budget["feasible"])
        self.assertIsNone(budget["total"])
        self.assertFalse(budget["complete"])

    def test_big_offset_and_domains_do_not_pass_through_float(self):
        domains = [2]*60 + [13]*60
        number = 2**70 + 917
        point = _digits(number, domains)
        recovered = 0
        for digit, domain in zip(point, domains):
            recovered = recovered*domain+digit
        self.assertEqual(recovered, number)
        result = scan_batch(self.request(ciphertext="A"*20, stages=[{"operation": "substitution", "period": 20}]),
                            offset=2**54+19, batch_size=2, top=2)
        self.assertEqual(result["next_offset_decimal"], str(2**54+21))
        self.assertEqual(len(result["candidates"]), 2)
        json.dumps(result, allow_nan=False)

    def test_argument_caps_and_explicit_cuda_failure(self):
        for kwargs in ({"backend": "gpu"}, {"offset": True}, {"offset": -1}, {"offset": 27},
                       {"batch_size": 0}, {"batch_size": 65537}, {"top": 101},{"ranking_mode":"float"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                scan_batch(self.request(), **kwargs)
        with patch("kryptos.accelerated._cuda_rank", side_effect=RuntimeError("deliberate unavailable")):
            with self.assertRaisesRegex(RuntimeError, "CUDA scan failed"):
                scan_batch(self.request(), backend="cuda")
            with patch("kryptos.accelerated.probe_backend", return_value={"cuda": {"ready": True}}):
                result = scan_batch(self.request(), backend="auto")
                self.assertEqual(result["backend_used"], "cpu")
                self.assertIn("deliberate unavailable", result["fallback_reason"])

    def test_work_cap(self):
        request = self.request(ciphertext="A"*100, stages=[{"operation": "substitution", "period": 30}])
        with self.assertRaisesRegex(ValueError, "work cap"):
            scan_batch(request, batch_size=65536)

    def test_explicit_score_mask(self):
        result=scan_batch(self.request(score_mask=[0,2,4]),top=26)
        self.assertEqual(result["scoring"]["windows"],0)
        self.assertEqual(result["scoring"]["excluded_positions"],[0,2,4])
        self.assertTrue(all(c["score"] is None for c in result["candidates"]))

    @unittest.skipUnless(__import__("os").environ.get("KRYPTOS_TEST_CUDA") == "1", "explicit CUDA test opt-in")
    def test_real_cuda_matches_cpu_and_cpu_replays(self):
        self.assertTrue(probe_backend()["cuda"]["ready"])
        requests = [self.request(alphabet=alphabet, stages=[{"operation": "substitution", "period": 2, "cipher": cipher},
                     {"operation": "gather", "permutation": [2, 0, 5, 1, 3, 4]}], cribs=[{"start": 1, "text": "A"}])
                    for alphabet in ("standard", "BACDEFGHIJKLMNOPQRSTUVWXYZ")
                    for cipher in ("vigenere", "beaufort", "variant")]
        requests.append(self.request(layer_model="scheduled", stages=[
            {"operation": "substitution", "key_id": "k", "key_length": 1, "phase_map": [0]*6}]))
        for request in requests:
            for offset in (0, 11):
                cpu = scan_batch(request, offset=offset, batch_size=26, top=10)
                cuda = scan_batch(request, backend="cuda", offset=offset, batch_size=26, top=10)
                self.assertEqual([(c["plaintext"], c["score_exact"], c["index"]) for c in cpu["candidates"]],
                                 [(c["plaintext"], c["score_exact"], c["index"]) for c in cuda["candidates"]])
                self.assertEqual(cuda["backend_used"], "cuda")
                self.assertTrue(cuda["ranking_exact_within_page"])
        fixed = self.request(cribs=[{"start": 1, "text": "ABCDEF"}])
        self.assertEqual(scan_batch(fixed, backend="cuda")["candidates"][0]["plaintext"], "ABCDEF")
        large = self.request(ciphertext="A"*20, stages=[{"operation": "substitution", "period": 20}])
        cpu = scan_batch(large, offset=2**54+19, batch_size=2)
        cuda = scan_batch(large, backend="cuda", offset=2**54+19, batch_size=2)
        self.assertEqual([c["plaintext"] for c in cpu["candidates"]], [c["plaintext"] for c in cuda["candidates"]])
        larger = scan_batch(self.request(stages=[{"operation": "substitution", "period": 2}]), backend="cuda", batch_size=512,ranking_mode="approximate")
        self.assertFalse(larger["ranking_exact_within_page"])
        self.assertEqual(larger["cpu_exact_scored"], 64)
        self.assertTrue(all(c["evidence"]["literal_reencryption_matches"] for c in larger["candidates"]))
        for mask in ([],[0,2,4]):
            request=self.request(stages=[{"operation":"substitution","period":2}],score_mask=mask)
            expected=scan_batch(request,batch_size=512)
            certified=scan_batch(request,backend="cuda",batch_size=512)
            self.assertEqual([(c["score_exact"],c["plaintext"],c["index"]) for c in expected["candidates"]],
                             [(c["score_exact"],c["plaintext"],c["index"]) for c in certified["candidates"]])
            self.assertTrue(certified["ranking_exact_within_page"])
            cached=scan_batch(request,backend="cuda",offset=512,batch_size=32)
            self.assertTrue(cached["certification"]["immutable_device_cache_hit"])
            if mask:
                self.assertEqual(certified["cpu_exact_scored"],512)


if __name__ == "__main__":
    unittest.main()
