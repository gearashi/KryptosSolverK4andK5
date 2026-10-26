"""Small exact oracles for the preregistered phase O engine controls."""
import itertools
import json
from pathlib import Path
import random
import shutil
import tempfile
import unittest

from kryptos.factor_decomposition import mini_bucket_upper
from kryptos.guided_search import guided_seeds
from kryptos.joint_ranked import rank_joint_columnar, _digest
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.search_runtime import optimize_lazy, score_assignment, SCHEMA
from tests.test_joint_ranked import oracle


def table(scope, values, power=1):
    return dict(kind="table", scope=scope, values=values, power=power)


def problem(domains, factors):
    return dict(schema=SCHEMA, domains=domains, factors=factors)


def literal(problem, point):
    result = 1
    for factor in problem["factors"]:
        number = 0
        for variable in factor["scope"]:
            number = number*problem["domains"][variable]+point[variable]
        result *= factor["values"][number]**factor.get("power",1)
    return result


class CoordinatedAndBoundTests(unittest.TestCase):
    def test_pair_barrier_and_small_unfavorable_control(self):
        for dimensions in (2,6):
            p = problem([2]*dimensions,[table([0,1],[2,1,1,9])])
            single = guided_seeds(p,restarts=1,max_sweeps=3,max_evaluations=100)
            paired = guided_seeds(p,restarts=1,max_sweeps=3,max_evaluations=100,block_size=2)
            self.assertEqual(int(single["candidates"][0]["score_hex"],16),2)
            self.assertEqual(int(paired["candidates"][0]["score_hex"],16),9)
            before_optimum = next(i+1 for i,pt in enumerate(itertools.product(range(2),repeat=dimensions)) if literal(p,pt)==9)
            if dimensions==6:
                self.assertLess(paired["work"]["objective_evaluations"],before_optimum)
            else:
                self.assertGreater(paired["work"]["objective_evaluations"],before_optimum)
            for row in paired["candidates"]:
                self.assertEqual(literal(p,row["assignment"]),int(row["score_hex"],16))

    def test_pair_delta_zero_power_caps_and_independent_factors(self):
        rng = random.Random(60131)
        for _ in range(30):
            p = problem([2,3,2],[table([0,1],[rng.randrange(5) for _ in range(6)],2),
                                     table([1,2],[rng.randrange(5) for _ in range(6)],3),table([],[rng.randrange(2)])])
            r = guided_seeds(p,block_size=2,max_evaluations=25,max_factor_evaluations=100,restarts=2)
            self.assertLessEqual(r["work"]["objective_evaluations"],25)
            self.assertLessEqual(r["work"]["factor_evaluations"],100)
            for row in r["candidates"]:
                self.assertEqual(literal(p,row["assignment"]),int(row["score_hex"],16))
        p = problem([2]*3,[table([i],[1,2]) for i in range(3)])
        a,b = [guided_seeds(p,block_size=size,restarts=1) for size in (1,2)]
        self.assertEqual(a["candidates"],b["candidates"])
        self.assertEqual(a["work"]["objective_evaluations"],b["work"]["objective_evaluations"])

    def test_mini_bucket_every_small_residual_and_caps(self):
        rng = random.Random(60132)
        for _ in range(36):
            domains = [rng.randrange(2,4) for _ in range(3)]
            factors = []
            for scope in ([],[0,1],[1,2],[0,2]):
                size = 1
                for v in scope:
                    size *= domains[v]
                factors.append(table(scope,[rng.randrange(5) for _ in range(size)],rng.randrange(1,4)))
            p = problem(domains,factors)
            for partial in itertools.product(*[(-1,0) for _ in domains]):
                truth = max(literal(p,pt) for pt in itertools.product(*(range(d) if v<0 else (v,) for d,v in zip(domains,partial))))
                for cap in (9,27):
                    r = mini_bucket_upper(p,partial,bucket_entries=cap)
                    self.assertTrue(r["bound_available"])
                    self.assertGreaterEqual(r["upper_bound"],truth)
            limited = mini_bucket_upper(p,max_operations=1)
            self.assertFalse(limited["bound_available"])
            self.assertIsNone(limited["upper_bound"])

    def test_bound_reduces_decisions_and_does_not_claim_witness(self):
        p = problem([2]*3,[table([0,1],[9,1,1,9]),table([1,2],[9,1,1,9]),table([0,2],[1,9,9,1])])
        baseline = optimize_lazy(p,ordering="natural")
        improved = optimize_lazy(p,ordering="natural",elimination_bound="mini_bucket",elimination_bucket_entries=8)
        self.assertEqual((improved["assignment"],improved["score"]),(baseline["assignment"],baseline["score"]))
        self.assertLess(improved["nodes"],baseline["nodes"])
        self.assertGreater(improved["work"]["elimination_tightenings"],0)
        relaxed = mini_bucket_upper(p,bucket_entries=4)
        self.assertGreater(relaxed["upper_bound"],baseline["score"])
        fallback = optimize_lazy(p,elimination_bound="mini_bucket",elimination_max_operations=1)
        self.assertEqual(fallback["score"],baseline["score"])
        self.assertGreater(fallback["work"]["elimination_fallbacks"],0)


class JointFrontierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = train_ngram_model([CorpusDocument("AAAAAAAAAAAAAAAAAABCDEFFEDCBA","phase-O synthetic")],label="Phase O",order=1)

    def setUp(self):
        self.base = Path(__file__).resolve().parents[1]/"research"/"manual-checks"
        self.base.mkdir(parents=True,exist_ok=True)
        self.folder = Path(tempfile.mkdtemp(prefix="joint-O-",dir=self.base))

    def tearDown(self):
        resolved = self.folder.resolve()
        self.assertEqual(resolved.parent,self.base.resolve())
        self.assertTrue(resolved.name.startswith("joint-O-"))
        shutil.rmtree(resolved)

    def run_case(self, **kwargs):
        return rank_joint_columnar("AAAAA",[],model=self.model,period=1,width=3,
            alphabet="standard",top=3,time_limit_seconds=10,**kwargs)

    def test_pruning_exact_top_ties_all_equations(self):
        for layer,cipher in itertools.product(("ST","TS"),("vigenere","beaufort","variant")):
            expected,assignments,_ = oracle("AAAAA",{},3,1,self.model,layer,cipher)
            actual = self.run_case(pruning="admissible",order=layer,cipher=cipher)
            self.assertTrue(actual["top_k_exact"])
            self.assertEqual([c["plaintext"] for c in actual["candidates"]],[p for p,_ in expected[:3]])
            self.assertLessEqual(actual["evaluated"],assignments)
            for row,(text,(score,(cols,key))) in zip(actual["candidates"],expected):
                self.assertEqual(int(row["score_exact"],16),score)
                self.assertEqual((tuple(row["column_order"]),row["key_pattern"]),(cols,key))

    def test_partial_key_pruning_reduces_actual_complete_objective_evaluations(self):
        baseline = rank_joint_columnar("AAAAA",[],model=self.model,period=2,width=3,
            alphabet="standard",top=1,max_states=1000000,time_limit_seconds=10)
        improved = rank_joint_columnar("AAAAA",[],model=self.model,period=2,width=3,
            alphabet="standard",top=1,max_states=1000000,time_limit_seconds=10,pruning="admissible")
        self.assertTrue(baseline["complete"])
        self.assertTrue(improved["complete"])
        self.assertEqual(baseline["candidates"],improved["candidates"])
        self.assertLess(improved["evaluated"],baseline["evaluated"])
        self.assertLess(improved["work"]["key_nodes"],baseline["work"]["key_nodes"])
        self.assertIsNone(improved["total_order_key_assignments"])

    def test_period_two_swapped_alphabet_and_masked_score_ties(self):
        alphabet = "BACDEFGHIJKLMNOPQRSTUVWXYZ"
        expected,_,_ = oracle("DBCFE",{0:"A"},3,2,self.model,"TS","beaufort",alphabet)
        r = rank_joint_columnar("DBCFE",[{"start":1,"text":"A"}],model=self.model,
            period=2,width=3,alphabet=alphabet,order="TS",cipher="beaufort",top=6,pruning="admissible")
        self.assertTrue(r["complete"])
        self.assertEqual([c["plaintext"] for c in r["candidates"]],[p for p,_ in expected[:6]])
        tied = self.run_case(pruning="admissible",score_mask=list(range(5)))
        self.assertEqual(tied["pruned_score_branches"],0)
        self.assertTrue(tied["enumeration_complete"])

    def test_twelve_fresh_bigram_oracles_with_reversed_ragged_columns(self):
        model = train_ngram_model([CorpusDocument("ABACABADABACABAEABCDEFFEDCBA","phase-O bigrams")],label="O bigram",order=2)
        for number,(order,cipher,alphabet) in enumerate(itertools.product(
                ("ST","TS"),("vigenere","beaufort","variant"),
                ("ABCDEFGHIJKLMNOPQRSTUVWXYZ","BACDEFGHIJKLMNOPQRSTUVWXYZ"))):
            reverse = bool(number%2)
            expected,_,_ = oracle("DHFBE",{0:"A"},3,2,model,order,cipher,alphabet,reverse)
            result = rank_joint_columnar("DHFBE",[{"start":1,"text":"A"}],model=model,
                period=2,width=3,alphabet=alphabet,order=order,cipher=cipher,top=4,
                column_direction="bottom_to_top" if reverse else "top_to_bottom",pruning="admissible")
            self.assertTrue(result["complete"])
            self.assertEqual([c["plaintext"] for c in result["candidates"]],[p for p,_ in expected[:4]])
            for candidate,(_, (score,(cols,key))) in zip(result["candidates"],expected):
                self.assertEqual(int(candidate["score_exact"],16),score)
                self.assertEqual((tuple(candidate["column_order"]),candidate["key_pattern"]),(cols,key))

    def test_continuation_no_repeated_candidates(self):
        for mode in ("off","admissible"):
            full = self.run_case(pruning=mode)
            path = None
            summed = 0
            verifications = verification_windows = previous_retained = 0
            for step in range(100):
                destination = self.folder/f"{mode}-{step}.json"
                r = self.run_case(pruning=mode,resume_path=path,checkpoint_path=destination,
                    max_evaluations=5,max_states=350,max_orders=1,max_segmentations=1)
                summed += r["evaluated_this_run"]
                self.assertEqual(summed,r["evaluated"])
                self.assertEqual(r["work_this_run"]["checkpoint_candidate_verifications"],previous_retained)
                self.assertEqual(r["work_this_run"]["checkpoint_score_window_evaluations"],previous_retained*5)
                verifications += previous_retained
                verification_windows += previous_retained*5
                self.assertEqual(r["work"]["checkpoint_candidate_verifications"],verifications)
                self.assertEqual(r["work"]["checkpoint_score_window_evaluations"],verification_windows)
                previous_retained = len(r["candidates"])
                self.assertGreaterEqual(r["states_total"],r["states_this_run"])
                path = destination
                if r["complete"]:
                    break
            self.assertTrue(r["complete"])
            self.assertEqual(r["candidates"],full["candidates"])
            self.assertEqual(r["evaluated"],full["evaluated"])
            self.assertEqual(r["column_orders_visited"],full["column_orders_visited"])
            self.assertEqual(r["pruned_score_branches"],full["pruned_score_branches"])
            self.assertEqual(full["work"]["checkpoint_candidate_verifications"],0)

    def test_checkpoint_rejects_tampering_and_changed_semantics(self):
        path = self.folder/"original.json"
        r = self.run_case(max_evaluations=1,checkpoint_path=path)
        self.assertFalse(r["complete"])
        for changes in ({"pruning":"admissible"},{"score_mask":[0]}):
            with self.assertRaises(ValueError):
                self.run_case(resume_path=path,**changes)
        saved = json.loads(path.read_text())
        saved["payload"]["evaluated"] += 1
        bad = self.folder/"bad.json"
        bad.write_text(json.dumps(saved))
        with self.assertRaises(ValueError):
            self.run_case(resume_path=bad)
        saved["payload"]["frontier"][0]["kind"] = "execute"
        saved["sha256"] = _digest(saved["payload"])
        bad.write_text(json.dumps(saved))
        with self.assertRaises(ValueError):
            self.run_case(resume_path=bad)
        bad.write_text('{"payload":{},"payload":{},"sha256":"x"}')
        with self.assertRaises(ValueError):
            self.run_case(resume_path=bad)

    def test_frontier_cap_restores_parent_without_counting_assignment(self):
        path = self.folder/"small.json"
        limited = self.run_case(max_frontier=1,checkpoint_path=path)
        self.assertEqual(limited["stop_reason"],"max_frontier")
        self.assertFalse(limited["complete"])
        final = self.run_case(resume_path=path,max_frontier=100)
        baseline = self.run_case()
        self.assertTrue(final["complete"])
        self.assertEqual(final["evaluated"],baseline["evaluated"])
        self.assertEqual(final["candidates"],baseline["candidates"])


if __name__ == "__main__":
    unittest.main()
