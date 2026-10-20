import copy
from itertools import product
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from kryptos.__main__ import _target
from kryptos.next_cli import _optimization_job, run_next
from kryptos.search_runtime import SCHEMA, _Evaluator, optimize_lazy, score_assignment

ROOT=Path(__file__).resolve().parents[1]


def independent_score(problem,point):
    result=1
    for f in problem["factors"]:
        index=0
        for v in f["scope"]:
            index=index*problem["domains"][v]+point[v]
        result*=f["values"][index]**f.get("power",1)
    return result


class GroupBoundTests(unittest.TestCase):
    def test_all_partial_assignments_against_independent_exhaustion(self):
        rng=random.Random(2026101403)
        for _ in range(8):
            problem={"schema":SCHEMA,"domains":[2,3,2],"factors":[
                {"kind":"table","scope":[0,1],"values":[rng.randrange(10) for _ in range(6)],"power":2},
                {"kind":"table","scope":[1,2],"values":[rng.randrange(10) for _ in range(6)]},
                {"kind":"table","scope":[],"values":[2]}]}
            points=list(product(range(2),range(3),range(2)))
            scores={p:independent_score(problem,p) for p in points}
            grouped=_Evaluator(problem,10000,1,2,12)
            fallback=_Evaluator(problem,10000,1,2,1)
            original=_Evaluator(problem,10000,1)
            for partial in product(range(-1,2),range(-1,3),range(-1,2)):
                exact=max(scores[p] for p in points if all(v<0 or v==p[i] for i,v in enumerate(partial)))
                self.assertEqual(grouped.upper(partial),exact)
                self.assertGreaterEqual(fallback.upper(partial),exact)
                self.assertLessEqual(grouped.upper(partial),original.upper(partial))
            truth=min(points,key=lambda p:(-scores[p],p))
            for group_size in (0,2,8):
                result=optimize_lazy(problem,factor_group_size=group_size,group_exact_limit=12)
                self.assertTrue(result["complete"])
                self.assertEqual(tuple(result["assignment"]),truth)
                self.assertEqual(result["score"],scores[truth])

    def test_conflicting_factor_maxima_and_resume_identity(self):
        problem={"schema":SCHEMA,"domains":[2],"factors":[
            {"kind":"table","scope":[0],"values":[9,1]},
            {"kind":"table","scope":[0],"values":[1,8]}]}
        self.assertEqual(_Evaluator(problem,0,1).upper((-1,)),72)
        self.assertEqual(_Evaluator(problem,0,1,2,2).upper((-1,)),9)
        with tempfile.TemporaryDirectory() as folder:
            saved=Path(folder)/"grouped.json"
            first=optimize_lazy(problem,max_nodes=0,factor_group_size=2,group_exact_limit=2,checkpoint_path=saved)
            second=optimize_lazy(problem,resume_path=saved,factor_group_size=2,group_exact_limit=2)
            self.assertEqual(second["assignment"],[0])
            self.assertEqual(first["upper_bound"],second["score"])
            for options in ({"factor_group_size":0,"group_exact_limit":2},{"factor_group_size":2,"group_exact_limit":1}):
                with self.assertRaises(ValueError): optimize_lazy(problem,resume_path=saved,**options)

    def test_seed_domain_check_objective_ties_and_elapsed_budget(self):
        problem={"schema":SCHEMA,"domains":[3],"factors":[{"kind":"table","scope":[0],"values":[1,7,7]}]}
        seeded=optimize_lazy(problem,initial_assignments=[[2]],max_nodes=0)
        self.assertEqual(seeded["score"],7)
        self.assertFalse(seeded["tie_break_proven"])
        finished=optimize_lazy(problem,initial_assignments=[[2]])
        self.assertEqual(finished["assignment"],[1])
        for point in ([3],[-1],[True],[],"1"):
            with self.assertRaises(ValueError): optimize_lazy(problem,initial_assignments=[point])
        stopped=optimize_lazy(problem,initial_assignments=[[1]],time_limit_seconds=0.1,elapsed_before_seconds=0.2)
        self.assertEqual(stopped["nodes"],0)
        self.assertEqual(stopped["stop_reason"],"time_limit")
        self.assertGreaterEqual(stopped["runtime_seconds"],0.2)

    def test_prior_budget_survives_large_clock_with_zero_new_elapsed(self):
        problem={"schema":SCHEMA,"domains":[2],"factors":[
            {"kind":"table","scope":[0],"values":[1,7]}]}
        # At this clock magnitude, subtracting0.2 rounds back to the same
        # timestamp. The previously spent0.2 must still exhaust this budget.
        with patch("kryptos.search_runtime.time.monotonic",return_value=float(2**52)):
            result=optimize_lazy(problem,time_limit_seconds=0.2,elapsed_before_seconds=0.2)
        self.assertEqual(result["runtime_seconds"],0.2)
        self.assertEqual(result["nodes"],0)
        self.assertEqual(result["stop_reason"],"time_limit")
        self.assertFalse(result["complete"])


class ScannerSeedTests(unittest.TestCase):
    def request(self):
        request=json.loads((ROOT/"examples/optimize-lazy.json").read_text())
        request["model_path"]=str(ROOT/request["model_path"])
        return request

    def test_real_cpu_scan_seed_exact_solution_and_mask(self):
        request=self.request()
        plain=run_next("optimize-plus",request,_target)
        request["seed_scan"]={"backend":"cpu","batch_size":26,"top":3}
        seeded=run_next("optimize-plus",request,_target)
        a,b=plain["optimization"],seeded["optimization"]
        self.assertEqual(a["search"]["score"],b["search"]["score"])
        self.assertEqual(a["search"]["assignment"],b["search"]["assignment"])
        self.assertEqual(a["candidate"]["plaintext"],b["candidate"]["plaintext"])
        self.assertEqual(b["search"]["seed_scan"]["verified_seeds"],3)
        request["score_mask"]=[0,4]
        masked=run_next("optimize-plus",request,_target)
        self.assertEqual(masked["optimization"]["scoring"]["excluded_positions"],[0,4])
        for mask in ([],[0,0],[0,99],[True]):
            with self.assertRaises(ValueError): _optimization_job(dict(request,score_mask=mask),_target)

    def test_invalid_seed_pages_cannot_change_incumbent(self):
        request=self.request()
        request["seed_scan"]={"backend":"cpu","batch_size":1}
        job=_optimization_job(request,_target)
        candidate=job["solution"].candidate()
        point=candidate["values_mod2"]+candidate["values_mod13"]
        candidate["score_exact"]=hex(score_assignment(job["problem"],point))
        valid={"model_file_sha256":job["model_sha256"],"candidates":[candidate],"evaluated":1,"backend_used":"cpu"}
        for field,value in (("plaintext","Z"*len(job["text"])),("score_exact","0x0"),("values_mod2",[99])):
            page=copy.deepcopy(valid)
            page["candidates"][0][field]=value
            with patch("kryptos.accelerated.scan_batch",return_value=page), self.assertRaises((ValueError,AssertionError)):
                run_next("optimize-plus",request,_target)
        for setting in ({"batch_size":-1},{"batch_size":True},{"offset":-1},{"top":11},{"backend":"other"}):
            with self.assertRaises(ValueError): run_next("optimize-plus",dict(request,seed_scan=setting),_target)

    @unittest.skipUnless(os.environ.get("KRYPTOS_TEST_CUDA")=="1","CUDA seed check is opt-in")
    def test_actual_cuda_seed_replays_and_preserves_exact_answer(self):
        request=self.request()
        plain=run_next("optimize-plus",request,_target)["optimization"]
        request["seed_scan"]={"backend":"cuda","batch_size":26,"top":3}
        seeded=run_next("optimize-plus",request,_target)["optimization"]
        self.assertEqual(seeded["search"]["seed_scan"]["backend_used"],"cuda")
        self.assertEqual(seeded["search"]["seed_scan"]["verified_seeds"],3)
        self.assertEqual(plain["search"]["assignment"],seeded["search"]["assignment"])
        self.assertEqual(plain["search"]["score"],seeded["search"]["score"])
        self.assertTrue(seeded["candidate"]["evidence"]["literal_reencryption_matches"])


if __name__=="__main__": unittest.main()
