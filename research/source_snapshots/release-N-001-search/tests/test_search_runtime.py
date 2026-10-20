import itertools
import json
from pathlib import Path
import random
import unittest
import uuid

from kryptos.search_runtime import SCHEMA,lazy_ngram_problem,optimize_lazy,score_assignment
from kryptos.factor_search import ngram_problem,product_score
from kryptos.general_layers import solve_layers
from kryptos.language import CorpusDocument,train_ngram_model


def table_problem():
    return {"schema":SCHEMA,"domains":[2,2,2],"factors":[
        {"kind":"table","scope":[0,2],"values":[1,2,3,10]},
        {"kind":"table","scope":[1,2],"values":[2,1,3,4]}]}


class SearchRuntimeTests(unittest.TestCase):
    def test_exact_random_tables_and_partial_bounds(self):
        rng=random.Random(20261013)
        for _ in range(12):
            problem={"schema":SCHEMA,"domains":[2,3,2],"factors":[
                {"kind":"table","scope":[0,1],"values":[rng.randrange(10) for _ in range(6)]},
                {"kind":"table","scope":[1,2],"values":[rng.randrange(10) for _ in range(6)]}]}
            points=list(itertools.product(range(2),range(3),range(2)))
            scores={p:score_assignment(problem,p) for p in points}
            best=min(points,key=lambda p:(-scores[p],p))
            for order in ("natural","impact"):
                for limit in (0,1,3,100):
                    result=optimize_lazy(problem,ordering=order,max_nodes=limit)
                    self.assertLessEqual(result["lower_bound"],scores[best])
                    self.assertGreaterEqual(result["upper_bound"],scores[best])
                    if result["complete"]:
                        self.assertEqual(tuple(result["assignment"]),best)
                        self.assertTrue(result["optimal"])
                        self.assertTrue(result["tie_break_proven"])

    def test_lazy_matches_dense_and_mask_gaps(self):
        model=train_ngram_model([CorpusDocument("SECRETMESSAGE"*10,"authored-control")],label="control",order=3,alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",normalization="identity")
        solution=solve_layers("ABCDEFGHIJKL",{0:"A"},[{"operation":"substitution","period":3}])
        mask=[0,5]
        problem=lazy_ngram_problem(solution,model,mask)
        dense=ngram_problem(solution,model,mask,max_factor_entries=100000)
        self.assertEqual(problem["metadata"]["windows"],dense.metadata["windows"])
        expected=[]
        for point in itertools.product(*(range(d) for d in problem["domains"])):
            score=score_assignment(problem,point)
            self.assertEqual(score,product_score(dense.domains,dense.factors,point))
            expected.append((score,point))
        truth=min(expected,key=lambda v:(-v[0],v[1]))
        for local_limit in (1,64):
            result=optimize_lazy(problem,local_exact_limit=local_limit,max_nodes=10000,time_limit_seconds=10)
            self.assertTrue(result["complete"])
            self.assertEqual((result["score"],tuple(result["assignment"])),truth)
        self.assertGreater(problem["metadata"]["dense_entries_avoided"],len(problem["factors"]))

    def test_checkpoint_resume_and_frontier_cap(self):
        folder=Path("research") / ("tmp-frontier-"+uuid.uuid4().hex)
        folder.mkdir()
        try:
            problem=table_problem()
            stopped=optimize_lazy(problem,max_frontier=1,checkpoint_path=folder/"a.json")
            self.assertFalse(stopped["complete"])
            self.assertEqual(stopped["stop_reason"],"frontier_limit")
            resumed=optimize_lazy(problem,max_nodes=1,resume_path=folder/"a.json",checkpoint_path=folder/"b.json")
            final=optimize_lazy(problem,resume_path=folder/"b.json")
            direct=optimize_lazy(problem)
            self.assertEqual(final["score"],direct["score"])
            self.assertEqual(final["assignment"],direct["assignment"])
            self.assertTrue(final["complete"])
            self.assertTrue(resumed["resumed"])
            with self.assertRaises(ValueError):
                optimize_lazy(problem,checkpoint_path=folder/"a.json")
            changed=table_problem()
            changed["factors"][0]["values"][0]+=1
            with self.assertRaises(ValueError):
                optimize_lazy(changed,resume_path=folder/"a.json")
            data=json.loads((folder/"a.json").read_text())
            data["payload"]["frontier"]=[]
            (folder/"tampered.json").write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                optimize_lazy(problem,resume_path=folder/"tampered.json")
        finally:
            for path in folder.iterdir():
                path.unlink()
            folder.rmdir()

    def test_correlated_lazy_bound_does_not_prune_truth(self):
        # One unknown shifts both letters equally; 'AB' is impossible, even
        # though each character is individually reachable. The relaxed upper
        # may admit it; exact search must recover AA/BB and the true optimum.
        problem={"schema":SCHEMA,"domains":[2],"model":{"alphabet":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","order":2,"p":1,"q":1,"id":"hand","counts":{"AB":100,"BB":4,"AA":1}},
                 "factors":[{"kind":"ngram","scope":[0],"base":[0,0],"columns":[[1,1]]}]}
        stopped=optimize_lazy(problem,max_nodes=0,local_exact_limit=1)
        self.assertEqual(stopped["upper_bound"],101)
        result=optimize_lazy(problem,local_exact_limit=1)
        self.assertEqual(result["assignment"],[1])
        self.assertEqual(result["score"],5)
        self.assertTrue(result["complete"])

    def test_empty_objective_and_validation(self):
        result=optimize_lazy({"schema":SCHEMA,"domains":[2],"factors":[]})
        self.assertEqual(result["assignment"],[0])
        self.assertTrue(result["complete"])
        for options in ({"max_frontier":0},{"max_nodes":True},{"time_limit_seconds":float("nan")},{"ordering":"random"}):
            with self.assertRaises(ValueError):
                optimize_lazy(table_problem(),**options)


if __name__ == "__main__":
    unittest.main()
