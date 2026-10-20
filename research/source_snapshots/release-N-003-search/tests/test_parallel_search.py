import unittest
import os
from pathlib import Path
import uuid

from kryptos.parallel_search import optimize_batch
from kryptos.search_runtime import SCHEMA
from kryptos.replay_expanded import replay_expanded


class ParallelTests(unittest.TestCase):
    def test_serial_parallel_exact_equality(self):
        problem={"schema":SCHEMA,"domains":[2,2],"factors":[{"kind":"table","scope":[0,1],"values":[1,2,3,8]}]}
        jobs=[{"id":name,"problem":problem,"options":{"max_nodes":50,"time_limit_seconds":2}} for name in ("b","a","c")]
        serial=optimize_batch(jobs,workers=1)
        parallel=optimize_batch(jobs,workers=2)
        for a,b in zip(serial["jobs"],parallel["jobs"]):
            self.assertEqual(a["id"],b["id"])
            for key in ("assignment","score","lower_bound","upper_bound","complete","tie_break_proven","nodes"):
                self.assertEqual(a["result"][key],b["result"][key])
        self.assertTrue(parallel["all_searches_complete"])
        self.assertEqual([r["id"] for r in parallel["jobs"]],["a","b","c"])

    def test_conflicting_checkpoints_rejected_before_work(self):
        problem={"schema":SCHEMA,"domains":[],"factors":[]}
        jobs=[{"id":name,"problem":problem,"options":{"checkpoint_path":"research/same-checkpoint.json"}} for name in ("a","b")]
        with self.assertRaises(ValueError):
            optimize_batch(jobs,workers=2)

    def test_relative_checkpoint_paths_use_caller_directory(self):
        original=Path.cwd()
        folder=original/"research"/(".paths-"+uuid.uuid4().hex)
        folder.mkdir()
        problem={"schema":SCHEMA,"domains":[2],"factors":[{"kind":"table","scope":[0],"values":[1,2]}]}
        try:
            os.chdir(folder)
            for workers in (1,2):
                path=f"state-{workers}.json"
                jobs=[{"id":"one","problem":problem,"options":{"checkpoint_path":path,"max_nodes":0}}]
                optimize_batch(jobs,workers=workers)
                self.assertTrue((folder/path).is_file())
                self.assertEqual(jobs[0]["options"]["checkpoint_path"],path)
                resumed=optimize_batch([{"id":"one","problem":problem,"options":{"resume_path":path}}],workers=workers)
                self.assertEqual(resumed["jobs"][0]["result"]["assignment"],[1])
        finally:
            os.chdir(original)
            for path in folder.iterdir():
                path.unlink()
            folder.rmdir()

    def test_expanded_replay_mixed_and_nonperiodic(self):
        a="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b=a[::-1]
        recipe={"schema":"kryptos.expanded-recipe.v1","stages":[
            {"operation":"repeat_substitution","cipher":"vigenere","alphabet":a,"key_pattern":"BCDE"},
            {"operation":"gather","permutation":[2,0,3,1]},
            {"operation":"repeat_substitution","cipher":"variant","alphabet":b,"key_pattern":"ZZZZ"}]}
        result=replay_expanded("AAAA",recipe)
        self.assertEqual(result["ciphertext"],"DBEC")
        self.assertEqual(len(result["stages"]),3)


if __name__=="__main__":
    unittest.main()
