import json
from pathlib import Path
import tempfile
import unittest

from kryptos.app_jobs import RunManager, validate_start
from kryptos.research_methods import catalog, execute


class ResearchMethodsTests(unittest.TestCase):
    def test_catalog_has_all90_and_explicit_examples(self):
        value=catalog()
        self.assertEqual([entry["number"] for entry in value["entries"]],list(range(1,91)))
        self.assertEqual(len({entry["id"] for entry in value["entries"]}),90)
        self.assertTrue(value["examples"])

    def test_managed_constraints_keep_native_request_and_work_evidence(self):
        request={"domains":{"x":[0,1]},"relations":[{"scope":["x"],"rows":[[1]]}]}
        config={"kind":"exact","command":"constraint-lab","request":request}
        self.assertEqual(validate_start(config)["request"],request)
        with tempfile.TemporaryDirectory(prefix="kryptos-method-") as folder:
            manager=RunManager(Path(folder)/"runs")
            try:
                record=manager.start(config)
                manager.thread.join(15)
                result=manager.view(record["id"])
                self.assertEqual(result["state"],"completed",result.get("error"))
                self.assertEqual(result["result"]["analysis"]["candidates"][0]["assignment"],{"x":1})
                self.assertEqual(result["candidates"],[])
                self.assertFalse(result["result"]["authenticated_solution"])
                self.assertIn("work",result["result"]["analysis"])
            finally:manager.close()

    def test_factor_incomplete_is_not_reported_as_complete(self):
        request=json.loads(Path("examples/factor-Q-conditional.json").read_text(encoding="utf-8"))
        request["options"]["max_operations"]=1
        self.assertIs(execute("factor-lab",request)["complete"],False)

    def test_method_commands_cannot_impersonate_cuda_family_scans(self):
        for kind,backend in (("accelerated","cpu"),("exact","cuda")):
            with self.assertRaises(ValueError):validate_start({"command":"model-lab","kind":kind,"backend":backend,"request":{}})

    def test_nested_affine_models_keep_dashboard_path_restrictions(self):
        request={"method":"affine","parameters":{"cipher_request":{"model_path":"../../private-model.json"}}}
        with self.assertRaisesRegex(ValueError,"bundled"):
            validate_start({"command":"constraint-lab","request":request})
        request={"method":"family_cover","parameters":{"families":[{"model_path":"../../private-model.json","candidates":[]}]}}
        with self.assertRaisesRegex(ValueError,"bundled"):
            validate_start({"command":"constraint-lab","request":request})


if __name__=="__main__":unittest.main()
