"""Hand-derived replay/position vectors and hostile inert-import controls."""
import copy
import json
import unittest

from kryptos.import_inspector import inspect_import, MAX_BYTES


def substitution(key="BC", cipher="vigenere", **extra):
    return {"operation": "repeat_substitution", "cipher": cipher,
            "key_pattern": key, **extra}


def artifact(plaintext="ABCDEF", ciphertext="BDFDHF", stages=None):
    return {"schema": "kryptos.candidate-export.v1",
            "request": {"target": "custom", "ciphertext": ciphertext,
                        "cribs": [{"start": 2, "text": "BC"}]},
            "candidate": {"plaintext": plaintext,
                "evidence": {"literal_reencryption_matches": True},
                "encryption_recipe": {"schema": "kryptos.encryption-recipe.v1",
                    "alphabet": "standard", "index_origin": 0,
                    "arithmetic": "modulo 26", "stages": stages or [
                        substitution(), {"operation": "gather", "permutation": [0, 2, 3, 1, 5, 4]}]}}}


class ImportInspectorTests(unittest.TestCase):
    def test_noninvolutive_gather_tracks_original_letters(self):
        value = artifact()
        before = copy.deepcopy(value)
        result = inspect_import({"artifact": value})
        self.assertTrue(result["valid"])
        self.assertEqual([s["output"] for s in result["trace"]], ["BDDFFH", "BDFDHF"])
        gather = result["trace"][1]
        self.assertEqual(gather["output_to_input"], [0, 2, 3, 1, 5, 4])
        self.assertEqual(gather["input_to_output"], [0, 3, 1, 2, 5, 4])
        self.assertEqual(gather["original_to_output"][1], 3)
        self.assertEqual(gather["output_to_original"][3], 1)
        self.assertEqual(value, before)
        self.assertFalse(result["authenticated_solution"])
        self.assertFalse(result["search_started"])

    def test_multiple_routes_compose_in_actual_direction(self):
        value = artifact("ABC", "ABC", [{"operation": "gather", "permutation": [1, 2, 0]},
                                        {"operation": "gather", "permutation": [2, 0, 1]}])
        result = inspect_import({"artifact": value})
        self.assertEqual([s["output"] for s in result["trace"]], ["BCA", "ABC"])
        self.assertEqual(result["trace"][0]["original_to_output"], [2, 0, 1])
        self.assertEqual(result["trace"][1]["original_to_output"], [0, 1, 2])

    def test_all_three_equations(self):
        for cipher, expected in [("vigenere", "BDD"), ("beaufort", "BBZ"), ("variant", "ZZB")]:
            with self.subTest(cipher=cipher):
                result = inspect_import({"artifact": artifact("ABC", expected, [substitution(cipher=cipher)])})
                self.assertTrue(result["valid"])

    def test_expanded_mixed_alphabet(self):
        # BACD...: indices(A,B,C)=(1,0,2); key CCC adds2 -> DCE.
        # Gather[1,2,0] -> CED; standard Beaufort key FGH -> DCE.
        value = artifact("ABC", "DCE", [substitution("CCC", alphabet="BACDEFGHIJKLMNOPQRSTUVWXYZ"),
                         {"operation": "gather", "permutation": [1, 2, 0]},
                         substitution("FGH", "beaufort", alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ")])
        value["candidate"]["encryption_recipe"] = {
            "schema": "kryptos.expanded-recipe.v1",
            "key_sharing_convention": "identical letter symbols",
            "stages": value["candidate"]["encryption_recipe"]["stages"]}
        result = inspect_import({"artifact": value})
        self.assertEqual([s["output"] for s in result["trace"]], ["DCE", "CED", "DCE"])
        self.assertTrue(result["valid"])

    def test_coordinate_lookups_use_current_stage_positions(self):
        row = {"operation": "coordinate_shift", "axis": "row", "lookup_offset": 1,
               "keys": [{"coordinate": 0, "shift": 1}, {"coordinate": 1, "shift": 3}]}
        col = {"operation": "coordinate_shift", "axis": "column", "lookup_offset": -1,
               "keys": [{"coordinate": 0, "shift": 2}, {"coordinate": 1, "shift": 5}]}
        value = artifact("ABC", "IIG", [row, {"operation": "gather", "permutation": [2, 0, 1]}, col])
        value["candidate"]["encryption_recipe"]["cells"] = [[0, 1], [1, 0], [1, 1]]
        result = inspect_import({"artifact": value})
        self.assertTrue(result["valid"])
        self.assertEqual([s["output"] for s in result["trace"]], ["DED", "DDE", "IIG"])
        self.assertEqual(result["trace"][2]["lookup_positions"], [2, 0, 1])
        self.assertEqual(result["trace"][2]["original_to_output"], [1, 2, 0])

    def test_tampering_ignores_saved_success(self):
        value = artifact()
        value["candidate"]["encryption_recipe"]["stages"][0]["key_pattern"] = "BD"
        result = inspect_import({"artifact": value})
        self.assertFalse(result["valid"])
        self.assertFalse(result["reencryption_matches"])
        self.assertEqual(result["crib_failures"], [])
        self.assertEqual([d["position"] for d in result["ciphertext_differences"]], [2, 3, 4])
        value = artifact()
        value["request"]["cribs"] = [{"start": 1, "text": "Z"}]
        result = inspect_import({"artifact": value})
        self.assertFalse(result["valid"])
        self.assertTrue(result["reencryption_matches"])
        self.assertEqual(result["crib_failures"], [{"position": 0, "expected": "Z", "actual": "A"}])

    def test_run_selection_and_legacy_wrapper(self):
        value = artifact()
        run = {"schema": "kryptos.local-run.v1", "request": value["request"],
               "candidates": [{"plaintext": "??????"}, value["candidate"]]}
        result = inspect_import({"artifact": run, "candidate_index": 1})
        self.assertTrue(result["valid"])
        self.assertEqual(result["candidate_count"], 2)
        with self.assertRaises(ValueError):
            inspect_import({"artifact": run})
        del value["schema"]
        self.assertTrue(inspect_import({"artifact": value})["legacy_wrapper"])

    def test_informational_paths_never_loaded_and_hashes_deterministic(self):
        value = artifact()
        value["request"]["model_path"] = "../../no-such-file.json"
        value["source_identity"] = {"../../untrusted.py": "fabricated"}
        first = inspect_import({"artifact": value})
        second = inspect_import({"artifact": json.dumps(value, indent=3)})
        self.assertEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertIsNone(first["raw_artifact_sha256"])
        self.assertEqual(len(second["raw_artifact_sha256"]), 64)
        self.assertIsNone(second["source_identity_match"])

    def test_malformed_and_unsupported_inputs_rejected(self):
        cases = []
        for mutate in [
            lambda a: a.update(schema="other.v1"),
            lambda a: a["request"].pop("cribs"),
            lambda a: a["request"].update(cribs=[{"start": True, "text": "A"}]),
            lambda a: a["request"].update(cribs=[{"start": 6, "text": "ABC"}]),
            lambda a: a["request"].update(cribs=[{"start": 1, "text": "A"}, {"start": 1, "text": "B"}]),
            lambda a: a["candidate"].update(plaintext="ABC???"),
            lambda a: a["candidate"]["encryption_recipe"].update(index_origin=False),
            lambda a: a["candidate"]["encryption_recipe"]["stages"][0].update(key_pattern="?"),
            lambda a: a["candidate"]["encryption_recipe"]["stages"][1].update(permutation=[0, 1, 2, 3, 4, 4]),
            lambda a: a["candidate"]["encryption_recipe"]["stages"][1].update(unknown_rule=True),
            lambda a: a.update(metadata={"checkpoint_path": "evil"}),
        ]:
            value = artifact()
            mutate(value)
            cases.append(value)
        cases.extend(['{"schema":1,"schema":2}', '{"x":NaN}', "x" * (MAX_BYTES + 1)])
        for value in cases:
            with self.subTest(value=str(value)[:120]), self.assertRaises(ValueError):
                inspect_import({"artifact": value})
        for index in [True, -1, 1, "0"]:
            with self.assertRaises(ValueError):
                inspect_import({"artifact": artifact(), "candidate_index": index})


if __name__ == "__main__":
    unittest.main()
