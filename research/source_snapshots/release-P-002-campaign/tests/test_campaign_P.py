"""Authored finite controls for shared, original-coordinate scan progress."""
import copy
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from kryptos.app_jobs import RunManager, validate_start
from kryptos.app_worker import execute
from kryptos.campaigns import CampaignManager, preview_campaign
from kryptos.campaign_sharing import compatible_prefix, digest
from kryptos.explanations import replay_recipe
from kryptos.language import CharacterNgramModel


MODEL = "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"


def plan(*, enabled=True, size=13, ciphers=("vigenere", "variant")):
    return {"name": "P6 authored control", "share_incomplete_scans": enabled,
            "base": {"kind": "accelerated", "command": "optimize-plus", "backend": "cpu",
                     "workers": 1, "batch_size": size, "max_batches": 1, "time_limit_seconds": 10,
                     "ranking_mode": "certified", "adaptive": False,
                     "request": {"target": "custom", "ciphertext": "BCDEFG", "cribs": [],
                                 "alphabet": "standard", "stages": [{"operation": "substitution", "period": 1}],
                                 "model_path": MODEL}},
            "axes": [{"path": "request.stages.0.cipher", "values": list(ciphers)}]}


def three_job_plan():
    """Three explicitly equivalent offset parameterizations, declared before use."""
    result = plan(size=10)
    result['base']['request'].update(layer_model='scheduled', stages=[
        {'operation':'substitution','key_id':'k','key_length':1,'cipher':'vigenere','offset':0}])
    result['axes'] = [{'path':'request.stages.0.offset','values':[0,1,2]}]
    return result


class CampaignPTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / "runtime"
        root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="campaign-P-", dir=root)
        self.folder = Path(self.temporary.name)
        self.manager = RunManager(self.folder / "runs")
        self.campaign = CampaignManager(self.manager)
        self.calls = []

    def tearDown(self):
        self.campaign.close()
        self.manager.close()
        self.temporary.cleanup()

    def dispatch(self, key, job):
        self.calls.append((key, job["offset"], job["request"]["stages"][0]["cipher"]))
        return execute(job)

    def wait(self):
        self.campaign.thread.join(timeout=15)
        self.assertFalse(self.campaign.thread.is_alive())
        value = self.campaign.view()
        self.assertNotEqual(value["state"], "failed", value.get("error"))
        return value

    def run_plan(self, body):
        with patch.object(self.manager, "_launch", side_effect=self.dispatch), patch.object(
                self.campaign, "_task", side_effect=lambda key, job: execute(job)):
            self.campaign.start(body)
            return self.wait()

    def test_default_off_and_unsupported_options(self):
        value = plan()
        value.pop("share_incomplete_scans")
        self.assertFalse(preview_campaign(value)["share_incomplete_scans"])
        for setting, change in (("ranking_mode", "approximate"), ("adaptive", True), ("kind", "exact")):
            value = plan()
            value["base"][setting] = change
            with self.subTest(setting=setting), self.assertRaisesRegex(ValueError, "Shared unfinished"):
                preview_campaign(value)
        value = plan()
        value["share_incomplete_scans"] = "yes"
        with self.assertRaisesRegex(ValueError, "boolean"):
            preview_campaign(value)

    def test_two_limited_jobs_finish_one_sequence_and_preserve_history(self):
        result = self.run_plan(plan())
        first, second = result["jobs"]
        self.assertEqual([j["state"] for j in result["jobs"]], ["incomplete", "completed"])
        self.assertEqual(len(self.manager.records), 1)
        self.assertEqual([r[1:] for r in self.calls], [(0, "vigenere"), (13, "vigenere")])
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(first["scan_snapshot"]["completed_offset_decimal"], "13")
        self.assertFalse(first["scan_snapshot"]["top_k_exact"])
        self.assertTrue(second["scan_snapshot"]["top_k_exact"])
        self.assertEqual(second["scan_snapshot"]["work"]["new_candidate_evaluations_decimal"], "13")
        self.assertEqual(second["scan_snapshot"]["work"]["reused_prefix_candidate_count_decimal"], "13")
        self.assertEqual(first["scan_snapshot"]["state_at_commit"], "limited")
        oracle = execute({"kind": "accelerated", "request": second["config"]["request"],
                          "backend": "cpu", "offset": 0, "batch_size": 26, "top": 20})
        signature = lambda rows: [(c["plaintext"], c["score_exact"]) for c in rows]
        self.assertEqual(signature(second["candidates"]), signature(oracle["candidates"]))
        for candidate in second["candidates"]:
            self.assertEqual(replay_recipe(candidate["plaintext"], candidate["encryption_recipe"])["ciphertext"], "BCDEFG")
            self.assertNotIn("assignment_index_decimal", candidate)
            self.assertEqual(candidate["encryption_recipe"]["stages"][0]["cipher"], "variant")
        self.assertEqual(second["sharing_validation"]["candidate_replays"], 20)
        self.assertEqual(second["sharing_validation"]["literal_reencrypted_letters"], 120)

    def test_three_aliases_keep_the_latest_prefix_not_stale_first_snapshot(self):
        result = self.run_plan(three_job_plan())
        self.assertEqual([j["scan_snapshot"]["completed_offset_decimal"] for j in result["jobs"]], ["10", "20", "26"])
        self.assertEqual([r[1] for r in self.calls], [0, 10, 20])
        self.assertEqual(len(self.manager.records), 1)
        self.assertEqual(result["jobs"][2]["shared_scan"]["reference_job_id"], "job-002")
        self.assertEqual([j["state"] for j in result["jobs"]], ["incomplete", "incomplete", "completed"])

    def test_beaufort_is_a_different_family_for_this_ciphertext(self):
        result = self.run_plan(plan(size=10, ciphers=("vigenere", "variant", "beaufort")))
        self.assertEqual([j['scan_snapshot']['completed_offset_decimal'] for j in result['jobs']], ['10','20','10'])
        self.assertEqual(len(self.manager.records), 2)
        self.assertNotEqual(result['jobs'][0]['family_identity']['family_sha256'], result['jobs'][2]['family_identity']['family_sha256'])

    def test_masked_alias_products_are_independently_recomputed_without_gap_ngrams(self):
        value = plan()
        value['base']['request']['score_mask'] = [0,2]
        result = self.run_plan(value)
        model = CharacterNgramModel.from_json(Path(MODEL).read_text(encoding='utf-8'))
        p,q = float(model.alpha).as_integer_ratio()
        for candidate in result['jobs'][1]['candidates']:
            product = 1
            text = candidate['plaintext']
            starts = [i for i in range(len(text)-model.order+1)
                      if not set(range(i,i+model.order)).intersection({0,2})]
            self.assertEqual(starts,[3])
            for i in starts:
                product *= model.counts.get(text[i:i+model.order],0)*q+p
            self.assertEqual(int(candidate['score_exact'],16), product)

    def test_default_off_keeps_independent_partial_runs(self):
        result = self.run_plan(plan(enabled=False))
        self.assertEqual(len(self.manager.records), 2)
        self.assertEqual([r[1] for r in self.calls], [0, 0])
        self.assertEqual([j["state"] for j in result["jobs"]], ["incomplete", "incomplete"])
        self.assertTrue(all("scan_snapshot" not in j for j in result["jobs"]))

    def test_incompatible_model_and_mask_do_not_share(self):
        value = plan()
        value["axes"] = [{"path": "request.model_path", "values": [MODEL,
            "research/runs/evaluation-J-001/artifacts/english-two-author-trigram.json"]}]
        result = self.run_plan(value)
        self.assertEqual(len(self.manager.records), 2)
        first, second = result["jobs"]
        self.assertNotEqual(first["family_identity"]["scoring_family_sha256"], second["family_identity"]["scoring_family_sha256"])
        request = copy.deepcopy(first["config"]["request"])
        request["score_mask"] = [0]
        other = execute({"kind": "family-identity", "request": request})
        self.assertNotEqual(other["scoring_family_sha256"], first["family_identity"]["scoring_family_sha256"])
        self.assertEqual(other["family_sha256"], first["family_identity"]["family_sha256"])

    def test_stale_committed_bytes_fall_back_without_importing_a_frontier(self):
        original = self.campaign._shared_source
        def changed(record, index, job):
            if index == 1:
                owner = record["jobs"][0]
                path = self.manager.directory / owner["run_id"] / "run.json"
                path.write_bytes(path.read_bytes() + b" ")
            return original(record, index, job)
        with patch.object(self.campaign, "_shared_source", side_effect=changed):
            result = self.run_plan(plan())
        self.assertEqual(len(self.manager.records), 2)
        self.assertEqual(result["jobs"][1]["sharing_status"]["reason"], "missing_or_changed_committed_snapshot")
        self.assertEqual([r[1] for r in self.calls], [0, 0])

    def test_guard_rejects_resources_request_failed_or_noncertified_owner(self):
        result = self.run_plan(plan(ciphers=("vigenere",)))
        owner = result["jobs"][0]
        run = self.manager.view(owner["run_id"])
        clone = copy.deepcopy(owner)
        clone["id"] = "job-002"
        settings = validate_start(clone["config"])["settings"]
        run_hash = owner["scan_snapshot"]["run_sha256"]
        current = run["source_identity"]
        self.assertIsNone(compatible_prefix(clone, owner, owner, run, run_hash, current, settings))
        variants = [dict(run, state="failed"), dict(run, ranking_exact_over_committed_pages=False),
                    dict(run, pending_resources={"workers": 2}), dict(run, resource_events=[{}]),
                    dict(run, request={**run["request"], "ciphertext": "AAAAAA"}),
                    dict(run, settings={**settings, "batch_size": 14}),
                    dict(run, source_identity={"changed": "bytes"})]
        for value in variants:
            with self.subTest(value=value.get("state")):
                self.assertIsNotNone(compatible_prefix(clone, owner, owner, value, run_hash, current, settings))

    def test_pause_restart_retains_one_owned_prefix_and_idle_reload(self):
        entered, release = threading.Event(), threading.Event()
        def dispatch(key, job):
            result = self.dispatch(key, job)
            if job["offset"] == 5:
                entered.set()
                release.wait(5)
            return result
        with patch.object(self.manager, "_launch", side_effect=dispatch), patch.object(
                self.campaign, "_task", side_effect=lambda key, job: execute(job)):
            started = self.campaign.start(plan(size=5))
            self.assertTrue(entered.wait(5))
            self.campaign.control("pause", started["id"])
            deadline = time.monotonic() + 3
            while self.manager.desired != "pause" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(self.manager.desired, "pause")
            release.set()
            paused = self.wait()
        self.assertEqual(paused["state"], "paused")
        self.assertEqual(self.manager.view()["progress"]["completed"], 10)
        before = copy.deepcopy(paused["jobs"][0]["scan_snapshot"])
        key = paused["jobs"][0]["run_id"]
        self.campaign.close()
        self.manager.close()
        self.manager = RunManager(self.folder / "runs")
        self.campaign = CampaignManager(self.manager)
        self.assertFalse(self.campaign.is_active())
        self.assertEqual(self.manager.view(key)["progress"]["completed"], 10)
        with patch.object(self.manager, "_launch", side_effect=self.dispatch), patch.object(
                self.campaign, "_task", side_effect=lambda key, job: execute(job)):
            self.campaign.control("resume", paused["id"])
            finished = self.wait()
        self.assertEqual([r[1] for r in self.calls], [0, 5, 10])
        self.assertEqual(len(self.manager.records), 1)
        self.assertEqual(digest(finished["jobs"][0]["scan_snapshot"]), digest(before))
        self.assertEqual(finished["jobs"][1]["scan_snapshot"]["completed_offset_decimal"], "15")
        self.assertFalse(finished["jobs"][1]["scan_snapshot"]["top_k_exact"])

    def test_reserved_missing_or_failed_owner_never_starts_a_replacement(self):
        # A dispatch failure after reservation leaves a recoverable campaign,
        # but an absent/failed owner must not become an alias-basis restart.
        with patch.object(self.manager,'_launch',side_effect=self.dispatch), patch.object(
                self.campaign,'_task',side_effect=lambda key,job:execute(job)), patch.object(
                self.manager,'control',side_effect=RuntimeError('injected dispatch failure')):
            self.campaign.start(plan())
            self.campaign.thread.join(timeout=10)
        saved=self.campaign.view()
        self.assertEqual(saved['state'],'failed')
        shared=saved['jobs'][1]
        self.assertIn('shared_scan',shared)
        source=self.manager.records[shared['run_id']]
        for missing in (False,True):
            with self.subTest(missing=missing):
                if missing:
                    self.manager.records.pop(source['id'])
                else:
                    source['state']='failed'
                with patch.object(self.manager,'_launch',side_effect=self.dispatch):
                    self.campaign.control('resume',saved['id'])
                    self.campaign.thread.join(timeout=10)
                rejected=self.campaign.view()
                self.assertEqual(rejected['state'],'failed')
                self.assertIn('Shared scan owner',rejected['error'])
                self.assertEqual([r[1] for r in self.calls],[0])

    def test_failed_shared_reservation_save_never_dispatches_or_changes_job(self):
        original=self.campaign._save
        def save(record):
            if record['jobs'][1].get('shared_scan'):
                raise OSError('injected shared reservation write failure')
            return original(record)
        with patch.object(self.manager,'_launch',side_effect=self.dispatch), patch.object(
                self.campaign,'_task',side_effect=lambda key,job:execute(job)), patch.object(
                self.campaign,'_save',side_effect=save):
            self.campaign.start(plan())
            self.campaign.thread.join(timeout=10)
        saved=self.campaign.view()
        self.assertEqual(saved['state'],'failed')
        self.assertIsNone(saved['jobs'][1]['run_id'])
        self.assertNotIn('shared_scan',saved['jobs'][1])
        self.assertEqual([r[1] for r in self.calls],[0])
        with patch.object(self.manager,'_launch',side_effect=self.dispatch), patch.object(
                self.campaign,'_task',side_effect=lambda key,job:execute(job)):
            self.campaign.control('resume',saved['id'])
            result=self.wait()
        self.assertEqual([r[1] for r in self.calls],[0,13])
        self.assertEqual(result['jobs'][1]['state'],'completed')


if __name__ == "__main__":
    unittest.main()
