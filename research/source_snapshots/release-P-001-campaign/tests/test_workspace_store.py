import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace

from kryptos.workspace_store import WorkspaceStore, packed
from kryptos.app import make_server


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = WorkspaceStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, operation, **fields):
        return self.store.update({"revision": self.store.view()["revision"], "operation": operation, **fields}, lambda c: None)

    def fixture(self):
        key = "1" * 32
        run = {"schema": "kryptos.local-run.v1", "id": key, "state": "paused", "kind": "exact", "command": "optimize-plus",
               "request": {"target": "custom", "ciphertext": "ABC", "resume_path": "C:/never-open-me"}, "created_at": "2026-01-01", "updated_at": "2026-01-01",
               "can_resume": True, "progress": {"completed": 2, "total": 10}, "candidates": [], "exact_checkpoint": {"file": "2" * 32 + ".json"}}
        folder = self.root / "runs" / key
        (folder / "checkpoints").mkdir(parents=True)
        (folder / "run.json").write_bytes(packed(run))
        (folder / "checkpoints" / ("2" * 32 + ".json")).write_bytes(b'{"opaque":"checkpoint"}')
        campaigns = self.root / "campaigns"
        campaigns.mkdir()
        return SimpleNamespace(directory=self.root / "runs"), SimpleNamespace(directory=campaigns)

    def test_drafts_persist_and_stale_tabs_cannot_overwrite(self):
        self.change("draft", draft={"recipe": "unfinished JSON {", "note": "explicit K5 hypothesis"})
        self.assertEqual(WorkspaceStore(self.root).view()["draft"]["recipe"], "unfinished JSON {")
        with self.assertRaisesRegex(ValueError, "another tab"):
            self.store.update({"operation": "draft", "revision": 0, "draft": {}}, lambda c: None)

    def test_presets_are_validated_inert_and_named(self):
        calls = []
        self.store.update({"operation": "preset", "revision": 0, "name": "Personal control", "config": {"request": {}}}, calls.append)
        self.assertEqual(calls, [{"request": {}}])
        preset = self.store.view()["presets"][0]
        self.change("remove_preset", id=preset["id"])
        self.assertEqual(self.store.view()["presets"], [])

    def test_history_filters_pagination_and_reversible_archive(self):
        rows = [{"id": f"{i:032x}", "command": "joint", "state": "completed", "created_at": f"2026-{i:03}", "request": {"target": "k4"}} for i in range(63)]
        key = rows[-1]["id"]
        self.change("metadata", run_id=key, tags=["short-period"], title="Seven columns", archived=True)
        result = self.store.history(rows, {"page_size": ["10"], "page": ["2"]})
        self.assertEqual((result["total"], len(result["runs"]), result["pages"]), (62, 10, 7))
        found = self.store.history(rows, {"archived": ["all"], "q": ["seven"], "tag": ["short-period"]})
        self.assertEqual([r["id"] for r in found["runs"]], [key])
        self.change("metadata", run_id=key, tags=["short-period"], title="Seven columns", archived=False)
        self.assertEqual(self.store.history(rows, {})["total"], 63)
        self.assertEqual(len(rows), 63)

    def test_backup_hashes_preview_and_restore_are_inert(self):
        managers = self.fixture()
        self.change("draft", draft={"note": "Current local draft"})
        bundle = self.store.backup(*managers)
        preview = self.store.restore(bundle, preview=True)
        self.assertEqual(preview["counts"]["checkpoint"], 1)
        self.assertFalse(self.store.recovered_runs)
        original = (self.root / "runs" / ("1" * 32) / "run.json").read_bytes()
        result = self.store.restore(bundle)
        self.assertEqual(result["runs_restored"], 1)
        run = next(iter(self.store.recovered_runs.values()))
        self.assertFalse(run["can_resume"])
        self.assertEqual(run["state"], "restored")
        self.assertNotIn("resume_path", run["request"])
        self.assertEqual((self.root / "runs" / ("1" * 32) / "run.json").read_bytes(), original)
        self.assertEqual(self.store.view()["draft"]["note"], "Current local draft")
        self.assertEqual(len(WorkspaceStore(self.root).recovered_runs), 1)
        self.assertEqual(self.store.recoveries[result["recovery_id"]]["editing"]["draft"]["note"], "Current local draft")

    def test_corrupt_bundle_unknown_fields_and_paths_rejected_before_writes(self):
        bundle = self.store.backup(*self.fixture())
        for edit in (lambda b: b["entries"][0].update(data_base64="e30="),
                     lambda b: b["entries"][0].update(path="../escape"),
                     lambda b: b["entries"][1].update(id="../outside"),
                     lambda b: b.update(manifest_sha256="0" * 64)):
            changed = copy.deepcopy(bundle)
            edit(changed)
            with self.assertRaises(ValueError): self.store.restore(changed)
        self.assertFalse((self.root / "workspace/recoveries").exists())

    def test_damaged_editing_file_preserved_with_actionable_diagnostic(self):
        self.store.path.write_text("{broken")
        store = WorkspaceStore(self.root)
        self.assertIn("action", store.diagnostics[0])
        with self.assertRaisesRegex(ValueError, "preserved"):
            store.update({"operation": "draft", "revision": 0, "draft": {}}, lambda c: None)
        self.assertEqual(store.path.read_text(), "{broken")

    def test_malformed_recovery_collections_reported_without_partial_registration(self):
        for i,value in enumerate([[], {"schema":"kryptos.recovery.v1","id":"3"*32,"runs":[],"campaigns":{}},
                                  {"schema":"kryptos.recovery.v1","id":"4"*32,"runs":{"5"*32:{}},"campaigns":[]} ]):
            key=["2"*32,"3"*32,"4"*32][i]
            folder=self.store.directory/"recoveries"/key
            folder.mkdir(parents=True)
            (folder/"snapshot.json").write_bytes(packed(value))
        restarted=WorkspaceStore(self.root)
        self.assertEqual(len(restarted.diagnostics),3)
        self.assertFalse(restarted.recovered_runs)

    def test_backup_rejects_resolved_paths_outside_owned_root(self):
        with tempfile.TemporaryDirectory() as outside:
            target=Path(outside)/"foreign.json"
            target.write_text("do not read")
            with self.assertRaisesRegex(ValueError,"outside"):
                self.store._owned(target)


class WorkspaceHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        bad = root / "runs" / ("a" * 32)
        bad.mkdir(parents=True)
        (bad / "run.json").write_text('{"schema":"unsupported"}')
        bad_campaign=root/"campaigns"/("b"*32)
        bad_campaign.mkdir(parents=True)
        (bad_campaign/"campaign.json").write_text('[]')
        self.server = make_server(root, 0, probe=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.token = self.call("/api/info")[1]["control_token"]

    def tearDown(self):
        self.server.campaigns.close()
        self.server.manager.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def call(self, path, body=None):
        headers = {"Content-Type": "application/json", "X-Kryptos-Token": getattr(self, "token", "")}
        req = urllib.request.Request(self.url + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try: response = self.client.open(req, timeout=5)
        except urllib.error.HTTPError as error: response = error
        with response: return response.status, json.loads(response.read())

    def test_health_drafts_backup_restore_and_no_execution(self):
        health = self.call("/api/workspace/health")[1]
        self.assertTrue(health["diagnostics"])
        self.assertEqual(len(health["diagnostics"]),2)
        self.assertIn("action", health["diagnostics"][0])
        status, _ = self.call("/api/workspace", {"operation": "draft", "revision": 0, "draft": {"source": "K5 hypothetical"}})
        self.assertEqual(status, 200)
        bundle = self.call("/api/workspace/backup", {})[1]["backup"]
        status, result = self.call("/api/workspace/restore", {"backup": bundle})
        self.assertEqual(status, 200)
        self.assertTrue(result["recovery"]["unreadable"])
        self.assertIsNone(self.call("/api/status")[1]["run"])
        self.assertIsNone(self.call("/api/status")[1]["campaign"])
        self.assertEqual(self.call("/api/runs?page_size=101")[0], 400)

    def test_backup_rejected_while_manager_or_campaign_active(self):
        from unittest.mock import patch
        with patch.object(self.server.campaigns, "is_active", return_value=True):
            self.assertEqual(self.call("/api/workspace/backup", {})[0], 400)
        with patch.object(self.server.manager, "_idle", side_effect=ValueError("active")):
            self.assertEqual(self.call("/api/workspace/backup", {})[0], 400)


if __name__ == "__main__":
    unittest.main()
