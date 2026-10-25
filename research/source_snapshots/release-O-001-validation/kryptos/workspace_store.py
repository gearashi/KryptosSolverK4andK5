"""Bounded local editing state and inert, verified recovery snapshots.

Bundle hashes detect damage, not authenticity. Restored records never become jobs.
All filesystem destinations are generated here; imported paths are never opened.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
import uuid

MAX_BUNDLE = 32 * 1024 * 1024
MAX_ENTRY = 16 * 1024 * 1024
ID = re.compile(r"[a-f0-9]{32}")
UNSAFE = {"checkpoint_path", "resume_path", "checkpoint_written", "control_token"}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def packed(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def inert(value):
    if isinstance(value, dict):
        return {k: inert(v) for k, v in value.items() if k not in UNSAFE}
    if isinstance(value, list):
        return [inert(v) for v in value]
    return value


def bounded(value, limit):
    if len(packed(value)) > limit:
        raise ValueError("Workspace value exceeds its declared size limit")
    return copy.deepcopy(value)


def _text(value, maximum, label, empty=True):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{label} must be text of at most {maximum} characters")
    return value.strip()


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        tmp.write_bytes(packed(value))
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


class WorkspaceStore:
    def __init__(self, state_dir):
        self.root = Path(state_dir).resolve()
        self.directory = self.root / "workspace"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "editing.json"
        self.lock = threading.RLock()
        self.diagnostics = []
        self.value = {"schema": "kryptos.workspace.v1", "revision": 0, "draft": None,
                      "presets": [], "run_metadata": {}}
        if self.path.exists():
            try:
                self._owned(self.path)
                if self.path.stat().st_size > 4 * 1024 * 1024:
                    raise ValueError("Editing state exceeds 4 MiB")
                value = json.loads(self.path.read_text(encoding="utf-8"))
                self._validate_state(value)
                self.value = value
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                self.diagnostics.append({"record": "workspace/editing.json", "kind": "editing",
                                         "reason": str(error), "action": "Back up the preserved file before repairing it. Editing saves are blocked until recovery."})
        self.recovered_runs = {}
        self.recovered_campaigns = {}
        self.recoveries = {}
        for path in sorted((self.directory / "recoveries").glob("*/snapshot.json")):
            try:
                self._owned(path)
                if path.stat().st_size > MAX_BUNDLE:
                    raise ValueError("Recovery snapshot is too large")
                saved = json.loads(path.read_text())
                if not isinstance(saved,dict) or saved.get("schema") != "kryptos.recovery.v1" or saved.get("id") != path.parent.name or not ID.fullmatch(path.parent.name):
                    raise ValueError("Unsupported recovery snapshot")
                self._load_recovery(saved)
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                self.diagnostics.append({"record": "workspace/recoveries/" + path.parent.name, "kind": "recovery",
                                         "reason": str(error), "action": "Keep this snapshot; restore a verified backup into a fresh recovery."})

    def _owned(self,path):
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("Saved file resolves outside the owned workspace; it was not opened")
        return path

    @staticmethod
    def _validate_state(value):
        if not isinstance(value, dict) or value.get("schema") != "kryptos.workspace.v1":
            raise ValueError("Unsupported workspace schema")
        if type(value.get("revision")) is not int or value["revision"] < 0:
            raise ValueError("Invalid workspace revision")
        if not isinstance(value.get("presets"), list) or len(value["presets"]) > 50 or not isinstance(value.get("run_metadata"), dict):
            raise ValueError("Invalid workspace collections")
        if value.get("draft") is not None and not isinstance(value["draft"], dict):
            raise ValueError("Invalid draft")
        for preset in value["presets"]:
            if not isinstance(preset,dict) or not isinstance(preset.get("id"),str) or not ID.fullmatch(preset["id"]) or not isinstance(preset.get("config"),dict):
                raise ValueError("Malformed personal preset")
            _text(preset.get("name"),100,"Preset name",False)
        for key, meta in value["run_metadata"].items():
            if not ID.fullmatch(key) or not isinstance(meta,dict) or type(meta.get("archived")) is not bool or not isinstance(meta.get("tags"),list) or len(meta["tags"])>12:
                raise ValueError("Malformed run labels")
            _text(meta.get("title"),100,"Run title")
            for tag in meta["tags"]:_text(tag,32,"Tag",False)
        bounded(value, 4 * 1024 * 1024)

    def view(self):
        with self.lock:
            return copy.deepcopy(self.value)

    def update(self, body, validate_config):
        if not isinstance(body, dict) or body.get("operation") not in {"draft", "preset", "remove_preset", "metadata"}:
            raise ValueError("Unknown workspace operation")
        with self.lock:
            if any(d["kind"] == "editing" for d in self.diagnostics):
                raise ValueError("Existing editing state is damaged; it was preserved. Back up and repair it before saving new editing state.")
            if type(body.get("revision")) is not int or body["revision"] != self.value["revision"]:
                raise ValueError("Workspace changed in another tab. Reload saved editing state before retrying; your current form remains unchanged.")
            value = copy.deepcopy(self.value)
            op = body["operation"]
            allowed = {"draft": {"draft"}, "preset": {"id", "name", "config"},
                       "remove_preset": {"id"}, "metadata": {"run_id", "title", "tags", "archived"}}[op] | {"operation", "revision"}
            if set(body) - allowed:
                raise ValueError("Unknown workspace fields")
            if op == "draft":
                draft = body.get("draft")
                if draft is not None and not isinstance(draft, dict):
                    raise ValueError("Draft must be an object or null")
                value["draft"] = bounded(draft, 256 * 1024)
            elif op == "preset":
                name = _text(body.get("name"), 100, "Preset name", False)
                config = bounded(body.get("config"), 128 * 1024)
                validate_config(config)
                key = body.get("id") or uuid.uuid4().hex
                if not isinstance(key, str) or not ID.fullmatch(key):
                    raise ValueError("Invalid preset id")
                old = next((p for p in value["presets"] if p["id"] == key), None)
                if body.get("id") and old is None:
                    raise ValueError("Preset does not exist")
                value["presets"] = [p for p in value["presets"] if p["id"] != key]
                value["presets"].append({"id": key, "name": name, "config": config, "updated_at": stamp()})
                if len(value["presets"]) > 50:
                    raise ValueError("At most 50 personal presets are supported")
            elif op == "remove_preset":
                key = body.get("id")
                if not any(p["id"] == key for p in value["presets"]):
                    raise ValueError("Preset does not exist")
                value["presets"] = [p for p in value["presets"] if p["id"] != key]
            else:
                key = body.get("run_id")
                if not isinstance(key, str) or not ID.fullmatch(key):
                    raise ValueError("Invalid run id")
                tags = body.get("tags", [])
                if not isinstance(tags, list) or len(tags) > 12:
                    raise ValueError("Use at most 12 tags")
                tags = sorted(set(_text(t, 32, "Tag", False) for t in tags))
                archived = body.get("archived", False)
                if type(archived) is not bool:
                    raise ValueError("Archived must be a boolean")
                value["run_metadata"][key] = {"title": _text(body.get("title", ""), 100, "Title"),
                                              "tags": tags, "archived": archived}
            value["revision"] += 1
            self._validate_state(value)
            self._owned(self.path)
            _write(self.path, value)
            self.value = value
            return self.view()

    def history(self, summaries, query):
        def parameter(name, default):
            items = query.get(name, [default])
            if len(items) != 1:
                raise ValueError("History query fields must be unique")
            return items[0]
        page, size = int(parameter("page", "1")), int(parameter("page_size", "25"))
        if not 1 <= page <= 100000 or not 1 <= size <= 100:
            raise ValueError("History page must be positive and page_size in 1..100")
        text = _text(parameter("q", ""), 200, "Search").lower()
        tag, status, archived = parameter("tag", ""), parameter("state", ""), parameter("archived", "active")
        if archived not in {"active", "archived", "all"}:
            raise ValueError("Archived filter must be active, archived or all")
        rows = []
        with self.lock:
            all_rows = list(summaries) + [self.summary(r) for r in self.recovered_runs.values()]
            for run in all_rows:
                meta = self.value["run_metadata"].get(run["id"], {})
                if archived != "all" and bool(meta.get("archived")) != (archived == "archived"):
                    continue
                if status and run["state"] != status or tag and tag not in meta.get("tags", []):
                    continue
                searchable = " ".join(str(x) for x in [run["id"], run.get("command"), run.get("note"), run.get("request", {}).get("target"), meta.get("title"), " ".join(meta.get("tags", []))]).lower()
                if text and text not in searchable:
                    continue
                rows.append({**run, "metadata": copy.deepcopy(meta)})
        rows.sort(key=lambda r: (r.get("created_at", ""), r["id"]), reverse=True)
        return {"runs": rows[(page - 1) * size:page * size], "total": len(rows), "page": page,
                "page_size": size, "pages": max(1, (len(rows) + size - 1) // size)}

    @staticmethod
    def summary(record):
        return copy.deepcopy({k: v for k, v in record.items() if k not in {"candidates", "result", "source_identity"}})

    def recovered(self, key):
        with self.lock:
            if key not in self.recovered_runs:
                raise KeyError("Recovered run not found")
            return copy.deepcopy(self.recovered_runs[key])

    def _load_recovery(self, saved):
        if not isinstance(saved,dict) or not isinstance(saved.get("runs"),dict) or not isinstance(saved.get("campaigns"),dict):
            raise ValueError("Malformed recovery record mappings")
        runs, campaigns = {}, {}
        for key, record in saved.get("runs", {}).items():
            if not ID.fullmatch(key) or not isinstance(record, dict):
                raise ValueError("Invalid recovered run")
            record = inert(copy.deepcopy(record))
            record.update(id=key, state="restored", can_resume=False, can_pause=False,
                          restored_evidence_only=True, recovery_id=saved["id"])
            runs[key] = record
        for key, record in saved.get("campaigns", {}).items():
            if not ID.fullmatch(key) or not isinstance(record,dict):
                raise ValueError("Invalid recovered campaign")
            record = inert(copy.deepcopy(record))
            record.update(id=key, state="restored", can_resume=False, restored_evidence_only=True)
            campaigns[key] = record
        self.recovered_runs.update(runs)
        self.recovered_campaigns.update(campaigns)
        self.recoveries[saved["id"]] = copy.deepcopy({k:v for k,v in saved.items() if k not in {"runs","campaigns"}})

    @staticmethod
    def _entry(kind, key, raw):
        if len(raw) > MAX_ENTRY:
            raise ValueError("A workspace file exceeds the 16 MiB per-file backup bound")
        return {"kind": kind, "id": key, "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw), "data_base64": base64.b64encode(raw).decode("ascii")}

    def backup(self, manager, campaigns):
        """Caller holds campaign then manager lock and has checked both idle."""
        with self.lock:
            entries, total = [], 0
            def read(path):
                self._owned(path)
                if path.stat().st_size>MAX_ENTRY:raise ValueError("A workspace file exceeds the 16 MiB backup bound")
                return path.read_bytes()
            def add(kind,key,raw):
                nonlocal total
                total += len(raw)*4//3+600
                if total>MAX_BUNDLE-2048 or len(entries)>=2000:
                    raise ValueError("Workspace exceeds the bounded 32 MiB/2000-entry backup capacity; use a smaller separate state directory")
                entries.append(self._entry(kind,key,raw))
            add("editing", "editing", read(self.path) if self.path.exists() else packed(self.value))
            for kind, directory, filename in [("run", manager.directory, "run.json"), ("campaign", campaigns.directory, "campaign.json")]:
                for path in sorted(directory.glob("*/" + filename)):
                    if not ID.fullmatch(path.parent.name) or path.is_symlink() or path.parent.is_symlink():
                        continue
                    raw = read(path)
                    add(kind, path.parent.name, raw)
                    if kind == "run":
                        # Fixed owned directory/name patterns only; never follow saved checkpoint strings.
                        for checkpoint in sorted((path.parent / "checkpoints").glob("*.json")):
                            if checkpoint.is_symlink() or checkpoint.parent.is_symlink() or not ID.fullmatch(checkpoint.stem):
                                continue
                            add("checkpoint", checkpoint.stem, read(checkpoint))
            for record in self.recovered_runs.values():
                add("run", record["id"], packed(record))
            for record in self.recovered_campaigns.values():
                add("campaign", record["id"], packed(record))
            for path in sorted((self.directory / "recoveries").glob("*/backup.json")):
                if not path.is_symlink() and not path.parent.is_symlink():
                    add("recovery", path.parent.name, read(path))
            result = {"schema": "kryptos.workspace-backup.v1", "created_at": stamp(), "entries": entries,
                      "manifest_sha256": hashlib.sha256(packed([{k: v for k, v in e.items() if k != "data_base64"} for e in entries])).hexdigest(),
                      "interpretation": "Hashes verify integrity, not provenance. Restoration is read-only evidence; checkpoints are preserved but never resumed."}
            return bounded(result, MAX_BUNDLE - 1024)

    def inspect_backup(self, bundle):
        bounded(bundle, MAX_BUNDLE - 1024)
        if not isinstance(bundle, dict) or bundle.get("schema") != "kryptos.workspace-backup.v1" or set(bundle) != {"schema", "created_at", "entries", "manifest_sha256", "interpretation"}:
            raise ValueError("Unsupported backup schema or fields")
        entries = bundle.get("entries")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 2000:
            raise ValueError("Backup must contain 1..2000 entries")
        seen, decoded = set(), []
        for e in entries:
            if not isinstance(e, dict) or set(e) != {"kind", "id", "sha256", "bytes", "data_base64"} or e["kind"] not in {"editing", "run", "campaign", "checkpoint", "recovery"}:
                raise ValueError("Unsupported backup entry")
            if not isinstance(e["id"], str) or not (e["kind"] == "editing" and e["id"] == "editing" or ID.fullmatch(e["id"])):
                raise ValueError("Invalid backup record identifier")
            identity = (e["kind"], e["id"])
            if identity in seen:
                raise ValueError("Duplicate backup entry")
            seen.add(identity)
            try:
                raw = base64.b64decode(e["data_base64"], validate=True)
            except (ValueError, TypeError) as error:
                raise ValueError("Invalid backup encoding") from error
            if type(e["bytes"]) is not int or e["bytes"] != len(raw) or len(raw) > MAX_ENTRY or hashlib.sha256(raw).hexdigest() != e["sha256"]:
                raise ValueError("Backup entry hash or size mismatch")
            decoded.append((e["kind"], e["id"], raw))
        digest = hashlib.sha256(packed([{k: v for k, v in e.items() if k != "data_base64"} for e in entries])).hexdigest()
        if digest != bundle["manifest_sha256"]:
            raise ValueError("Backup manifest hash mismatch")
        return decoded

    def restore(self, bundle, *, preview=False):
        decoded = self.inspect_backup(bundle)
        counts = {kind: sum(k == kind for k, _, _ in decoded) for kind in {k for k, _, _ in decoded}}
        report = {"verified": True, "counts": counts, "manifest_sha256": bundle["manifest_sha256"],
                  "interpretation": "Restore creates a separate read-only recovery. Existing editing state and runs remain unchanged. No job or frontier is activated."}
        if preview:
            return report
        key = uuid.uuid4().hex
        saved = {"schema": "kryptos.recovery.v1", "id": key, "created_at": stamp(), "runs": {}, "campaigns": {}, "unreadable": [], "source_manifest_sha256": bundle["manifest_sha256"]}
        run_map = {}
        for kind, source_id, raw in decoded:
            if kind=="editing":
                try:
                    editing=json.loads(raw)
                    self._validate_state(editing)
                    saved["editing"]=editing
                except (ValueError,TypeError,KeyError):
                    saved["unreadable"].append({"kind":kind,"source_id":source_id,"reason":"Editing bytes preserved but unsupported"})
                continue
            if kind not in {"run", "campaign"}:
                continue
            try:
                record = json.loads(raw)
                expected = "kryptos.local-run.v1" if kind == "run" else "kryptos.campaign.v1"
                if not isinstance(record, dict) or record.get("schema") != expected or record.get("id") != source_id:
                    raise ValueError("Unsupported saved record")
                if kind == "run" and not isinstance(record.get("request"), dict):
                    raise ValueError("Missing saved request")
                if not isinstance(record.get("created_at"),str) or not isinstance(record.get("updated_at"),str):
                    raise ValueError("Missing saved record dates")
                if kind=="campaign" and (not isinstance(record.get("jobs"),list) or any(not isinstance(j,dict) for j in record["jobs"])):
                    raise ValueError("Missing campaign jobs")
                new_id = uuid.uuid4().hex
                record = inert(record)
                record.update(restored_from=source_id, restored_at=stamp())
                saved["runs" if kind == "run" else "campaigns"][new_id] = record
                if kind=="run":run_map[source_id]=new_id
            except (ValueError, TypeError):
                saved["unreadable"].append({"kind": kind, "source_id": source_id, "reason": "Preserved as opaque backup data; unsupported or damaged record"})
        for record in saved["campaigns"].values():
            for job in record["jobs"]:
                job["run_id"]=run_map.get(job.get("run_id"))
                job["alias_run_id"]=run_map.get(job.get("alias_run_id"))
                job["alias_campaign_id"]=None
        with self.lock:
            folder = self.directory / "recoveries" / key
            self._owned(folder)
            folder.mkdir(parents=True, exist_ok=False)
            # Commit marker last: partial writes never appear as restored history.
            _write(folder / "backup.json", bundle)
            _write(folder / "snapshot.json", saved)
            self._load_recovery(saved)
        return {**report, "recovery_id": key, "runs_restored": len(saved["runs"]),
                "campaigns_restored": len(saved["campaigns"]), "unreadable": saved["unreadable"]}
