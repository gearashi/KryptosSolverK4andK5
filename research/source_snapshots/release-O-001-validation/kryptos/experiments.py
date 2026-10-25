"""Single-process, append-only experiment checkpoints with stale-input guards."""
import hashlib
import json
import math
import os
from pathlib import Path


def _read_json(text):
    def reject(value):
        raise ValueError(f"non-finite JSON value: {value}")
    def finite(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            reject(value)
        return parsed
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = value
        return result
    return json.loads(text, parse_constant=reject, parse_float=finite, object_pairs_hook=unique)


def fingerprint(config, input_paths=()):
    inputs = {str(Path(p).resolve()): hashlib.sha256(Path(p).read_bytes()).hexdigest()
              for p in sorted(input_paths, key=str)}
    body = {"config": config, "inputs": inputs}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {**body, "sha256": hashlib.sha256(encoded.encode()).hexdigest()}


class ExperimentJournal:
    """One owner only. Resume exactly matching source/data/config; never mix runs.

    A malformed final line is an error, not silently dropped evidence. A caller
    may preserve that file and start a fresh journal after an interrupted write.
    """
    def __init__(self, path, identity):
        self.path = Path(path)
        self.identity = identity
        self.records = {}
        if self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if not lines or _read_json(lines[0]) != {"identity": identity, "version": 1}:
                raise ValueError("checkpoint belongs to different code, data, or configuration")
            for line in lines[1:]:
                row = _read_json(line)
                if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or row["id"] in self.records or set(row) != {"id", "result"}:
                    raise ValueError("invalid or duplicate checkpoint record")
                self.records[row["id"]] = row["result"]
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps({"identity": identity, "version": 1}, sort_keys=True, allow_nan=False) + "\n")

    def record(self, record_id, result):
        if not isinstance(record_id, str) or not record_id or record_id in self.records:
            raise ValueError("checkpoint id must be new and nonempty")
        encoded = json.dumps({"id": record_id, "result": result}, sort_keys=True, allow_nan=False)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.records[record_id] = result


def control_summary(observed, controls):
    """Descriptive control comparison; no calibrated significance claim."""
    values = list(controls)
    finite = [x for x in values if x is not None]
    return {"observed": observed, "controls": len(values), "controls_with_score": len(finite),
            "controls_without_score": len(values) - len(finite),
            "at_least_observed": None if observed is None else sum(x >= observed for x in finite),
            "minimum": min(finite) if finite else None, "maximum": max(finite) if finite else None,
            "mean": sum(finite) / len(finite) if finite else None,
            "interpretation": "Descriptive pilot comparison, not a solution probability or independent validation."}
