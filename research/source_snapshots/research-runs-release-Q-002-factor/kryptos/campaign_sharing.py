"""Conservative, same-campaign reuse of one owned certified scan sequence.

This module never translates an offset to an equivalent recipe's basis.  The
original run remains the sole enumerator; other recipes receive replayed text
witnesses and immutable historical snapshots of that run's committed prefix.
"""
import copy
import hashlib
import json


SCHEMA = "kryptos.shared-scan-snapshot.v1"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def validate_option(body, jobs):
    enabled = body.get("share_incomplete_scans", False)
    if type(enabled) is not bool:
        raise ValueError("share_incomplete_scans must be a boolean")
    if enabled:
        for job in jobs:
            config = job["config"]
            if (config["kind"] != "accelerated" or config["command"] != "optimize-plus"
                    or config["ranking_mode"] != "certified" or config["adaptive"]):
                raise ValueError("Shared unfinished scans require certified accelerated optimize-plus jobs with adaptive=false")
    return enabled


def compatible_prefix(job, prior, owner, run, run_sha256, current_source_identity, settings):
    """Return a reason rather than relaxing any prerequisite on a cache miss."""
    identity, old = job.get("family_identity") or {}, prior.get("family_identity") or {}
    snapshot = prior.get("scan_snapshot") or {}
    if (identity.get("eligible") is not True or old.get("eligible") is not True
            or identity.get("schema") != "kryptos.affine-family-identity.v1"
            or old.get("schema") != "kryptos.affine-family-identity.v1"
            or identity.get("scoring_family_sha256") != old.get("scoring_family_sha256")):
        return "different_or_unavailable_scoring_family"
    if (snapshot.get("schema") != SCHEMA or snapshot.get("run_sha256") != run_sha256
            or snapshot.get("recipe_request_sha256") != digest(prior["config"]["request"])):
        return "missing_or_changed_committed_snapshot"
    if (owner.get("shared_scan") or owner.get("run_id") != run.get("id")
            or snapshot.get("owner_job_id") != owner.get("id")
            or snapshot.get("owner_run_id") != run.get("id")):
        return "not_an_original_owned_sequence"
    if (run.get("request") != owner["config"]["request"]
            or snapshot.get("coordinate_request_sha256") != digest(run.get("request"))
            or snapshot.get("source_identity_sha256") != digest(run.get("source_identity"))
            or run.get("source_identity") != current_source_identity):
        return "owner_request_or_source_identity_changed"
    if (run.get("kind") != "accelerated" or run.get("command") != "optimize-plus"
            or run.get("state") not in {"limited", "paused", "stopped", "interrupted"}
            or run.get("ranking_exact_over_committed_pages") is not True):
        return "owner_is_not_an_intact_certified_partial_scan"
    if (run.get("settings") != settings or run.get("initial_settings") != settings
            or run.get("pending_resources") or run.get("resource_events")):
        return "scan_settings_or_resources_changed"
    completed, total = (run.get("progress") or {}).get("completed"), (run.get("progress") or {}).get("total")
    if (type(completed) is not int or type(total) is not int or not 0 < completed < total
            or snapshot.get("completed_offset_decimal") != str(completed)
            or snapshot.get("total_decimal") != str(total)
            or identity.get("distinct_plaintext_count_decimal") != str(total)
            or snapshot.get("scoring_family_sha256") != identity.get("scoring_family_sha256")):
        return "committed_prefix_or_family_size_mismatch"
    return None


def snapshot(job, owner, run, run_sha256, candidates):
    """Freeze a prefix result; completeness is never inferred from exact scores."""
    shared = job.get("shared_scan") or {}
    start = int(shared.get("started_offset_decimal", "0"))
    completed, total = run["progress"]["completed"], run["progress"]["total"]
    if type(completed) is not int or completed < start:
        raise ValueError("The owned scan frontier moved backwards")
    certified = run.get("ranking_exact_over_committed_pages") is True
    complete = run["state"] == "completed" and total is not None and completed == total and certified
    return {
        "schema": SCHEMA, "owner_job_id": owner["id"], "owner_run_id": run["id"],
        "coordinate_request_sha256": digest(run["request"]),
        "recipe_request_sha256": digest(job["config"]["request"]),
        "source_identity_sha256": digest(run["source_identity"]),
        "scoring_family_sha256": (job.get("family_identity") or {}).get("scoring_family_sha256"),
        "started_offset_decimal": str(start), "completed_offset_decimal": str(completed),
        "total_decimal": None if total is None else str(total), "state_at_commit": run["state"],
        "ranking_scope": "whole_family" if complete else "committed_owner_prefix",
        "ranking_exact_over_committed_prefix": certified, "whole_family_complete": complete,
        "top_k_exact": complete, "candidates": copy.deepcopy(candidates), "run_sha256": run_sha256,
        "work": {"new_candidate_evaluations_decimal": str(completed-start),
                 "reused_prefix_candidate_count_decimal": str(start),
                 "validation": copy.deepcopy(job.get("sharing_validation", {}))},
        "interpretation": "Offsets belong only to the original managed run. This job's immutable snapshot does not change when a later job continues that run. Partial ranking is not an exact whole-family top-k.",
        "authenticated_solution": False,
    }
