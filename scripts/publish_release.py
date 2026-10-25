"""Explicit publication gate. Only an authenticated gearashi account can publish.

Run after the exact tagged commit passes verify-package.yml on Windows/Linux.
The script downloads that run's validated package, publishes it, then checks the
public tag, release author and downloadable asset digests. It never commits code,
creates credentials, edits repository secrets, or silently creates a tag.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

REPOSITORY = "gearashi/KryptosSolverK4AndK5"
GH_EXECUTABLE="gh"


def gh(*args):
    return subprocess.check_output([GH_EXECUTABLE, *args], text=True, encoding="utf-8",timeout=180).strip()


def check_identity(user, repository):
    if user.get("login") != "gearashi" or repository.get("full_name", "").lower() != REPOSITORY.lower() or repository.get("private") is not False:
        raise ValueError("Publication requires authenticated gearashi and the public gearashi/KryptosSolverK4AndK5 repository")


def check_tag(tag, commit, resolved):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", tag) or not re.fullmatch(r"[a-f0-9]{40}", commit) or commit != resolved:
        raise ValueError("Release tag must already resolve remotely to the exact validated commit")


def resolve_remote_tag(tag):
    obj=json.loads(gh("api",f"repos/{REPOSITORY}/git/ref/tags/{tag}"))["object"]
    for _ in range(8):
        if obj.get("type")=="commit":return obj["sha"]
        if obj.get("type")!="tag" or not re.fullmatch(r"[a-f0-9]{40}",obj.get("sha","")):
            break
        obj=json.loads(gh("api",f"repos/{REPOSITORY}/git/tags/{obj['sha']}"))["object"]
    raise ValueError("Remote tag did not resolve to a commit")


def check_release(release, tag, expected_assets):
    if release.get("tag_name") != tag or release.get("draft") or not release.get("published_at") or release.get("author", {}).get("login") != "gearashi":
        raise ValueError("Published release identity/tag/state did not match the required gearashi release")
    assets = {a["name"]: a for a in release.get("assets", [])}
    if not set(expected_assets) <= set(assets):
        raise ValueError("Published release is missing validated assets")
    for name in expected_assets:
        if assets[name].get("state") != "uploaded" or not assets[name].get("browser_download_url", "").lower().startswith("https://github.com/" + REPOSITORY.lower() + "/releases/download/"):
            raise ValueError("Asset public link is invalid")
    return assets


def publish(args):
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?",args.tag):raise ValueError("Use a version tag")
    user = json.loads(gh("api", "user"))
    repo = json.loads(gh("api", "repos/" + REPOSITORY))
    check_identity(user, repo)
    run = json.loads(gh("api", f"repos/{REPOSITORY}/actions/runs/{args.run_id}"))
    if run.get("conclusion") != "success" or run.get("status") != "completed" or run.get("path") != ".github/workflows/verify-package.yml":
        raise ValueError("Select a successful completed package-verification workflow run")
    commit = run["head_sha"]
    # commits/{ref} resolves annotated and lightweight tags to their commit.
    resolved = resolve_remote_tag(args.tag)
    check_tag(args.tag, commit, resolved)
    with tempfile.TemporaryDirectory(prefix="kryptos-release-") as folder:
        directory = Path(folder)
        gh("run", "download", str(args.run_id), "--repo", REPOSITORY, "--name", "validated-package-Windows-3.12", "--dir", str(directory))
        validation = json.loads((directory / "validation.json").read_text())
        archive = directory / "KryptosSolverK4AndK5.zip"
        if validation.get("passed") is not True or validation.get("commit") != commit or hashlib.sha256(archive.read_bytes()).hexdigest() != validation.get("package_sha256"):
            raise ValueError("Downloaded CI package is not the validated tagged source")
        assets = [archive, directory / "SHA256SUMS", directory / "validation.json"]
        expected = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in assets}
        if not args.publish:
            return {"ready": True, "published": False, "identity": user["login"], "tag": args.tag, "commit": commit, "assets": expected,
                    "next": "Repeat with --publish after reviewing this exact tagged package."}
        notes = directory / "release-notes.md"
        notes.write_text(f"Kryptos Research Workbench {args.tag}\n\nValidated source: `{commit}`. Windows and Linux CPU/package/browser gates passed in [workflow run](https://github.com/{REPOSITORY}/actions/runs/{args.run_id}).\n\nCPU CI is not CUDA hardware evidence. CUDA requires compatible NVIDIA hardware and separately recorded hardware-qualified checks. This project has not authenticated a K4 or K5 solution.\n", encoding="utf-8")
        gh("release", "create", args.tag, *map(str, assets), "--repo", REPOSITORY, "--verify-tag", "--title", "Kryptos Research Workbench " + args.tag, "--notes-file", str(notes))
        release = json.loads(gh("api", f"repos/{REPOSITORY}/releases/tags/{args.tag}"))
        published = check_release(release, args.tag, expected)
        with urllib.request.urlopen(release["html_url"], timeout=30) as response:
            if response.status != 200: raise ValueError("Public release page is not reachable")
        for name, digest in expected.items():
            with urllib.request.urlopen(published[name]["browser_download_url"], timeout=60) as response:
                actual = hashlib.sha256(response.read()).hexdigest()
            if actual != digest: raise ValueError("Public release asset digest mismatch: " + name)
        check_tag(args.tag, commit, resolve_remote_tag(args.tag))
        return {"published": True, "identity": user["login"], "tag": args.tag, "commit": commit, "url": release["html_url"], "verified_assets": expected}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--publish", action="store_true", help="Explicitly create the public release after all gates pass")
    parser.add_argument("--gh",default="gh",help="Existing GitHub CLI or compatible local adapter; no credentials are installed")
    args=parser.parse_args()
    GH_EXECUTABLE=args.gh
    print(json.dumps(publish(args), indent=2))
