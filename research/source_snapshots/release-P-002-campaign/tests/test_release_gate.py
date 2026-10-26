import unittest
from scripts.publish_release import check_identity, check_tag, check_release, resolve_remote_tag, REPOSITORY


class ReleaseGateTests(unittest.TestCase):
    def test_identity_requires_gearashi_public_repository(self):
        good = {"full_name": REPOSITORY, "private": False}
        check_identity({"login": "gearashi"}, good)
        for user, repo in [({"login": "github-actions[bot]"}, good), ({"login": "gearashi"}, {**good, "private": True}), ({"login": "gearashi"}, {**good, "full_name": "other/repo"})]:
            with self.assertRaises(ValueError): check_identity(user, repo)

    def test_exact_existing_tag_required(self):
        check_tag("v0.4.0", "a" * 40, "a" * 40)
        for tag, sha in [("main", "a" * 40), ("v0.4.0", "b" * 40), ("v0.4.0/../../x", "a" * 40)]:
            with self.assertRaises(ValueError): check_tag(tag, "a" * 40, sha)

    def test_published_author_and_public_asset_links_verified(self):
        asset = {"name": "source.zip", "state": "uploaded", "browser_download_url": "https://github.com/" + REPOSITORY + "/releases/download/v0.4.0/source.zip"}
        release = {"tag_name": "v0.4.0", "draft": False, "published_at": "2026-10-25", "author": {"login": "gearashi"}, "assets": [asset]}
        check_release(release, "v0.4.0", {"source.zip"})
        for change in [{"draft": True}, {"author": {"login": "github-actions[bot]"}}, {"assets": []}, {"published_at": None}]:
            with self.assertRaises(ValueError): check_release({**release, **change}, "v0.4.0", {"source.zip"})
        asset["browser_download_url"]=asset["browser_download_url"].replace("K4AndK5","K4andK5")
        check_release(release,"v0.4.0",{"source.zip"})

    def test_remote_annotated_tag_is_resolved_from_tag_ref_not_branch(self):
        from unittest.mock import patch
        with patch("scripts.publish_release.gh",side_effect=['{"object":{"type":"tag","sha":"'+'b'*40+'"}}','{"object":{"type":"commit","sha":"'+'a'*40+'"}}']) as gh:
            self.assertEqual(resolve_remote_tag("v0.4.0"),'a'*40)
            self.assertIn("/git/ref/tags/v0.4.0",gh.call_args_list[0].args[1])

    def test_package_process_timeout_always_closes_owned_tree(self):
        from unittest.mock import patch,MagicMock
        from scripts.verify_package import run
        import tempfile,subprocess
        from pathlib import Path
        process=MagicMock()
        process.wait.side_effect=subprocess.TimeoutExpired('test',.01)
        with tempfile.TemporaryDirectory() as folder,patch('scripts.verify_package.launch_owned',return_value=process):
            with self.assertRaisesRegex(RuntimeError,'timed out'):
                run(['irrelevant'],Path(folder),Path(folder)/'test.txt',{},timeout=.01)
            process.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
