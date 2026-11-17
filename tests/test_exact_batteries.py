import itertools
import json
from pathlib import Path
import random
import shutil
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

from kryptos import exact_batteries as eb
from kryptos.app import make_server
from kryptos.data import K4_CIPHERTEXT

FILLER = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVEN"


def planted_plaintext():
    text = list(FILLER[:97])
    for i, ch in eb.clue_map().items():
        text[i] = ch
    return "".join(text)


def trifid(text, cube, period, start):
    inverse = {v: k for k, v in cube.items()}
    starts = sorted({0} | {i for i in range(len(text)) if i % period == start % period}) + [len(text)]
    out = []
    for b0, b1 in zip(starts, starts[1:]):
        block = text[b0:b1]
        stream = [cube[x][c] for c in range(3) for x in block]
        out += [inverse[tuple(stream[3 * j:3 * j + 3])] for j in range(len(block))]
    return "".join(out)


class ExactBatteryTests(unittest.TestCase):
    def test_k4_has_no_survivor_in_the_fast_batteries(self):
        expected = {"periodic": 312, "recurrence": 552, "grid": 1980, "trifid": 19204, "pairs": 14}
        for name, tested in expected.items():
            result = eb.run_battery(name)
            self.assertEqual((name, result["tested"], result["survivors"]), (name, tested, []))
        periods = eb.run_battery("periodic")["consistent_periods"]
        self.assertFalse(any(key.startswith("fixed alphabets") for key in periods))
        self.assertTrue(all(row["residual"] <= 1 for rows in periods.values() for row in rows))

    def test_planted_unknown_alphabet_periodic_key_is_found(self):
        rng = random.Random(77); mixed = list(range(26)); rng.shuffle(mixed); key = [rng.randrange(26) for _ in range(5)]
        cipher = "".join(eb.KRY[(mixed[eb.STD.index(p)] + key[i % 5]) % 26] for i, p in enumerate(planted_plaintext()))
        models = [s["model"] for s in eb.run_battery("periodic", cipher=cipher)["survivors"]]
        self.assertIn("period 5, unknown plaintext alphabet, other alphabet kryptos", models)

    def test_planted_compound_and_lagged_keys_are_found(self):
        rng = random.Random(2026); a = [rng.randrange(26) for _ in range(7)]; b = [rng.randrange(26) for _ in range(5)]
        plain = planted_plaintext()
        cipher = "".join(eb.KRY[(eb.KRY.index(p) + a[i % 7] + b[i % 5]) % 26] for i, p in enumerate(plain))
        models = [s["model"] for s in eb.run_battery("compound", cipher=cipher)["survivors"]]
        self.assertIn("periods 5 and 7, plain kryptos, cipher kryptos, c=p+k", models)
        out = []
        for i, p in enumerate(plain):
            feedback = 11 * eb.KRY.index(out[i - 7]) if i >= 7 else rng.randrange(26)
            out.append(eb.KRY[(eb.KRY.index(p) + a[i % 2] + feedback) % 26])
        models = [s["model"] for s in eb.run_battery("compound", cipher="".join(out))["survivors"]]
        self.assertIn("period 2 + ciphertext letter 7 back (kryptos), plain kryptos, cipher kryptos, c=p+k", models)

    def test_planted_recurrence_is_found_and_shuffles_are_not(self):
        key = [4, 9]
        while len(key) < 97:
            key.append((3 * key[-1] + 5 * key[-2] + 1) % 26)
        cipher = "".join(eb.STD[(eb.STD.index(p) + k) % 26] for p, k in zip(planted_plaintext(), key))
        models = [s["model"] for s in eb.run_battery("recurrence", cipher=cipher)["survivors"]]
        self.assertIn("recurrence of order 2, plain standard, cipher standard, c=p+k", models)
        rng = random.Random(9)
        for _ in range(3):
            shuffled = list(K4_CIPHERTEXT); rng.shuffle(shuffled); shuffled = "".join(shuffled)
            for name in ("periodic", "recurrence", "trifid"):
                self.assertEqual(eb.run_battery(name, cipher=shuffled)["survivors"], [])

    def test_planted_trifid_survives_only_at_its_true_setting(self):
        rng = random.Random(5); triples = list(itertools.product(range(3), repeat=3)); rng.shuffle(triples)
        cube = dict(zip(eb.SYMBOLS, triples))
        cipher = trifid(planted_plaintext(), cube, 7, 3)
        models = [s["model"] for s in eb.run_battery("trifid", cipher=cipher)["survivors"]]
        self.assertEqual(models, ["Trifid period 7, block start 4, encipher, with question mark", "Trifid period 7, block start 3, encipher, letters only"])
        self.assertTrue(eb.cube_exists([]))
        self.assertFalse(eb.cube_exists([(("A", c), ("B", c)) for c in range(3)]))

    def test_planted_transposition_with_keyed_substitution_is_found(self):
        key = "PALIMPSE"; order = (3, 0, 4, 1, 2); plain = planted_plaintext()
        substituted = [eb.KRY[(eb.KRY.index(p) + eb.KRY.index(key[i % 8])) % 26] for i, p in enumerate(plain)]
        cipher = "".join(substituted[j] for j in eb.columnar(97, 5, order, 1))
        result = eb.run_battery("transposition", cipher=cipher, max_width=5)
        hits = [s for s in result["survivors"] if s["key"] == key]
        self.assertTrue(any("columnar width 5, order 30412, read up; substitute, then transpose; period 8" in s["model"] for s in hits))
        self.assertEqual(eb.run_battery("transposition", max_width=5)["survivors"], [])
        with self.assertRaises(ValueError):
            eb.run_battery("transposition", max_width=12)

    def test_runner_runs_one_battery_at_a_time_and_validates_requests(self):
        runner = eb.ExactRunner()
        try:
            for bad in ({}, {"battery": "nope"}, {"battery": "pairs", "extra": 1}, {"battery": "pairs", "cipher": "ABC"}):
                with self.assertRaises(ValueError):
                    runner.start(bad)
            self.assertEqual(runner.start({"battery": "pairs"})["state"], "running")
            deadline = time.monotonic() + 10
            while runner.view()["state"] == "running" and time.monotonic() < deadline:
                time.sleep(0.02)
            view = runner.view()
            self.assertEqual((view["state"], view["result"]["survivors"]), ("complete", []))
        finally:
            runner.close()
        self.assertEqual([b["id"] for b in eb.catalog()["batteries"]], list(eb.BATTERIES))


class ExactHttpTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path("research") / (".http-test-" + uuid.uuid4().hex)
        self.server = make_server(self.folder, 0, probe=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.exact_runner.close()
        self.server.campaigns.close()
        self.server.manager.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        assert self.folder.resolve().is_relative_to(Path("research").resolve()) and self.folder.name.startswith(".http-test-")
        shutil.rmtree(self.folder)

    def call(self, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.url + path, data=data, headers=headers or {})
        try:
            response = self.client.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, json.loads(raw) if response.headers.get_content_type() == "application/json" else raw

    def test_catalog_static_page_and_guarded_run(self):
        status, data = self.call("/api/exact-tests")
        self.assertEqual((status, data["run"]["state"]), (200, "idle"))
        self.assertEqual([b["id"] for b in data["batteries"]], list(eb.BATTERIES))
        status, script = self.call("/static/exact.js")
        self.assertEqual(status, 200)
        self.assertIn(b"/api/exact-tests/start", script)
        self.assertIn(b'id="exact-view"', self.call("/")[1])
        self.assertEqual(self.call("/api/exact-tests/start", {"battery": "pairs"}, {"Content-Type": "application/json"})[0], 403)
        auth = {"Content-Type": "application/json", "X-Kryptos-Token": self.call("/api/info")[1]["control_token"]}
        self.assertEqual(self.call("/api/exact-tests/start", {"battery": "unknown"}, auth)[0], 400)
        self.assertEqual(self.call("/api/exact-tests/stop", {"run": 1}, auth)[0], 400)
        status, started = self.call("/api/exact-tests/start", {"battery": "trifid"}, auth)
        self.assertEqual((status, started["run"]["state"]), (200, "running"))
        self.assertEqual(self.call("/api/exact-tests/start", {"battery": "pairs"}, auth)[0], 400)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            run = self.call("/api/exact-tests")[1]["run"]
            if run["state"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual((run["state"], run["result"]["tested"], run["result"]["survivors"]), ("complete", 19204, []))
        self.assertIsNone(self.call("/api/status")[1]["run"])


if __name__ == "__main__":
    unittest.main()
