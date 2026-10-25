import json
from pathlib import Path
import shutil
import threading
import unittest
import urllib.error
import urllib.request
import uuid

from kryptos.app import make_server, strict_json, browser_safe_integers


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.folder=Path("research")/(".http-test-"+uuid.uuid4().hex)
        self.server=make_server(self.folder,0,probe=False)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.url=f"http://127.0.0.1:{self.server.server_port}"
        self.client=urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.campaigns.close()
        self.server.manager.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        assert self.folder.resolve().is_relative_to(Path("research").resolve()) and self.folder.name.startswith(".http-test-")
        shutil.rmtree(self.folder)

    def call(self,path,data=None,headers=None):
        request=urllib.request.Request(self.url+path,data=data,headers=headers or {})
        try:
            response=self.client.open(request,timeout=5)
        except urllib.error.HTTPError as error:
            response=error
        with response:
            raw=response.read()
            return response.status,json.loads(raw) if response.headers.get_content_type()=="application/json" else raw,response.headers

    def test_idle_page_presets_and_local_security(self):
        status,info,headers=self.call("/api/info")
        self.assertEqual(status,200)
        self.assertEqual(len(info["k4"]["ciphertext"]),97)
        self.assertGreaterEqual(len(info["presets"]),3)
        self.assertIsNone(self.call("/api/status")[1]["run"])
        self.assertIn("frame-ancestors 'none'",headers["Content-Security-Policy"])
        self.assertEqual(self.call("/",headers={"Host":"evil.example"})[0],403)
        self.assertEqual(self.call("/api/start",data=b"{}",headers={"Content-Type":"application/json"})[0],403)
        auth={"Content-Type":"application/json","X-Kryptos-Token":info["control_token"]}
        self.assertEqual(self.call("/api/start",data=b"{}",headers={**auth,"Origin":"https://evil.example"})[0],403)
        self.assertEqual(self.call("/api/start",data=b'{"kind":"exact","kind":"exact"}',headers=auth)[0],400)
        for value in (b'{"number":1e309}',b'{"number":NaN}',b'{"number":-Infinity}'):
            self.assertEqual(self.call("/api/start",data=value,headers=auth)[0],400)
        self.assertIsNone(self.call("/api/status")[1]["run"])
        self.assertEqual(self.call("/static/mark.svg")[0],200)
        self.assertEqual(self.call("/../README.md")[0],404)

    def test_exact_large_counts_survive_browser_json(self):
        original={"count":2**70+1,"negative":-(2**80+1),"boolean":True,"small":97}
        encoded=json.loads(json.dumps(browser_safe_integers(original)))
        self.assertEqual(int(encoded["count"]["value"],16),original["count"])
        self.assertEqual(int(encoded["negative"]["value"],16),original["negative"])
        self.assertIs(encoded["boolean"],True)
        self.assertEqual(encoded["small"],97)

    def test_control_and_export_flow(self):
        info=self.call("/api/info")[1]
        auth={"Content-Type":"application/json","X-Kryptos-Token":info["control_token"]}
        data={k:v for k,v in next(p for p in info["presets"] if p["id"]=="joint-ragged").items() if k in {"kind","command","request"}}
        status,value,_=self.call("/api/start",json.dumps(data).encode(),auth)
        self.assertEqual(status,200,value)
        key=value["run"]["id"]
        self.server.manager.thread.join(timeout=10)
        result=self.call("/api/runs/"+key)[1]["run"]
        self.assertEqual(result["state"],"completed",result.get("error"))
        exported=self.call("/api/export?run_id="+key)
        self.assertEqual(exported[1]["id"],key)
        self.assertIn("attachment",exported[2]["Content-Disposition"])
        self.assertTrue(exported[1]["candidates"][0]["evidence"]["literal_reencryption_matches"])

    def test_import_independent_replay_and_no_job_execution(self):
        from tests.test_import_inspector import artifact
        info=self.call("/api/info")[1]
        auth={"Content-Type":"application/json","X-Kryptos-Token":info["control_token"]}
        good=artifact()
        status,value,_=self.call("/api/import",json.dumps({"artifact":good}).encode(),auth)
        self.assertEqual(status,200,value)
        self.assertTrue(value["inspection"]["valid"])
        good["candidate"]["plaintext"]="ABCDEX"
        status,value,_=self.call("/api/import",json.dumps({"artifact":good}).encode(),auth)
        self.assertEqual(status,200,value)
        self.assertFalse(value["inspection"]["valid"])
        self.assertEqual(self.call("/api/import",b'{"artifact":{},"candidate_index":true}',auth)[0],400)
        self.assertIsNone(self.call("/api/status")[1]["run"])

    def test_campaign_endpoints_and_single_run_ownership(self):
        from unittest.mock import patch
        info=self.call("/api/info")[1]
        self.assertEqual({p["id"] for p in info["validation_presets"]},
                         {"validate-holdout","validate-controls","validate-k4-shaped","validate-ablations","validate-campaign-null"})
        auth={"Content-Type":"application/json","X-Kryptos-Token":info["control_token"]}
        base={k:v for k,v in next(p for p in info["presets"] if p["id"]=="demo-scan").items() if k in {"kind","command","request"}}
        plan={"base":base,"axes":[{"path":"request.stages.0.period","values":[1,2,3]}]}
        status,value,_=self.call("/api/campaigns/preview",json.dumps(plan).encode(),auth)
        self.assertEqual(status,200,value)
        self.assertEqual(value["preview"]["job_count"],3)
        generated={"base":base,"generator":{"patterns":["S","ST","TS"],"periods":[1],"routes":["identity","reverse"]}}
        status,value,_=self.call("/api/campaigns/preview",json.dumps(generated).encode(),auth)
        self.assertEqual(status,200,value)
        self.assertEqual(value["preview"]["job_count"],3)
        self.assertIsNone(self.call("/api/status")[1]["run"])
        for field in ("checkpoint_path","resume_path"):
            malicious={"kind":"exact","command":"optimize-plus","request":{**base["request"],field:"runtime/foreign.json"}}
            self.assertEqual(self.call("/api/start",json.dumps(malicious).encode(),auth)[0],400)
        self.assertEqual(self.call("/api/campaigns")[1],{"campaigns":[]})
        with patch.object(self.server.campaigns,"_begin"):
            status,value,_=self.call("/api/campaigns/start",json.dumps(plan).encode(),auth)
        self.assertEqual(status,200,value)
        key=value["campaign"]["id"]
        self.assertEqual(self.call("/api/campaigns/"+key)[1]["campaign"]["id"],key)
        self.assertEqual(self.call("/api/status")[1]["campaign"]["id"],key)
        with patch.object(self.server.campaigns,"is_active",return_value=True):
            self.assertEqual(self.call("/api/start",json.dumps(base).encode(),auth)[0],400)
            self.assertEqual(self.call("/api/pause",json.dumps({"run_id":"0"*32}).encode(),auth)[0],400)
        self.assertEqual(self.call("/api/resources",b'{"run_id":"missing","workers":2}',auth)[0],404)
        self.assertEqual(self.call("/api/campaigns/pause",b'{}',auth)[0],400)
        self.assertIsNone(self.call("/api/status")[1]["run"])


if __name__=="__main__":
    unittest.main()
