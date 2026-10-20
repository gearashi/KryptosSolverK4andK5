"""Local browser dashboard. Opening the page never starts a search."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import math
import mimetypes
import os
from pathlib import Path
import re
import secrets
import threading
from urllib.parse import parse_qs,urlsplit
import webbrowser

from .advanced_cli import json_safe_integers
from .app_jobs import RunManager,ROOT,MODELS
from .data import K4_CIPHERTEXT,K4_CRIBS
from .campaigns import CampaignManager,preview_campaign
from .import_inspector import inspect_import

VERSION="0.2.0"


def validation_presets():
    return [{"id":command,"label":label,"kind":"exact","command":command,
             "description":description,"request":json.loads((ROOT/"examples"/(command+".json")).read_text())}
            for command,label,description in (
                ("validate-holdout","Reduced-clue recovery", "Rerun model selection with withheld clue values removed, then assess recovery. All supplied clue positions are excluded from language scoring; public K4 clues remain retrospective evidence."),
                ("validate-controls","Competing models · positive/null controls", "Two newly authored messages and paired shuffled controls run through the complete declared model bank. This fast fixture uses an artificial contiguous clue mask, not the K4 clue geometry."))]


def presets():
    model=MODELS[0]["path"]
    records=[{"id":"k4-joint","label":"K4 · joint column/key check","description":"Test all width-7 column orders with a period-2 Vigenère key. This small family can be excluded without finding K4's actual method.",
        "kind":"exact","command":"joint","request":{"target":"k4","width":7,"period":2,"order":"ST","alphabet":"kryptos","max_states":20000,"time_limit_seconds":3}},
        {"id":"k4-scan","label":"K4 · period-27 family scan","description":"Enumerate distinct crib-compatible repeating-key plaintexts in bounded pages. Language scores are hypotheses, not authenticated answers.",
         "kind":"accelerated","command":"optimize-plus","request":{"target":"k4","alphabet":"kryptos","stages":[{"operation":"substitution","period":27}],"model_path":model}},
        {"id":"demo-scan","label":"Control · recover a known message","description":"A small synthetic family for checking CPU/GPU execution and candidate explanations. This is not K4.",
         "kind":"accelerated","command":"optimize-plus","request":json.loads((ROOT/"examples/optimize-lazy.json").read_text())},
        {"id":"demo-optimize","label":"Control · exact optimization with optional scan seed","description":"Check exact pruning and verified CPU/GPU incumbent seeds on a small synthetic family.",
         "kind":"exact","command":"optimize-plus","request":json.loads((ROOT/"examples/optimize-lazy.json").read_text())}]
    for name,command,label in (("joint-ragged","joint","Control · joint column/key recovery"),
                                ("scheduled-shared","scheduled","Control · shared key and sculpture schedule"),
                                ("mixed-shared","mixed","Control · different alphabets")):
        records.append({"id":name,"label":label,"description":"A reproducible small fixture with independent literal replay.","kind":"exact","command":command,
                        "request":json.loads((ROOT/"examples"/(name+".json")).read_text())})
    return records


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key]=value
        return result
    def invalid(value):
        raise ValueError("Nonfinite JSON value")
    def finite_float(value):
        number=float(value)
        if not math.isfinite(number):
            raise ValueError("Nonfinite JSON value")
        return number
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid,parse_float=finite_float)


def browser_safe_integers(value):
    """Preserve exact counts through JavaScript's binary64 JSON parser."""
    if isinstance(value,int) and not isinstance(value,bool) and abs(value)>2**53-1:
        return {"encoding":"exact_integer_hex","value":hex(value)}
    if isinstance(value,dict):
        return {key:browser_safe_integers(item) for key,item in value.items()}
    if isinstance(value,(list,tuple)):
        return [browser_safe_integers(item) for item in value]
    return value


def make_server(state_dir,port=8767,*,probe=True):
    manager=RunManager(Path(state_dir)/"runs")
    try:
        campaigns=CampaignManager(manager)
    except BaseException:
        manager.close()
        raise
    token=secrets.token_urlsafe(32)
    capabilities={"cpu":True,"workers_max":4,"cuda":{"ready":False,"available":False,"error":"GPU probe has not run"}}
    if probe:
        for name in ("TEMP","TMP","CUPY_CACHE_DIR"):
            os.environ[name]=manager.worker_env[name]
        try:
            from .accelerated import probe_backend
            value=probe_backend()
            cuda=value.get("cuda",value)
            capabilities["cuda"]={**cuda,"available":bool(cuda.get("ready",cuda.get("available",False)))}
        except Exception as error:
            capabilities["cuda"]={"ready":False,"available":False,"error":str(error)}

    class Handler(BaseHTTPRequestHandler):
        server_version="KryptosLocal/"+VERSION

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self,format,*args):
            pass

        def _host_valid(self):
            return self.headers.get("Host","") in {f"127.0.0.1:{self.server.server_port}",f"localhost:{self.server.server_port}"}

        def _send(self,status,value,content_type="application/json; charset=utf-8",download=False):
            if not isinstance(value,bytes):
                value=json.dumps(browser_safe_integers(value),allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type",content_type)
            self.send_header("Content-Length",str(len(value)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if download:
                self.send_header("Content-Disposition",'attachment; filename="kryptos-run.json"')
            self.end_headers()
            try:
                self.wfile.write(value)
            except (BrokenPipeError,ConnectionResetError):
                pass

        def do_GET(self):
            if not self._host_valid():
                self._send(403,{"error":"Use this app's localhost address"})
                return
            parsed=urlsplit(self.path)
            try:
                if parsed.path=="/api/info":
                    goal_path=ROOT/"research/improvement-state.json"
                    self._send(200,{"version":VERSION,"k4":{"ciphertext":K4_CIPHERTEXT,"cribs":list(K4_CRIBS)},
                        "presets":presets(),"validation_presets":validation_presets(),"models":MODELS,"capabilities":capabilities,"control_token":token,
                        "goal":json.loads(goal_path.read_text()) if goal_path.exists() else None,
                        "knowledge":{"k4":"No authenticated solution from this project","k5":"No authenticated public input bundled; supply explicit ciphertext and assumptions"}})
                elif parsed.path=="/api/status":
                    self._send(200,{"run":manager.view(),"campaign":campaigns.view()})
                elif parsed.path=="/api/campaigns":
                    self._send(200,{"campaigns":campaigns.list_campaigns()})
                elif re.fullmatch(r"/api/campaigns/[a-f0-9]{32}",parsed.path):
                    self._send(200,{"campaign":campaigns.view(parsed.path.rsplit("/",1)[1])})
                elif parsed.path=="/api/runs":
                    self._send(200,{"runs":manager.list_runs()})
                elif re.fullmatch(r"/api/runs/[a-f0-9]{32}",parsed.path):
                    self._send(200,{"run":manager.view(parsed.path.rsplit("/",1)[1])})
                elif parsed.path=="/api/export":
                    run=manager.view(parse_qs(parsed.query).get("run_id",[None])[0])
                    if run is None:
                        raise KeyError("No run to export")
                    self._send(200,run,download=True)
                elif parsed.path in {"/","/static/index.html","/static/app.js","/static/style.css","/static/mark.svg"}:
                    filename="index.html" if parsed.path=="/" else parsed.path.rsplit("/",1)[1]
                    path=ROOT/"kryptos/static"/filename
                    mime={"index.html":"text/html; charset=utf-8","app.js":"application/javascript; charset=utf-8","style.css":"text/css; charset=utf-8","mark.svg":"image/svg+xml"}[filename]
                    self._send(200,path.read_bytes(),mime)
                elif parsed.path=="/favicon.ico":
                    self._send(204,b"","image/x-icon")
                else:
                    self._send(404,{"error":"Not found"})
            except KeyError as error:
                self._send(404,{"error":str(error)})
            except (ValueError,OSError) as error:
                self._send(500,{"error":str(error)})

        def do_POST(self):
            origin=self.headers.get("Origin")
            expected=f"http://{self.headers.get('Host','')}"
            supplied=self.headers.get("X-Kryptos-Token","")
            if not self._host_valid() or (origin is not None and origin!=expected) or not secrets.compare_digest(supplied,token):
                self._send(403,{"error":"Local session token or origin is invalid; reload the dashboard"})
                return
            try:
                if self.headers.get("Content-Type","").split(";",1)[0]!="application/json":
                    raise ValueError("Send application/json")
                length=int(self.headers.get("Content-Length","0"))
                limit=2*1024*1024 if self.path=="/api/import" else 1024*1024
                if not 0<length<=limit:
                    raise ValueError(f"Request body must be 1 byte through {limit//1024} KiB")
                body=strict_json(self.rfile.read(length).decode("utf-8"))
                if self.path=="/api/start":
                    with campaigns.lock:
                        if campaigns.is_active():
                            raise ValueError("Use campaign controls while a campaign is active")
                        response={"run":manager.start(body)}
                elif self.path in {"/api/pause","/api/stop","/api/resume"}:
                    if not isinstance(body,dict) or set(body)!={"run_id"}:
                        raise ValueError("Control requests require run_id only")
                    with campaigns.lock:
                        if campaigns.is_active():
                            raise ValueError("Use campaign controls while a campaign is active")
                        response={"run":manager.control(self.path.rsplit("/",1)[1],body["run_id"])}
                elif self.path=="/api/resources":
                    if not isinstance(body,dict) or "run_id" not in body:
                        raise ValueError("Resource updates require run_id and settings")
                    response={"run":manager.update_resources(body["run_id"],{k:v for k,v in body.items() if k!="run_id"})}
                elif self.path=="/api/import":
                    response={"inspection":inspect_import(body)}
                elif self.path=="/api/campaigns/preview":
                    response={"preview":preview_campaign(body)}
                elif self.path=="/api/campaigns/start":
                    response={"campaign":campaigns.start(body)}
                elif self.path in {"/api/campaigns/pause","/api/campaigns/stop","/api/campaigns/resume"}:
                    if not isinstance(body,dict) or set(body)!={"campaign_id"}:
                        raise ValueError("Campaign controls require campaign_id only")
                    response={"campaign":campaigns.control(self.path.rsplit("/",1)[1],body["campaign_id"])}
                else:
                    self._send(404,{"error":"Unknown operation"})
                    return
                self._send(200,response)
            except KeyError as error:
                self._send(404,{"error":str(error)})
            except (ValueError,TypeError,UnicodeError,OSError,RecursionError) as error:
                self._send(400,{"error":str(error)})

    try:
        server=ThreadingHTTPServer(("127.0.0.1",port),Handler)
    except OSError:
        campaigns.close()
        manager.close()
        raise
    server.manager=manager
    server.campaigns=campaigns
    return server


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port",type=int,default=8767)
    p.add_argument("--state-dir",type=Path,default=ROOT/"runtime")
    p.add_argument("--no-browser",action="store_true")
    p.add_argument("--skip-gpu-probe",action="store_true")
    args=p.parse_args()
    if not 0<=args.port<=65535:
        p.error("port must be in0..65535")
    try:
        server=make_server(args.state_dir,args.port,probe=not args.skip_gpu_probe)
    except (OSError,RuntimeError) as error:
        p.error(f"Cannot open local server: {error}")
    url=f"http://127.0.0.1:{server.server_port}/"
    print(f"Kryptos Lab {VERSION}: {url}\nNo search starts until you select Start. Ctrl+C stops the local server.",flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.campaigns.close()
        server.manager.close()
        server.server_close()


if __name__=="__main__":
    main()
