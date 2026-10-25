"""Own the isolated source server and bounded post-review browser check."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from kryptos.process_lifetime import launch_owned


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--node',required=True)
    p.add_argument('--playwright-module',required=True)
    p.add_argument('--browser-executable',required=True)
    args=p.parse_args()
    out=Path(__file__).resolve().parent
    app=ROOT/'kryptos/static/app.js'
    before=hashlib.sha256(app.read_bytes()).hexdigest()
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with (out/'server.txt').open('x',encoding='utf-8') as log:
        server=launch_owned([sys.executable,'-B','-m','kryptos.app','--port','0','--no-browser','--skip-gpu-probe','--state-dir',str(out/'isolated-state')],cwd=ROOT,env=env,stdout=log,stderr=log)
        try:
            url=None
            for _ in range(150):
                found=re.search(r'http://127\.0\.0\.1:\d+/',(out/'server.txt').read_text())
                if found:url=found.group();break
                if server.poll() is not None:break
                time.sleep(.1)
            if url is None:raise RuntimeError('Isolated server did not become ready')
            with (out/'browser-console.txt').open('x',encoding='utf-8') as browser_log:
                browser=launch_owned([args.node,str(out/'check_joint_label.cjs'),url,str(out),args.playwright_module,args.browser_executable],cwd=ROOT,env=env,stdout=browser_log,stderr=browser_log)
                try:
                    if browser.wait(timeout=60):raise RuntimeError('Focused browser assertion failed; see saved log')
                finally:browser.close()
        finally:server.close()
    after=hashlib.sha256(app.read_bytes()).hexdigest()
    assert before==after
    result=json.loads((out/'browser-result.json').read_text())
    assert result['served_app_js_sha256']==after
    evidence={'schema':'kryptos.post-review-ui-integrity.v1','source':'kryptos/static/app.js','sha256_before':before,'sha256_after':after,'checks_passed':result['passed'],'cleanup':'Owned browser and isolated random-port server process trees closed.','files':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in out.iterdir() if f.is_file()}}
    (out/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'passed':result['passed'],'label':result['expected'],'app_js_sha256':after}))


if __name__=='__main__':main()
