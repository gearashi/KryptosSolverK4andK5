"""Durable bounded recipe campaigns with exact, conservative family reuse."""
import copy
import hashlib
from itertools import product
import json
from pathlib import Path
import re
import threading
import time
import uuid

from .app_jobs import atomic_json,now,validate_start,source_identity,ROOT,ACTIVE
from .parallel_search import _decode

TERMINAL={"completed","equivalent","incomplete","failed"}
AXIS=re.compile(r"request\.(?:period|width|order|alphabet|cipher|model_path)|request\.stages\.(?:[0-9]|1[0-5])\.(?:period|key_length|offset|cipher|alphabet|permutation)")

def _flat(config):
    return {k:copy.deepcopy(config[k]) for k in ("kind","command","request","note")}|copy.deepcopy(config["settings"])

def preview_campaign(body):
    if not isinstance(body,dict) or set(body)-{"base","axes","name","generator"}:
        raise ValueError("Campaign requires base, axes or generator, and optional name")
    name=body.get("name","Recipe campaign")
    if not isinstance(name,str) or not 1<=len(name)<=100:
        raise ValueError("Campaign name must contain1..100 characters")
    base=body.get("base")
    if 'generator' in body:
        if body.get('axes'):
            raise ValueError('Use a grammar or explicit axes, not both')
        from .hypotheses import generate_configs
        generated,summary=generate_configs(_flat(validate_start(base)),body['generator'])
        jobs=[{'id':f'job-{i+1:03d}','config':_flat(validate_start(row['config'])),
               'changes':{},'generation_aliases':row['generation_aliases']} for i,row in enumerate(generated)]
        return {'name':name,'jobs':jobs,'job_count':len(jobs),'generation':summary,'limits':{'max_jobs':128},
                'interpretation':summary['interpretation']}
    axes=body.get("axes",[])
    if not isinstance(axes,list) or len(axes)>6:
        raise ValueError("Campaign allows at most6 axes")
    paths=[]
    sizes=1
    for axis in axes:
        if not isinstance(axis,dict) or set(axis)!={"path","values"} or not isinstance(axis["path"],str) or not AXIS.fullmatch(axis["path"]):
            raise ValueError("Axis must name a supported recipe field")
        if axis["path"] in paths or not isinstance(axis["values"],list) or not 1<=len(axis["values"])<=32:
            raise ValueError("Axis paths must be unique and have1..32 values")
        paths.append(axis["path"])
        sizes*=len(axis["values"])
    if sizes>128:
        raise ValueError("Campaign exceeds128 expanded jobs")
    jobs=[]
    seen=set()
    for choices in product(*(axis["values"] for axis in axes)):
        config=copy.deepcopy(base)
        changes={}
        for path,value in zip(paths,choices):
            parts=path.split(".")
            node=config
            try:
                for part in parts[:-1]:
                    node=node[int(part)] if isinstance(node,list) else node[part]
                if not isinstance(node,dict):
                    raise ValueError("Axis parent must be a recipe object")
                node[parts[-1]]=copy.deepcopy(value)
            except (KeyError,IndexError,TypeError) as error:
                raise ValueError(f"Axis path is absent: {path}") from error
            changes[path]=value
        config=_flat(validate_start(config))
        if config["command"] in {"validate-holdout","validate-controls","validate-ablations"}:
            raise ValueError("Validation protocols already select a model bank; run them separately")
        fingerprint=json.dumps(config,sort_keys=True,separators=(",",":"),allow_nan=False)
        if fingerprint not in seen:
            seen.add(fingerprint)
            jobs.append({"id":f"job-{len(jobs)+1:03d}","config":config,"changes":changes})
    return {"name":name,"job_count":len(jobs),"jobs":jobs,"limits":{"max_jobs":128},
            "interpretation":"Each unique request has its own budget/outcome. Incomplete jobs remain inconclusive. Raw scores from different models/masks are not pooled; equal plaintext families do not identify equal encryption methods."}

def _identities(jobs):
    models=set()
    for job in jobs:
        request=job["config"]["request"]
        if "model_path" in request:
            models.add(request["model_path"])
        models.update(request.get("model_paths",[]))
    # Python source is common to every job: hash each file only once per check.
    return source_identity({"model_paths":sorted(models)})

class CampaignManager:
    def __init__(self,manager):
        self.manager=manager
        self.directory=manager.directory.parent/"campaigns"
        self.directory.mkdir(parents=True,exist_ok=True)
        self.lock=threading.RLock()
        self.records={}
        self.current=None
        self.thread=None
        self.desired=None
        self.preflight_pool=None
        self.closed=False
        self.cache_path=self.directory/'completed-families.json'
        self.completed_cache={}
        try:
            if self.cache_path.stat().st_size<=4*1024*1024:
                cached=json.loads(self.cache_path.read_text())
                if cached.get('schema')=='kryptos.completed-family-cache.v1' and isinstance(cached.get('entries'),dict) and len(cached['entries'])<=1000:
                    self.completed_cache=cached['entries']
        except (OSError,ValueError,AttributeError):
            pass  # Cache is expendable. Saved runs remain authoritative.
        for path in sorted(self.directory.glob("*/campaign.json")):
            try:
                value=_decode(json.loads(path.read_text()))
                if value.get("schema")!="kryptos.campaign.v1" or value["id"]!=path.parent.name:
                    continue
                if value["state"] in ACTIVE:
                    value.update(state="interrupted",error="Server ended; resume continues unfinished jobs only")
                    atomic_json(path,value)
                self.records[value["id"]]=value
            except (ValueError,KeyError,OSError):
                continue
        if self.records:
            self.current=max(self.records,key=lambda k:self.records[k]["updated_at"])

    def is_active(self):
        return self.thread is not None and self.thread.is_alive()

    def _save(self,value):
        value["updated_at"]=now()
        atomic_json(self.directory/value["id"]/"campaign.json",value)

    def view(self,key=None):
        with self.lock:
            key=key or self.current
            if key is None:
                return None
            value=copy.deepcopy(self.records[key])
            value["progress"]={"finished":sum(j["state"] in TERMINAL for j in value["jobs"]),"total":len(value["jobs"]),"deduplicated":sum(j["state"]=="equivalent" for j in value["jobs"])}
            value["can_resume"]=value["state"] in {"paused","stopped","interrupted","failed"}
            return value

    def list_campaigns(self):
        with self.lock:
            return [{k:v for k,v in self.view(key).items() if k not in {"jobs","source_identity","plan"}} for key in sorted(self.records,key=lambda k:self.records[k]["created_at"],reverse=True)]

    def start(self,body):
        plan=preview_campaign(body)
        with self.lock:
            if self.closed or self.is_active():
                raise ValueError("Campaign manager is closed or already running")
            self.manager._idle()
            key=uuid.uuid4().hex
            record={"schema":"kryptos.campaign.v1","id":key,"name":plan["name"],"state":"running","created_at":now(),"updated_at":now(),"error":None,"plan":copy.deepcopy(body),
                    "jobs":[dict(j,state="queued",run_id=None,classification=None,alias_of=None,family_identity=None) for j in plan["jobs"]],
                    "source_identity":_identities(plan["jobs"]),"interpretation":plan["interpretation"],"authenticated_solution":False}
            if 'generation' in plan:
                record['generation']=plan['generation']
            self._save(record)
            self.records[key]=record
            self.current=key
            self._begin(key)
            return self.view(key)

    def _begin(self,key):
        self.desired=None
        self.thread=threading.Thread(target=self._run,args=(key,),daemon=True,name="kryptos-campaign")
        self.thread.start()

    def control(self,action,key):
        with self.lock:
            if self.closed:
                raise ValueError("Campaign manager is closed")
            record=self.records[key]
            if action=="resume":
                if self.is_active() or record["state"] not in {"paused","stopped","interrupted","failed"}:
                    raise ValueError("Campaign is not resumable")
                self.manager._idle()
                if _identities(record["jobs"])!=record["source_identity"]:
                    raise ValueError("Source/model files changed; create a new campaign")
                staged=dict(record,state="running",error=None)
                self._save(staged)
                record.update(staged)
                self.current=key
                self._begin(key)
            elif action in {"pause","stop"}:
                if key!=self.current or not self.is_active():
                    raise ValueError("Campaign is not active")
                staged=dict(record,state="pausing" if action=="pause" else "stopping")
                self._save(staged)
                record.update(staged)
                self.desired=action
            else:
                raise ValueError("Unknown campaign control")
            return self.view(key)

    def _check_identity(self,record):
        if _identities(record["jobs"])!=record["source_identity"]:
            raise ValueError("Source/model files changed; campaign cannot commit new work")

    def _remember_completed(self,record,job):
        identity=job.get('family_identity') or {}
        if job['state']!='completed' or not identity.get('eligible') or not job.get('run_id'):
            return
        run=self.manager.view(job['run_id'])
        if run['kind']!='accelerated' or run['state']!='completed' or run.get('ranking_exact_over_committed_pages') is not True:
            return
        path=self.manager.directory/run['id']/'run.json'
        entry={'campaign_id':record['id'],'job_id':job['id'],'run_id':run['id'],
               'run_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.completed_cache[identity['scoring_family_sha256']]=entry
        while len(self.completed_cache)>1000:
            del self.completed_cache[next(iter(self.completed_cache))]
        try:
            atomic_json(self.cache_path,{'schema':'kryptos.completed-family-cache.v1','entries':self.completed_cache})
        except OSError as error:
            record['cache_diagnostic']='Completed run saved; optional cache write failed: '+str(error)

    def _cached_completed(self,identity):
        entry=self.completed_cache.get(identity.get('scoring_family_sha256')) if identity.get('eligible') else None
        if not isinstance(entry,dict):
            return None
        try:
            run_id=entry['run_id']
            if not isinstance(run_id,str) or not re.fullmatch('[0-9a-f]{32}',run_id):
                return None
            path=self.manager.directory/run_id/'run.json'
            if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['run_sha256']:
                return None
            run=self.manager.view(run_id)
            if (run['kind']!='accelerated' or run['state']!='completed' or run.get('ranking_exact_over_committed_pages') is not True
                    or run['source_identity']!=source_identity(run['request'])
                    or run['progress']['completed']!=run['progress']['total']):
                return None
            owner=self.records[entry['campaign_id']]
            original=next(j for j in owner['jobs'] if j['id']==entry['job_id'] and j['run_id']==run_id)
            if (original.get('family_identity') or {}).get('scoring_family_sha256')!=identity['scoring_family_sha256']:
                return None
            return entry,run
        except (KeyError,ValueError,OSError,TypeError,StopIteration):
            return None

    def _task(self,key,job):
        from .worker_pool import PersistentWorkerPool
        if self.preflight_pool is None:
            self.preflight_pool=PersistentWorkerPool(1,python=self.manager.python,env=self.manager.worker_env,cwd=ROOT,folder=self.directory/key/"preflight")
        return self.preflight_pool.execute(job,cancel=lambda:self.desired is not None,timeout=60)

    @staticmethod
    def _outcome(run):
        result=run.get("result") or {}
        if run["state"]=="failed":
            return "failed","worker_failure"
        if result.get("feasible") is False:
            return "completed","excluded_declared_model"
        search=(result.get("optimization") or {}).get("search",{})
        complete=run["state"]=="completed" and (run["kind"]=="accelerated" or search.get("complete",result.get("complete",result.get("enumeration_complete",False))))
        if complete:
            return "completed","family_evaluated_with_fits" if run.get("candidates") else "completed_declared_check"
        return "incomplete","inconclusive_within_budget"

    def _wait_run(self,record,job):
        while self.manager.thread is not None and self.manager.thread.is_alive():
            if self.desired:
                current=self.manager.view(job["run_id"])
                if current["state"]=="running":
                    action="pause" if self.desired=="pause" and current.get('can_pause') else "stop"
                    self.manager.control(action,job["run_id"])
                elif self.desired=="stop" and current["state"]=="pausing":
                    self.manager.control("stop",job["run_id"])
            self.manager.thread.join(timeout=.1)
        return self.manager.view(job["run_id"])

    def _run(self,key):
        record=self.records[key]
        try:
            for index in range(len(record["jobs"])):
                with self.lock:
                    if self.desired:
                        record["state"]="paused" if self.desired=="pause" else "stopped"
                        break
                    job=record["jobs"][index]
                    if job["state"] in TERMINAL:
                        continue
                    self._check_identity(record)
                if job["run_id"] and job["run_id"] in self.manager.records:
                    run=self.manager.view(job["run_id"])
                    if run["state"] in {"paused","stopped","interrupted","failed"}:
                        self.manager.control("resume",run["id"])
                    run=self._wait_run(record,job)
                else:
                    if job["config"]["kind"]=="accelerated" and job.get("family_identity") is None:
                        identity=self._task(key,{"kind":"family-identity","request":job["config"]["request"]})
                        with self.lock:
                            self._check_identity(record)
                            job["family_identity"]=identity
                            self._save(record)
                    identity=job.get("family_identity") or {}
                    cached=self._cached_completed(identity)
                    if cached and cached[0]['campaign_id']!=key:
                        reference,original=cached
                        replay=self._task(key,{"kind":"alias-candidates","request":job["config"]["request"],"candidates":original["candidates"]})
                        with self.lock:
                            if self.desired:
                                raise InterruptedError('Campaign stopped before cached alias commit')
                            self._check_identity(record)
                            job.update(state='equivalent',classification='completed_cross_campaign_family; own_recipe_replayed',
                                alias_of=reference['job_id'],alias_campaign_id=reference['campaign_id'],alias_run_id=reference['run_id'],
                                candidates=replay['candidates'],cache_integrity_verified=True)
                            self._save(record)
                        continue
                    alias=next((prior for prior in record["jobs"][:index] if prior["state"]=="completed" and (prior.get("family_identity") or {}).get("eligible") and identity.get("eligible") and prior["family_identity"]["scoring_family_sha256"]==identity["scoring_family_sha256"] and prior.get("run_id")),None)
                    if alias:
                        original=self.manager.view(alias["run_id"])
                        # Partial or approximate ranking is not reused as an exact alias.
                        if original["state"]=="completed" and original["ranking_exact_over_committed_pages"] is True:
                            replay=self._task(key,{"kind":"alias-candidates","request":job["config"]["request"],"candidates":original["candidates"]})
                            with self.lock:
                                if self.desired:
                                    raise InterruptedError("Campaign stopped before alias commit")
                                self._check_identity(record)
                                job.update(state="equivalent",classification="same_plaintext_family_and_scoring; own_recipe_replayed",alias_of=alias["id"],candidates=replay["candidates"])
                                self._save(record)
                            continue
                    with self.lock:
                        if self.desired:
                            record["state"]="paused" if self.desired=="pause" else "stopped"
                            break
                        self._check_identity(record)
                        # Persist a reserved identity BEFORE dispatch. A crash on
                        # either side cannot orphan an untracked completed run.
                        job["run_id"]=job["run_id"] or uuid.uuid4().hex
                        self._save(record)
                        run=self.manager.start(job["config"],run_id=job["run_id"])
                        job.update(state="running")
                        self._save(record)
                    run=self._wait_run(record,job)
                with self.lock:
                    self._check_identity(record)
                    if self.desired and run["state"] in {"paused","stopped","interrupted"}:
                        job["state"]="paused"
                        record["state"]="paused" if self.desired=="pause" else "stopped"
                        self._save(record)
                        break
                    state,classification=self._outcome(run)
                    job.update(state=state,classification=classification,error=run.get("error"))
                    self._save(record)
                    self._remember_completed(record,job)
            else:
                with self.lock:
                    record["state"]="completed"
        except InterruptedError:
            with self.lock:
                record["state"]="paused" if self.desired=="pause" else "stopped"
        except Exception as error:
            with self.lock:
                record.update(state="failed",error=str(error))
        finally:
            if self.preflight_pool is not None:
                try:
                    self.preflight_pool.close()
                    self.preflight_pool=None
                except Exception as error:
                    with self.lock:
                        record.update(state='failed',error='Campaign worker cleanup failed: '+str(error))
            with self.lock:
                self._save(record)

    def close(self):
        self.closed=True
        self.desired="stop"
        if self.thread is not None:
            self.thread.join(timeout=15)
            if self.thread.is_alive():
                raise RuntimeError("Campaign shutdown is still pending")
        if self.preflight_pool is not None:
            self.preflight_pool.close()  # Failure keeps ownership/ref for a later retry.
            self.preflight_pool=None
