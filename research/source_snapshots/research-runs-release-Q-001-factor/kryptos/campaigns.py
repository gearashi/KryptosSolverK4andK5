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
from .campaign_sharing import compatible_prefix, digest, snapshot, validate_option

TERMINAL={"completed","equivalent","incomplete","failed"}
AXIS=re.compile(r"request\.(?:period|width|order|alphabet|cipher|model_path)|request\.stages\.(?:[0-9]|1[0-5])\.(?:period|key_length|offset|cipher|alphabet|permutation)")

def _flat(config):
    return {k:copy.deepcopy(config[k]) for k in ("kind","command","request","note")}|copy.deepcopy(config["settings"])

def preview_campaign(body):
    if not isinstance(body,dict) or set(body)-{"base","axes","name","generator","share_incomplete_scans"}:
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
                'share_incomplete_scans':validate_option(body,jobs),
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
            "share_incomplete_scans":validate_option(body,jobs),
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
        self.load_diagnostics=[]
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
                if path.stat().st_size>16*1024*1024:
                    raise ValueError("Campaign record exceeds 16 MiB")
                value=_decode(json.loads(path.read_text()))
                if not isinstance(value,dict) or value.get("schema")!="kryptos.campaign.v1" or value.get("id")!=path.parent.name:
                    raise ValueError("Unsupported campaign schema or mismatched identifier")
                if not re.fullmatch(r"[a-f0-9]{32}",value["id"]) or not isinstance(value.get("jobs"),list) or len(value["jobs"])>128:
                    raise ValueError("Malformed campaign identifier or job list")
                if any(not isinstance(j,dict) or not isinstance(j.get("state"),str) for j in value["jobs"]) or not isinstance(value.get("updated_at"),str) or not isinstance(value.get("created_at"),str) or not isinstance(value.get("state"),str):
                    raise ValueError("Malformed campaign state or timestamps")
                if value["state"] in ACTIVE:
                    value.update(state="interrupted",error="Server ended; resume continues unfinished jobs only")
                    atomic_json(path,value)
                self.records[value["id"]]=value
            except (ValueError,KeyError,OSError,TypeError,AttributeError,RecursionError) as error:
                self.load_diagnostics.append({"path":"campaigns/"+path.parent.name+"/campaign.json","reason":str(error),
                    "action":"Original file preserved. Back up the workspace before repairing this record or recovering another copy."})
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
                    "source_identity":_identities(plan["jobs"]),"interpretation":plan["interpretation"],"authenticated_solution":False,
                    "share_incomplete_scans":plan["share_incomplete_scans"]}
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

    def _preflight(self,key,job,task):
        """Count validation work separately from committed candidate evaluations."""
        started=time.monotonic()
        result=None
        try:
            result=self._task(key,task)
            return result
        finally:
            if self.records[key].get('share_incomplete_scans'):
                with self.lock:
                    work=job.setdefault('sharing_validation',{})
                    kind=task['kind']
                    work[kind+'_calls']=work.get(kind+'_calls',0)+1
                    work['elapsed_seconds']=work.get('elapsed_seconds',0)+time.monotonic()-started
                    if kind=='alias-candidates' and result is not None:
                        count=len(result['candidates'])
                        work['candidate_replays']=work.get('candidate_replays',0)+count
                        work['literal_reencrypted_letters']=work.get('literal_reencrypted_letters',0)+sum(len(c['plaintext']) for c in result['candidates'])

    def _owner(self,record,job):
        key=(job.get('shared_scan') or {}).get('owner_job_id',job['id'])
        return next(j for j in record['jobs'] if j['id']==key)

    def _shared_source(self,record,index,job):
        """Search only this campaign's own historical, hash-pinned snapshots."""
        if not record.get('share_incomplete_scans'):
            return None
        reason='no_compatible_committed_prefix'
        identity=job.get('family_identity') or {}
        settings=validate_start(job['config'])['settings']
        for prior in reversed(record['jobs'][:index]):
            if (prior['state'] not in TERMINAL or not prior.get('run_id')
                    or (prior.get('family_identity') or {}).get('scoring_family_sha256')!=identity.get('scoring_family_sha256')):
                continue
            try:
                owner=self._owner(record,prior)
                run=self.manager.view(prior['run_id'])
                run_hash=hashlib.sha256((self.manager.directory/run['id']/'run.json').read_bytes()).hexdigest()
                reason=compatible_prefix(job,prior,owner,run,run_hash,source_identity(run['request']),settings)
                if reason is None:
                    return prior,owner,run,run_hash
            except (KeyError,ValueError,OSError,StopIteration):
                reason='owned_prefix_unavailable'
        job['sharing_status']={'shared':False,'reason':reason}
        return None

    def _validate_shared_owner(self,record,job,run):
        owner=self._owner(record,job)
        shared=job['shared_scan']
        if (shared['owner_run_id']!=run['id'] or owner['run_id']!=run['id']
                or owner.get('shared_scan') or run['request']!=owner['config']['request']
                or run['state']=='failed'
                or digest(run['request'])!=shared['coordinate_request_sha256']
                or digest(job['config']['request'])!=shared['recipe_request_sha256']
                or (job.get('family_identity') or {}).get('scoring_family_sha256')!=shared['scoring_family_sha256']
                or digest(run['source_identity'])!=shared['source_identity_sha256']
                or run['source_identity']!=source_identity(run['request'])
                or run['settings']!=validate_start(job['config'])['settings']
                or run.get('pending_resources') or run.get('resource_events')
                or run['progress']['completed']<int(shared['started_offset_decimal'])
                or run.get('ranking_exact_over_committed_pages') is not True):
            raise ValueError('Shared scan owner, source, resources or certified frontier changed; no restart was attempted')

    def _freeze_scan(self,key,record,job,run):
        if not record.get('share_incomplete_scans'):
            return None
        owner=self._owner(record,job)
        path=self.manager.directory/run['id']/'run.json'
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        candidates=copy.deepcopy(run['candidates'])
        if job.get('shared_scan'):
            self._validate_shared_owner(record,job,run)
            replay=self._preflight(key,job,{'kind':'alias-candidates','request':job['config']['request'],'candidates':candidates})
            candidates=replay['candidates']
            for candidate in candidates:
                # An assignment index would belong to the owner's basis only.
                candidate.pop('assignment_index',None)
                candidate.pop('assignment_index_decimal',None)
                candidate['shared_owner_run_id']=run['id']
                candidate['ranking_scope']='whole_family' if run['state']=='completed' else 'committed_owner_prefix'
        if hashlib.sha256(path.read_bytes()).hexdigest()!=before:
            raise ValueError('Owned run changed during alias validation; no snapshot committed')
        return snapshot(job,owner,run,before,candidates)

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
                    if job.get('shared_scan') and job.get('run_id') not in self.manager.records:
                        raise ValueError('Shared scan owner is unavailable; no new sequence or imported frontier was started')
                if job["run_id"] and job["run_id"] in self.manager.records:
                    run=self.manager.view(job["run_id"])
                    if job.get('shared_scan'):
                        self._validate_shared_owner(record,job,run)
                    # Explicit campaign resume can recover an interruption
                    # after the child cutoff but before its outcome commit.
                    # Terminal incomplete jobs were already skipped above.
                    if run["state"] in {"paused","stopped","limited","interrupted","failed"}:
                        self.manager.control("resume",run["id"])
                    run=self._wait_run(record,job)
                else:
                    if job["config"]["kind"]=="accelerated" and job.get("family_identity") is None:
                        identity=self._preflight(key,job,{"kind":"family-identity","request":job["config"]["request"]})
                        with self.lock:
                            self._check_identity(record)
                            job["family_identity"]=identity
                            self._save(record)
                    identity=job.get("family_identity") or {}
                    cached=self._cached_completed(identity)
                    if cached and cached[0]['campaign_id']!=key:
                        reference,original=cached
                        replay=self._preflight(key,job,{"kind":"alias-candidates","request":job["config"]["request"],"candidates":original["candidates"]})
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
                            replay=self._preflight(key,job,{"kind":"alias-candidates","request":job["config"]["request"],"candidates":original["candidates"]})
                            with self.lock:
                                if self.desired:
                                    raise InterruptedError("Campaign stopped before alias commit")
                                self._check_identity(record)
                                job.update(state="equivalent",classification="same_plaintext_family_and_scoring; own_recipe_replayed",alias_of=alias["id"],candidates=replay["candidates"])
                                self._save(record)
                            continue
                    with self.lock, self.manager.lock:
                        if self.desired:
                            record["state"]="paused" if self.desired=="pause" else "stopped"
                            break
                        self._check_identity(record)
                        shared=self._shared_source(record,index,job)
                        if shared:
                            prior,owner,run,run_hash=shared
                            staged=copy.deepcopy(record)
                            staged_job=staged['jobs'][index]
                            staged_job.update(run_id=run['id'],alias_of=owner['id'],alias_run_id=run['id'],
                                shared_scan={'owner_job_id':owner['id'],'owner_run_id':run['id'],
                                    'reference_job_id':prior['id'],'reference_run_sha256':run_hash,
                                    'started_offset_decimal':str(run['progress']['completed']),
                                    'coordinate_request_sha256':digest(run['request']),
                                    'recipe_request_sha256':digest(job['config']['request']),
                                    'scoring_family_sha256':identity['scoring_family_sha256'],
                                    'source_identity_sha256':digest(run['source_identity'])},
                                sharing_status={'shared':True,'reason':'continued_original_managed_sequence'})
                            # Reservation precedes dispatch, so restarts keep the
                            # same owner; an alias never starts a fresh basis.
                            self._save(staged)
                            job.update(staged_job)
                            self.manager.control('resume',run['id'])
                        else:
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
                scan_snapshot=self._freeze_scan(key,record,job,run)
                with self.lock:
                    self._check_identity(record)
                    state,classification=self._outcome(run)
                    if job.get('shared_scan'):
                        classification=('shared_complete_family; own_recipe_replayed' if state=='completed'
                                        else 'shared_partial_prefix; own_recipe_replayed; whole_family_inconclusive')
                    job.update(state=state,classification=classification,error=run.get("error"))
                    if scan_snapshot is not None:
                        job.update(scan_snapshot=scan_snapshot,candidates=copy.deepcopy(scan_snapshot['candidates']))
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
