"""Durable local jobs. Only completed pages advance the saved scan frontier."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

from .advanced_cli import json_safe_integers
from .parallel_search import _decode
from .__main__ import _target
from .resource_governor import validate_resources,next_batch_size,MAX_EVENTS
from .process_lifetime import launch_owned

ROOT=Path(__file__).resolve().parents[1]
EXACT_COMMANDS={"joint","joint-ranked","scheduled","mixed","alphabet-plus","optimize-plus","general","columns","alphabet","optimize","recover","layers","grid","residues","layout","validate-holdout","validate-controls","validate-ablations"}
MODELS=[{"id":name,"label":name.title()+" · two authors","path":f"research/runs/evaluation-J-001/artifacts/{name}-two-author-trigram.json"}
        for name in ("english","spanish","french","italian","latin")]
MODELS.append({"id":"english-pilot","label":"English · pilot control","path":"research/models/multilingual-001/artifacts/pg1342-english-trigram.json"})
MODEL_PATHS={m["path"] for m in MODELS}
ACTIVE={"running","pausing","stopping"}


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path,value):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+"."+uuid.uuid4().hex+".tmp")
    try:
        with temporary.open("x",encoding="utf-8") as stream:
            json.dump(json_safe_integers(value),stream,allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():
            temporary.unlink()


def integer(value,name,lo,hi):
    if type(value) is not int or not lo<=value<=hi:
        raise ValueError(f"{name} must be an integer in {lo}..{hi}")
    return value


def validate_start(body):
    allowed={"kind","command","request","backend","workers","batch_size","max_batches","time_limit_seconds","note","ranking_mode","adaptive","idle_ms","target_page_seconds"}
    if not isinstance(body,dict) or set(body)-allowed:
        raise ValueError("Unknown run setting")
    kind=body.get("kind","exact")
    command=body.get("command","joint")
    backend=body.get("backend","cpu")
    if kind not in ("exact","accelerated") or command not in EXACT_COMMANDS or backend not in ("cpu","cuda","auto","auto-measured"):
        raise ValueError("Unsupported run kind, command or backend")
    if kind=="exact" and backend=="cuda":
        raise ValueError("This constraint command runs on CPU; choose a family scan for CUDA")
    request=copy.deepcopy(body.get("request",{}))
    if not isinstance(request,dict):
        raise ValueError("Recipe request must be an object")
    if {"checkpoint_path","resume_path"}&set(request):
        raise ValueError("The dashboard manages its own saved run paths")
    if "model_path" in request and request["model_path"] not in MODEL_PATHS:
        raise ValueError("Select a bundled scoring model")
    if "model_paths" in request and (not isinstance(request["model_paths"],list) or not 1<=len(request["model_paths"])<=5 or any(p not in MODEL_PATHS for p in request["model_paths"])):
        raise ValueError("Select1..5 bundled scoring models")
    if command!="validate-controls":
        target,text,cribs,known=_target(request)
        if len(text)>512:
            raise ValueError("Dashboard messages are limited to 512 letters")
        request.update(target=target,ciphertext=text,cribs=cribs)
    elif not isinstance(request.get("cases"),list) or not 2<=len(request["cases"])<=8:
        raise ValueError("Validation controls require2..8 explicit cases")
    caps={"max_nodes":100000,"max_states":200000,"max_segmentations":4096,"max_candidates":1000,
          "top":100,"max_key_slots":256,"max_matrix_cells":2000000,"max_operations":20000000,
          "max_relation_checks":2000000,"max_distinct_plaintexts":10000,"max_constraints":4096,
          "max_frontier":20000,"max_cache_entries":100000,"local_exact_limit":4096,"factor_group_size":8,"group_exact_limit":100000,
          "max_candidates_per_family":17576,"max_total_candidates":100000,"max_orders":5000,"max_evaluations":100000,
          "decomposition_max_entries":20000,"decomposition_max_operations":200000,
          "elimination_bucket_entries":10000,"elimination_max_entries":20000,"elimination_max_operations":200000,
          "null_replicates":16,"minimum_distinct_surviving_families":16,"max_protocol_candidates":100000,
          "max_bound_cache_entries":10000,"residual_cache_max_entries":1024,
          "residual_cache_max_assignments":4096,"residual_cache_max_operations":200000}
    for name,cap in caps.items():
        if name in request:
            minimum=1 if name in {"residual_cache_max_assignments","residual_cache_max_operations"} else 0
            integer(request[name],name,minimum,cap)
    choices={}
    booleans=[]
    if command=="joint-ranked":
        choices={"propagation":{"off","fixed_point"},"branching":{"prefix","constrained"},
                 "score_bound":{"independent","shared_key"},"symmetry":{"off","identical_chunks"}}
        booleans=["early_segmentation"]
    elif command=="optimize-plus":
        choices={"residual_cache":{"off","components"}}
        booleans=["cheap_bound_first"]
    for name,options in choices.items():
        if name in request and (not isinstance(request[name],str) or request[name] not in options):
            raise ValueError("Invalid search strategy: "+name)
    for name in booleans:
        if name in request and type(request[name]) is not bool:
            raise ValueError(name+" must be boolean")
    if "time_limit_seconds" in request:
        value=request["time_limit_seconds"]
        cap=30 if command in {"validate-holdout","validate-controls","validate-ablations"} else 10
        if type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=cap:
            raise ValueError(f"Per-command time_limit_seconds must be in(0,{cap}]")
    if "stages" in request and (not isinstance(request["stages"],list) or not 1<=len(request["stages"])<=16):
        raise ValueError("Supply 1..16 stages")
    settings={"backend":backend,"workers":integer(body.get("workers",1),"workers",1,4),
        "batch_size":integer(body.get("batch_size",512),"batch_size",1,8192),
        "max_batches":integer(body.get("max_batches",100),"max_batches",1,1000000),
        "time_limit_seconds":integer(body.get("time_limit_seconds",60),"time_limit_seconds",1,86400)}
    settings.update(validate_resources({"adaptive":body.get("adaptive",False),"idle_ms":body.get("idle_ms",0),"target_page_seconds":body.get("target_page_seconds",1.0)},backend))
    settings["ranking_mode"]=body.get("ranking_mode","certified")
    if settings["ranking_mode"] not in {"certified","approximate"}:
        raise ValueError("ranking_mode must be certified or approximate")
    if kind=="accelerated":
        if command!="optimize-plus":
            raise ValueError("Family scans use an optimize-plus general/scheduled recipe")
        if "model_path" not in request:
            raise ValueError("Select a frozen model for a family scan")
        if backend in ("cuda","auto","auto-measured"):
            settings["workers"]=1  # One CUDA context; do not multiply GPU memory by worker count.
    note=body.get("note","")
    if not isinstance(note,str) or len(note)>1000:
        raise ValueError("Source/assumptions note must be at most 1000 characters")
    if kind=="exact":
        settings["workers"]=1
    return {"kind":kind,"command":command,"request":request,"settings":settings,"note":note}


def source_identity(request):
    files=sorted((ROOT/"kryptos").glob("*.py"))
    if "model_path" in request:
        files.append(ROOT/request["model_path"])
    files.extend(ROOT/p for p in request.get("model_paths",[]))
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def scan_sort(candidate):
    value=candidate.get("score_exact",0)
    exact=int(value,16) if isinstance(value,str) else value
    return (-exact,candidate.get("plaintext",""),int(candidate.get("assignment_index_decimal","0")))


class _DirectoryOwnership:
    """OS lock, released on handle/process exit; the stable lock file is kept."""
    def __init__(self,path):
        handle=Path(path).open("a+b")
        try:
            if os.name=="nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as error:
            handle.close()
            raise RuntimeError("This state directory is already owned by another app manager, or its OS lock is unavailable. Close the other app or select a different state directory.") from error
        self.handle=handle

    def close(self):
        if self.handle is not None:
            self.handle.close()  # Closing releases the OS lock, including after process death.
            self.handle=None


class RunManager:
    def __init__(self,state_dir,python=None):
        self.directory=Path(state_dir).resolve()
        self.directory.mkdir(parents=True,exist_ok=True)
        self.python=str(python or sys.executable)
        self.worker_env=os.environ.copy()
        for name,part in (("TEMP","tmp"),("TMP","tmp"),("CUPY_CACHE_DIR","cupy")):
            destination=self.directory.parent/"cache"/part
            destination.mkdir(parents=True,exist_ok=True)
            self.worker_env[name]=str(destination)
        self.lock=threading.RLock()
        self.records={}
        self.load_diagnostics=[]
        self.current=None
        self.thread=None
        self.desired=None
        self.pool=None
        self.pool_size=None
        self._closed=False
        self._ownership=_DirectoryOwnership(self.directory/".owner.lock")
        try:
            self._load_records()
        except BaseException:
            self._ownership.close()
            self._closed=True
            raise

    def _load_records(self):
        self.load_diagnostics=[]
        for path in sorted(self.directory.glob("*/run.json")):
            try:
                if path.stat().st_size>64*1024*1024:
                    raise ValueError('Saved record exceeds the64MiB limit')
                value=_decode(json.loads(path.read_text(encoding="utf-8")))
                if not isinstance(value,dict) or value.get("schema")!="kryptos.local-run.v1":
                    raise ValueError('Unsupported saved run schema')
                if (path.parent.name!=value.get('id') or len(path.parent.name)!=32
                        or any(c not in '0123456789abcdef' for c in path.parent.name)):
                    raise ValueError('Saved run identifier does not match its directory')
                for field in ('settings','request','progress'):
                    if not isinstance(value.get(field),dict):
                        raise ValueError('Missing or invalid saved '+field)
                if (value.get('kind') not in {'exact','accelerated'} or value.get('command') not in EXACT_COMMANDS
                        or value.get('state') not in ACTIVE|{'paused','stopped','limited','interrupted','failed','completed'}):
                    raise ValueError('Invalid saved command or state')
                if any(not isinstance(value.get(k),str) for k in ('created_at','updated_at')):
                    raise ValueError('Invalid saved timestamps')
                progress=value['progress']
                if type(progress.get('completed')) is not int or progress['completed']<0:
                    raise ValueError('Invalid saved progress')
                if progress.get('total') is not None and (type(progress['total']) is not int or progress['total']<progress['completed']):
                    raise ValueError('Invalid saved total')
                if value["state"] in ACTIVE:
                    value.update(state="interrupted",error="The local server ended before this run finished. Resume repeats only uncommitted work.",updated_at=now())
                    atomic_json(path,value)
                value.setdefault("ranking_exact_over_committed_pages",False if value.get("kind")=="accelerated" and value.get("progress",{}).get("completed",0) else None)
                value.setdefault("backends_used",[])
                value.setdefault("fallback_reasons",[])
                value.setdefault("resource_events",[])
                value.setdefault("pending_resources",{})
                value["settings"].setdefault("ranking_mode","approximate")
                value["settings"].setdefault("adaptive",False)
                value["settings"].setdefault("idle_ms",0)
                value["settings"].setdefault("target_page_seconds",1.0)
                self.records[value["id"]]=value
            except (ValueError,KeyError,OSError,TypeError,AttributeError) as error:
                self.load_diagnostics.append({'path':path.relative_to(self.directory).as_posix(),
                    'reason':str(error),'action':'Preserve this file; inspect or recover a verified backup. No job was started.'})
        if self.records:
            self.current=max(self.records,key=lambda key:self.records[key]["updated_at"])

    def _save(self,record):
        record["updated_at"]=now()
        atomic_json(self.directory/record["id"]/"run.json",record)

    def view(self,run_id=None):
        with self.lock:
            key=run_id or self.current
            if key is None:
                return None
            if key not in self.records:
                raise KeyError("Run not found")
            value=copy.deepcopy(self.records[key])
            value["can_pause"]=value["state"]=="running" and (value["kind"]=="accelerated" or value.get('exact_resume_supported',False))
            value["can_resume"]=value["state"] in {"paused","stopped","limited","interrupted","failed"}
            value["progress"]["completed_decimal"]=str(value["progress"]["completed"])
            total=value["progress"]["total"]
            value["progress"]["total_decimal"]=str(total) if total is not None else None
            return value

    def list_runs(self):
        with self.lock:
            return [{k:v for k,v in self.view(key).items() if k not in {"candidates","result","source_identity"}}
                    for key in sorted(self.records,key=lambda k:self.records[k]["created_at"],reverse=True)]

    def list_run_summaries(self):
        """History summaries never copy potentially large candidates or results."""
        fields={'id','kind','command','state','created_at','updated_at','note','progress',
                'backend_requested','backend_actual','elapsed_seconds','batches_committed','error',
                'exact_resume_supported','exact_checkpoint'}
        with self.lock:
            result=[]
            for record in self.records.values():
                row={k:copy.deepcopy(record[k]) for k in fields if k in record}
                row['request']={k:record.get('request',{}).get(k) for k in ('target','ciphertext')}
                row['can_resume']=record['state'] in {'paused','stopped','limited','interrupted','failed'}
                row['can_pause']=record['state']=='running' and (record['kind']=='accelerated' or record.get('exact_resume_supported',False))
                row['progress']['completed_decimal']=str(row['progress']['completed'])
                row['progress']['total_decimal']=str(row['progress']['total']) if row['progress'].get('total') is not None else None
                result.append(row)
            return sorted(result,key=lambda r:(r['created_at'],r['id']),reverse=True)

    def _idle(self):
        if self._closed:
            raise ValueError("This app manager is closed")
        if self.thread is not None and self.thread.is_alive():
            raise ValueError("Wait for the current run to pause or stop first")

    def start(self,body,*,run_id=None):
        config=validate_start(body)
        with self.lock:
            self._idle()
            key=run_id or uuid.uuid4().hex
            if not isinstance(key,str) or len(key)!=32 or any(c not in "0123456789abcdef" for c in key) or key in self.records:
                raise ValueError("Run id must be a fresh32-character hex identifier")
            record={"schema":"kryptos.local-run.v1","id":key,"state":"running",**config,
                "created_at":now(),"updated_at":now(),"progress":{"completed":0,"total":None if config["kind"]=="accelerated" else 1,
                 "unit":"candidates" if config["kind"]=="accelerated" else "jobs"},
                "elapsed_seconds":0.0,"rate":0.0,"candidates":[],"result":None,"error":None,
                "backend_requested":config["settings"]["backend"],"backend_actual":None,"batches_committed":0,
                "ranking_exact_over_committed_pages":None,"backends_used":[],"fallback_reasons":[],
                "resource_events":[],"pending_resources":{},"initial_settings":copy.deepcopy(config["settings"]),
                "source_identity":source_identity(config["request"]),"authenticated_solution":False}
            if config['kind']=='exact' and config['command'] in {'optimize-plus','joint-ranked'}:
                record.update(exact_resume_supported=True,exact_checkpoint=None)
                record['progress'].update(completed=0,total=None,unit='search nodes' if config['command']=='optimize-plus' else 'search work steps')
            self._save(record)
            self.records[key]=record
            self.current=key
            self._begin(key)
            return self.view(key)

    def update_resources(self,key,values):
        with self.lock:
            if self._closed:
                raise ValueError("This app manager is closed")
            if key not in self.records:
                raise KeyError("Run not found")
            record=self.records[key]
            if record["kind"]!="accelerated":
                raise ValueError("Resource changes apply to paged family scans")
            if record["state"]=="completed":
                raise ValueError("Completed runs cannot change resources")
            values=validate_resources(values,record["settings"]["backend"])
            if len(record["resource_events"])>=MAX_EVENTS:
                raise ValueError("Resource history limit reached; start a new run")
            staged=copy.deepcopy(record)
            staged["pending_resources"].update(values)
            self._save(staged)
            record.update(staged)
            return self.view(key)

    def _resource_boundary(self,record):
        pending=record.get("pending_resources",{})
        if pending:
            staged=copy.deepcopy(record)
            staged["settings"].update(pending)
            staged["pending_resources"]={}
            staged["resource_events"].append({"offset_decimal":str(record["progress"]["completed"]),"reason":"user","settings":dict(pending)})
            self._save(staged)
            record.update(staged)

    def _close_pool(self):
        if self.pool is not None:
            self.pool.close()
            self.pool=None
            self.pool_size=None

    def _ensure_pool(self,size,key):
        if self.pool is not None and self.pool_size!=size:
            self._close_pool()
        if self.pool is None:
            from .worker_pool import PersistentWorkerPool
            self.pool=PersistentWorkerPool(size,python=self.python,env=self.worker_env,cwd=ROOT,folder=self.directory/key/"pool")
            self.pool_size=size

    def _begin(self,key):
        self.desired=None
        self.thread=threading.Thread(target=self._run,args=(key,),daemon=True,name="kryptos-job")
        self.thread.start()

    def control(self,action,key):
        with self.lock:
            if self._closed:
                raise ValueError("This app manager is closed")
            if key not in self.records:
                raise KeyError("Run not found")
            record=self.records[key]
            if action=="resume":
                self._idle()
                if record["state"] not in {"paused","stopped","limited","interrupted","failed"}:
                    raise ValueError("This run cannot be resumed")
                if source_identity(record["request"])!=record["source_identity"]:
                    raise ValueError("Solver or model files changed. Start a new run to preserve provenance.")
                staged=dict(record,state="running",error=None)
                self._save(staged)
                record.update(staged)
                self.current=key
                self._begin(key)
            else:
                if key!=self.current or record["state"] not in ACTIVE:
                    raise ValueError("This run is not active")
                if action=="pause" and record["kind"]!="accelerated" and not record.get('exact_resume_supported'):
                    raise ValueError("This exact command can be stopped and restarted; page pause applies to family scans")
                staged=dict(record,state="pausing" if action=="pause" else "stopping")
                self._save(staged)
                record.update(staged)
                self.desired=action
            return self.view(key)

    def _launch(self,key,job):
        self._require_identity(self.records[key])
        if job["kind"]=="accelerated":
            return self.pool.execute(job,cancel=lambda:self.desired=="stop",timeout=60)
        folder=self.directory/key/"work"
        folder.mkdir(exist_ok=True)
        token=uuid.uuid4().hex
        input_path=folder/(token+"-job.json")
        output_path=folder/(token+"-result.json")
        error_path=folder/(token+"-stderr.txt")
        atomic_json(input_path,job)
        flags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
        try:
            with error_path.open("w",encoding="utf-8") as errors:
                process=launch_owned([self.python,"-B","-m","kryptos.app_worker","--job",str(input_path),"--output",str(output_path)],
                    cwd=ROOT,stdout=subprocess.DEVNULL,stderr=errors,creationflags=flags,env=self.worker_env)
                started=time.monotonic()
                try:
                    while process.poll() is None:
                        if self.desired=="stop":
                            raise InterruptedError("Stopped before this page committed")
                        if time.monotonic()-started>60:
                            raise TimeoutError("Worker exceeded its 60-second outer limit; reduce the batch or command bounds")
                        time.sleep(0.05)
                finally:
                    try:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=3)
                    finally:
                        process.close()
            if process.returncode:
                raise RuntimeError(error_path.read_text(encoding="utf-8",errors="replace")[-3000:])
            if not output_path.exists() or output_path.stat().st_size>32*1024*1024:
                raise RuntimeError("Worker produced no usable bounded result")
            return _decode(json.loads(output_path.read_text(encoding="utf-8")))
        finally:
            # Worker inputs/results are transient; the atomically saved run owns
            # every committed result. Only private named files are removed.
            for path in (input_path,output_path,error_path):
                if path.exists():
                    path.unlink()

    def _require_identity(self,record,results=()):
        if source_identity(record["request"])!=record["source_identity"]:
            raise ValueError("Solver or model files changed during this run; no new page was committed. Start a new run to preserve provenance.")
        for result in results:
            if "source_sha256" in result:
                expected={key.removeprefix("kryptos/"):value for key,value in record["source_identity"].items() if key.startswith("kryptos/")}
                if result["source_sha256"]!=expected:
                    raise ValueError("Worker solver identity differs from this run; no new page was committed")
            model=record["request"].get("model_path")
            if model and "model_file_sha256" in result and result["model_file_sha256"]!=record["source_identity"][model]:
                raise ValueError("Worker scoring model differs from this run; no new page was committed")

    def _saved_frontier(self,record):
        checkpoint=record.get('exact_checkpoint')
        if checkpoint is None:
            return None
        name=checkpoint.get('file')
        if not isinstance(name,str) or len(name)!=37 or not name.endswith('.json') or any(c not in '0123456789abcdef' for c in name[:-5]):
            raise ValueError('Invalid managed checkpoint filename')
        folder=(self.directory/record['id']/'checkpoints').resolve()
        path=(folder/name).resolve()
        if path.parent!=folder or path.stat().st_size>64*1024*1024 or hashlib.sha256(path.read_bytes()).hexdigest()!=checkpoint.get('sha256'):
            raise ValueError('Managed checkpoint integrity check failed')
        return path

    @staticmethod
    def _public_optimizer_result(value):
        # Execution paths belong to this service. Exported recipes never receive
        # authority to read/write checkpoints when imported on another machine.
        if isinstance(value,dict):
            return {k:RunManager._public_optimizer_result(v) for k,v in value.items()
                    if k not in {'checkpoint_path','resume_path','checkpoint_written'}}
        if isinstance(value,list):
            return [RunManager._public_optimizer_result(v) for v in value]
        return value

    def _run_optimizer(self,key,started,initial_batches):
        record=self.records[key]
        initial_nodes=record['progress']['completed']
        node_budget=integer(record['request'].get('max_nodes',10000),'optimizer activation node budget',0,100000)
        maximum_seconds=record['request'].get('time_limit_seconds',10)
        if type(maximum_seconds) not in (int,float) or not math.isfinite(maximum_seconds) or not 0<maximum_seconds<=10:
            raise ValueError('Invalid optimizer slice time cap')
        while True:
            with self.lock:
                if self.desired:
                    record['state']='paused' if self.desired=='pause' else 'stopped'
                    return
                spent=record['progress']['completed']-initial_nodes
                slices=record['batches_committed']-initial_batches
                settings=record['settings']
                if slices and (spent>=node_budget or slices>=settings['max_batches'] or time.monotonic()-started>=settings['time_limit_seconds']):
                    record['state']='limited'
                    return
                self._require_identity(record)
                previous=self._saved_frontier(record)
                folder=self.directory/key/'checkpoints'
                folder.mkdir(exist_ok=True)
                output=folder/(uuid.uuid4().hex+'.json')
                request=copy.deepcopy(record['request'])
                slice_seconds=record.get('optimizer_slice_seconds',min(2.0,maximum_seconds))
                if type(slice_seconds) not in (int,float) or not math.isfinite(slice_seconds) or not 0<slice_seconds<=maximum_seconds:
                    raise ValueError('Invalid saved optimizer slice duration')
                request.update(max_nodes=min(256,max(0,node_budget-spent)),
                    time_limit_seconds=slice_seconds,checkpoint_path=str(output))
                if previous is not None:
                    request['resume_path']=str(previous)
            result=self._launch(key,{'kind':'exact','command':'optimize-plus','request':request})
            with self.lock:
                self._require_identity(record,[result])
                if self.desired=='stop':
                    raise InterruptedError('Stopped before this optimizer slice committed')
                search=(result.get('optimization') or {}).get('search')
                staged=copy.deepcopy(record)
                staged['result']=self._public_optimizer_result(result)
                candidate=(result.get('optimization') or {}).get('candidate')
                staged['candidates']=[candidate] if candidate is not None else []
                if search is not None:
                    if not output.is_file() or output.stat().st_size>64*1024*1024:
                        raise ValueError('Optimizer did not preserve a bounded frontier')
                    nodes=integer(search['nodes_total'],'optimizer nodes',0,10**18)
                    if nodes<record['progress']['completed'] or nodes-record['progress']['completed']!=search['nodes']:
                        raise ValueError('Optimizer slice did not continue the committed node count')
                    staged['exact_checkpoint']={'file':output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                        'sequence':record['batches_committed']+1,'nodes_total':nodes}
                    staged['progress'].update(completed=nodes,total=None,unit='search nodes')
                    advanced=integer(search.get('frontier_progress_nodes',search['nodes']),
                        'optimizer frontier progress',0,search['nodes'])
                    staged['progress']['frontier_progress_nodes']=record['progress'].get('frontier_progress_nodes',0)+advanced
                    # A timed-out decomposition restores its whole parent.
                    # Count that work, but do not mistake it for proof progress.
                    stalled=advanced==0 and search['stop_reason']=='time_limit'
                    grow=stalled and slice_seconds<maximum_seconds and spent<node_budget
                    staged['optimizer_slice_seconds']=min(maximum_seconds,slice_seconds*2) if grow else slice_seconds
                    staged['optimizer_slice']={'seconds':slice_seconds,'next_seconds':staged['optimizer_slice_seconds'],
                        'retry_after_rebuild':grow,'rebuild_limit_reached':stalled and not grow,
                        'frontier_progress_nodes':advanced,'requeued_nodes':search.get('requeued_nodes',0)}
                    if search['complete']:
                        staged['state']='completed'
                    elif search['stop_reason'] not in {'node_limit','time_limit'} or (advanced==0 and not grow):
                        staged['state']='limited'
                else:
                    staged['state']='completed' if result.get('feasible') is False else 'limited'
                backends=set(staged.get('backends_used',[]))|{'cpu'}
                seed_backend=((search or {}).get('seed_scan') or {}).get('backend_used')
                if seed_backend in {'cpu','cuda'}:
                    backends.add(seed_backend)
                staged.update(backend_actual='cpu',backends_used=sorted(backends))
                staged['batches_committed']+=1
                # The immutable checkpoint is written first. Publishing its
                # digest/pointer is one atomic run commit; interrupted files are ignored.
                self._save(staged)
                record.update(staged)
                if record['state'] in {'completed','limited'}:
                    return

    def _run_joint_ranked(self,key,started,initial_batches):
        """Commit immutable route/key frontiers, with per-activation work limits."""
        record=self.records[key]
        initial=record.get('result') or {}
        counters={'max_states':('states_total',200000),'max_evaluations':('evaluated',100000),
                  'max_orders':('column_orders_visited',5000),'max_segmentations':('segmentations_tested',2048)}
        if record['request'].get('branching')=='constrained':
            counters['max_orders']=('route_completion_blocks',5000)
        start_counts={field:initial.get(field,0) for field,_ in counters.values()}
        budgets={limit:integer(record['request'].get(limit,default),limit,1,200000)
                 for limit,(field,default) in counters.items()}
        maximum=record['request'].get('time_limit_seconds',5)
        if type(maximum) not in (int,float) or not math.isfinite(maximum) or not 0<maximum<=10:
            raise ValueError('Invalid ranked-search slice time cap')
        while True:
            with self.lock:
                if self.desired:
                    record['state']='paused' if self.desired=='pause' else 'stopped'
                    return
                previous_result=record.get('result') or {}
                remaining={limit:budgets[limit]-(previous_result.get(field,0)-start_counts[field])
                           for limit,(field,_) in counters.items()}
                slices=record['batches_committed']-initial_batches
                settings=record['settings']
                if (any(value<=0 for value in remaining.values()) or slices>=settings['max_batches']
                        or time.monotonic()-started>=settings['time_limit_seconds']):
                    record['state']='limited'
                    return
                self._require_identity(record)
                previous=self._saved_frontier(record)
                folder=self.directory/key/'checkpoints'
                folder.mkdir(exist_ok=True)
                output=folder/(uuid.uuid4().hex+'.json')
                seconds=record.get('joint_slice_seconds',min(2.0,maximum))
                if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=maximum:
                    raise ValueError('Invalid saved ranked-search slice duration')
                request=copy.deepcopy(record['request'])
                request.update(remaining,time_limit_seconds=seconds,checkpoint_path=str(output))
                if previous is not None:
                    request['resume_path']=str(previous)
            result=self._launch(key,{'kind':'exact','command':'joint-ranked','request':request})
            with self.lock:
                self._require_identity(record,[result])
                if self.desired=='stop':
                    raise InterruptedError('Stopped before the ranked-search frontier committed')
                if not output.is_file() or output.stat().st_size>64*1024*1024:
                    raise ValueError('Ranked search did not preserve a bounded frontier')
                steps=integer(result['states_total'],'ranked work total',0,10**18)
                if steps-record['progress']['completed']!=result['states_this_run'] or steps<record['progress']['completed']:
                    raise ValueError('Ranked search did not continue committed work counts')
                for limit,(field,_) in counters.items():
                    if result[field]<previous_result.get(field,0) or result[field]-previous_result.get(field,0)>remaining[limit]:
                        raise ValueError('Ranked search exceeded the declared activation budget')
                staged=copy.deepcopy(record)
                staged['result']=self._public_optimizer_result(result)
                staged['candidates']=copy.deepcopy(result.get('candidates',[]))
                staged['exact_checkpoint']={'file':output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                    'sequence':record['batches_committed']+1,'states_total':steps}
                staged['progress'].update(completed=steps,total=None,unit='search work steps',
                    candidate_evaluations=result['evaluated'],frontier_nodes=result['frontier_nodes'])
                advanced=integer(result['frontier_progress_nodes'],'ranked frontier progress',0,10**18)
                stalled=advanced==0 and result['stop_reason']=='time_limit_seconds'
                grow=stalled and seconds<maximum
                staged['joint_slice_seconds']=min(maximum,seconds*2) if grow else seconds
                staged['joint_slice']={'seconds':seconds,'next_seconds':staged['joint_slice_seconds'],
                    'frontier_progress_nodes':advanced,'candidate_evaluations':result['evaluated_this_run']}
                staged.update(backend_actual='cpu',backends_used=['cpu'])
                staged['batches_committed']+=1
                if result['complete']:
                    staged['state']='completed'
                elif result['stop_reason']!='time_limit_seconds' or (advanced==0 and not grow):
                    staged['state']='limited'
                self._save(staged)
                record.update(staged)
                if record['state'] in {'completed','limited'}:
                    return

    def _run(self,key):
        record=self.records[key]
        started=time.monotonic()
        prior_elapsed=record["elapsed_seconds"]
        initial_batches=record["batches_committed"]
        settings=record["settings"]
        try:
            if record.get('exact_resume_supported'):
                if record['command']=='joint-ranked':
                    self._run_joint_ranked(key,started,initial_batches)
                else:
                    self._run_optimizer(key,started,initial_batches)
            elif record["kind"]=="exact":
                self._require_identity(record)
                result=self._launch(key,{"kind":"exact","command":record["command"],"request":record["request"]})
                with self.lock:
                    self._require_identity(record,[result])
                    if self.desired=="stop":
                        raise InterruptedError("Stopped before this result committed")
                    staged=copy.deepcopy(record)
                    staged["result"]=result
                    staged["candidates"]=result.get("candidates",[])
                    if result.get("optimization",{}).get("candidate") is not None:
                        staged["candidates"]=[result["optimization"]["candidate"]]
                    staged["progress"].update(completed=1,total=1)
                    staged["batches_committed"]+=1
                    staged.update(state="completed",backend_actual="cpu",backends_used=["cpu"])
                    self._save(staged)
                    record.update(staged)
            else:
                while True:
                    with self.lock:
                        if self.desired:
                            record["state"]="paused" if self.desired=="pause" else "stopped"
                            break
                        self._resource_boundary(record)
                        settings=record["settings"]
                        if time.monotonic()-started>=settings["time_limit_seconds"] or record["batches_committed"]-initial_batches>=settings["max_batches"]:
                            record["state"]="limited"
                            break
                        self._require_identity(record)
                        offset=record["progress"]["completed"]
                        total=record["progress"]["total"]
                        workers=min(settings["workers"],settings["max_batches"]-(record["batches_committed"]-initial_batches))
                        if total is None:
                            workers=1  # First page establishes exact family size.
                        jobs=[]
                        for i in range(workers):
                            page=offset+i*settings["batch_size"]
                            if total is not None and page>=total:
                                break
                            jobs.append({"kind":"accelerated","request":record["request"],"backend":settings["backend"],
                                         "offset":page,"batch_size":settings["batch_size"],"top":20,"ranking_mode":settings["ranking_mode"]})
                    if not jobs:
                        with self.lock:
                            record["state"]="completed"
                        break
                    self._ensure_pool(settings["workers"],key)
                    wave_started=time.monotonic()
                    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
                        results=list(executor.map(lambda job:self._launch(key,job),jobs))
                    with self.lock:
                        if self.desired=="stop":
                            raise InterruptedError("Stopped before this wave committed")
                        self._require_identity(record,results)
                        unresolved=next((result for result in results if result.get("feasible","unspecified") is None
                                         or result.get("stop_reason")=="algebra_budget"),None)
                        if unresolved is not None:
                            record["result"]={k:v for k,v in unresolved.items() if k!="candidates"}
                            record.update(state="limited",error="The algebra resource bound was reached; feasibility is unresolved and no new page was committed. Resuming unchanged bounds will repeat this result; start a new request with suitable bounds or a smaller model.")
                            self._save(record)
                            break
                        staged=copy.deepcopy(record)
                        merged=staged["candidates"][:]
                        for result in results:
                            total=int(result.get("total_decimal",result.get("total",0)))
                            next_offset=int(result.get("next_offset_decimal",result.get("next_offset",0)))
                            merged.extend(result.get("candidates",[]))
                            staged["progress"].update(completed=next_offset,total=total)
                            staged["backend_actual"]=result.get("backend_used",settings["backend"])
                            backend=result.get("backend_used")
                            if backend is not None and backend not in staged["backends_used"]:
                                staged["backends_used"].append(backend)
                                staged["backends_used"].sort()
                            if result.get("evaluated",0):
                                exact=result.get("ranking_exact_within_page") is True
                                previous=staged["ranking_exact_over_committed_pages"]
                                staged["ranking_exact_over_committed_pages"]=exact if previous is None else previous and exact
                            reason=result.get("fallback_reason")
                            if reason and reason not in staged["fallback_reasons"]:
                                staged["fallback_reasons"].append(reason)
                            staged["result"]={k:v for k,v in result.items() if k!="candidates"}
                            staged["batches_committed"]+=1
                        unique={}
                        for candidate in sorted(merged,key=scan_sort):
                            unique.setdefault(candidate["plaintext"],candidate)
                        staged["candidates"]=list(unique.values())[:20]
                        staged["elapsed_seconds"]=prior_elapsed+time.monotonic()-started
                        staged["rate"]=staged["progress"]["completed"]/max(staged["elapsed_seconds"],0.001)
                        if staged["progress"]["completed"]>=total:
                            staged["state"]="completed"
                        elif settings["adaptive"]:
                            size=next_batch_size(settings["batch_size"],time.monotonic()-wave_started,settings["target_page_seconds"])
                            if size!=settings["batch_size"]:
                                if len(staged["resource_events"])+bool(staged["pending_resources"])<MAX_EVENTS:
                                    staged["settings"]["batch_size"]=size
                                    staged["resource_events"].append({"offset_decimal":str(staged["progress"]["completed"]),"reason":"measured_wave_duration","wave_seconds":time.monotonic()-wave_started,"settings":{"batch_size":size}})
                                else:
                                    staged["settings"]["adaptive"]=False
                                    staged["adaptation_disabled_reason"]="Resource event cap reached; remaining pages keep current size"
                        self._save(staged)
                        record.update(staged)
                        if record["state"]=="completed":
                            break
                    idle_until=time.monotonic()+record["settings"]["idle_ms"]/1000
                    while time.monotonic()<idle_until and not self.desired:
                        time.sleep(min(.05,max(0,idle_until-time.monotonic())))
        except InterruptedError:
            with self.lock:
                record["state"]="stopped"
        except Exception as error:
            with self.lock:
                record.update(state="failed",error=str(error))
        finally:
            self._close_pool()
            with self.lock:
                record["elapsed_seconds"]=prior_elapsed+time.monotonic()-started
                record["rate"]=record["progress"]["completed"]/max(record["elapsed_seconds"],0.001)
                try:
                    self._save(record)
                except OSError as error:
                    # Preserve the last committed frontier. This diagnostic is
                    # explicitly memory-only while storage is unavailable.
                    record.update(state="failed",error=f"Final status could not be saved: {error}",status_persistence_failed=True)

    def close(self):
        with self.lock:
            self._closed=True
            self.desired="stop"
        if self.thread is not None:
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                # Do not allow a replacement manager while this writer is alive.
                raise RuntimeError("Worker shutdown is still pending; state-directory ownership was retained")
        with self.lock:
            # A worker-lifetime cleanup failure must keep this manager's
            # directory lock until all owned descendants are released.
            self._close_pool()
            self._ownership.close()
