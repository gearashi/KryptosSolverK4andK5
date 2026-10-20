"""Lazy exact-product bounds, adaptive branching and resumable finite search.

Scores are integers. An independent-letter ngram bound may be loose but never
excludes a feasible local completion. Checkpoints preserve an entire frontier,
including the unexpanded parent when a memory cap prevents expansion.
"""
import hashlib
import heapq
from itertools import product
import json
import math
from pathlib import Path
import time

SCHEMA = "kryptos.lazy-product.v1"


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _integer(value,name,low,high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def _strict_load(path):
    path = Path(path)
    if path.stat().st_size > 64*1024*1024:
        raise ValueError("checkpoint exceeds64MiB")
    def unique(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise ValueError("duplicate checkpoint field")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("nonfinite checkpoint value")
    return json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=unique,parse_constant=reject)


def _validate(problem):
    if not isinstance(problem,dict) or set(problem)-{"schema","domains","factors","model","metadata"} or problem.get("schema") != SCHEMA:
        raise ValueError("unsupported product problem")
    domains = problem.get("domains")
    if not isinstance(domains,list) or len(domains)>512:
        raise ValueError("problem requires at most512 domains")
    for d in domains:
        _integer(d,"domain",1,26)
    factors = problem.get("factors")
    if not isinstance(factors,list) or len(factors)>4096:
        raise ValueError("problem requires at most4096 factors")
    model = problem.get("model")
    if model is not None:
        if not isinstance(model,dict) or set(model)!={"alphabet","counts","p","q","order","id"}:
            raise ValueError("invalid saved scoring model")
        alphabet = model["alphabet"]
        if not isinstance(alphabet,str) or len(alphabet)!=26 or set(alphabet)!=set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            raise ValueError("invalid model alphabet")
        _integer(model["order"],"ngram order",1,6)
        for field in ("p","q"):
            _integer(model[field],field,1,1<<1075)
        counts = model["counts"]
        if not isinstance(counts,dict) or len(counts)>2000000 or any(not isinstance(k,str) or len(k)!=model["order"] or any(c not in alphabet for c in k) or type(v) is not int or v<0 for k,v in counts.items()):
            raise ValueError("invalid model counts")
    entries = 0
    for f in factors:
        if not isinstance(f,dict):
            raise ValueError("factor must be an object")
        scope = f.get("scope")
        if not isinstance(scope,list) or any(type(i) is not int or not 0<=i<len(domains) for i in scope) or scope!=sorted(set(scope)):
            raise ValueError("factor scope must be sorted distinct variable indices")
        _integer(f.get("power",1),"factor power",1,4096)
        if f.get("kind")=="table":
            if set(f)-{"kind","scope","values","power"}:
                raise ValueError("unknown table field")
            values = f.get("values")
            size = math.prod(domains[i] for i in scope)
            if not isinstance(values,list) or len(values)!=size or any(type(v) is not int or v<0 for v in values):
                raise ValueError("table must cover its Cartesian domain with nonnegative integers")
            entries += len(values)
        elif f.get("kind")=="ngram":
            if model is None or set(f)-{"kind","scope","base","columns","power"}:
                raise ValueError("ngram requires an explicit saved model")
            base,columns = f.get("base"),f.get("columns")
            if not isinstance(base,list) or len(base)!=model["order"] or any(type(v) is not int or not 0<=v<26 for v in base):
                raise ValueError("invalid ngram base")
            if not isinstance(columns,list) or len(columns)!=len(scope) or any(not isinstance(c,list) or len(c)!=len(base) or any(type(v) is not int or not 0<=v<26 for v in c) for c in columns):
                raise ValueError("invalid ngram columns")
        else:
            raise ValueError("unknown factor kind")
    if entries>2000000:
        raise ValueError("explicit factor tables exceed2million entries")
    return tuple(domains), factors


def lazy_ngram_problem(solution,model,excluded_positions=()):
    """Build only affine window descriptions; never a Cartesian score table."""
    from .language import CharacterNgramModel
    if not isinstance(model,CharacterNgramModel):
        raise ValueError("a validated corpus model is required")
    affine = solution.affine_plaintext()
    alphabet,base,columns,domains = (affine[k] for k in ("alphabet","base","columns","domains"))
    if set(model.alphabet)!=set(alphabet) or model.normalization not in ("identity","upper-single"):
        raise ValueError("model normalization or alphabet incompatible")
    mask = tuple(excluded_positions)
    if any(type(i) is not int or not 0<=i<len(base) for i in mask):
        raise ValueError("invalid original-position mask")
    mask = set(mask)
    factors,windows,intern = [],[],{}
    raw_dense = 0
    for start in range(len(base)-model.order+1):
        window = list(range(start,start+model.order))
        if any(i in mask for i in window):
            continue
        scope = [i for i,col in enumerate(columns) if any(col[j] for j in window)]
        factor = {"kind":"ngram","scope":scope,"base":[base[j] for j in window],
                  "columns":[[columns[i][j] for j in window] for i in scope],"power":1}
        key = _canonical(factor)
        if key in intern:
            factors[intern[key]]["power"] += 1
        else:
            intern[key] = len(factors)
            factors.append(factor)
        windows.append(window)
        raw_dense += math.prod(domains[i] for i in scope)
    p,q = float(model.alpha).as_integer_ratio()
    problem = {"schema":SCHEMA,"domains":list(domains),"factors":factors,
               "model":{"alphabet":alphabet,"counts":dict(model.counts),"p":p,"q":q,"order":model.order,"id":model.model_id},
               "metadata":{"windows":len(windows),"window_positions":windows,"excluded_positions":sorted(mask),
                           "score_available":bool(windows),"dense_entries_avoided":raw_dense,
                           "distinct_factors":len(factors),"merged_duplicate_windows":len(windows)-len(factors),
                           "objective":"exact product(count*q+p); denominator common within this family/model/mask"}}
    _validate(problem)
    return problem


class _Evaluator:
    def __init__(self,problem,cache_limit,local_limit):
        self.domains,self.factors = _validate(problem)
        self.model = problem.get("model")
        self.cache_limit,self.local_limit = cache_limit,local_limit
        self.cache = {}
        self.stats = {"cache_hits":0,"bound_evaluations":0,"exact_local_completions":0,"relaxed_bounds":0,"observed_grams_checked":0}
        self.grams = [] if self.model is None else sorted(self.model["counts"].items(),key=lambda kv:(-kv[1],kv[0]))

    def _value(self,f,values):
        if f["kind"]=="table":
            i = 0
            for variable,value in zip(f["scope"],values):
                i = i*self.domains[variable]+value
            return f["values"][i]
        text = "".join(self.model["alphabet"][(b+sum(col[j]*v for col,v in zip(f["columns"],values)))%26]
                       for j,b in enumerate(f["base"]))
        return self.model["counts"].get(text,0)*self.model["q"]+self.model["p"]

    def local_upper(self,number,assignment):
        f = self.factors[number]
        values = tuple(assignment[i] for i in f["scope"])
        cache_key = (number,values)
        if cache_key in self.cache:
            self.stats["cache_hits"] += 1
            return self.cache[cache_key]
        self.stats["bound_evaluations"] += 1
        unresolved = [j for j,v in enumerate(values) if v<0]
        size = math.prod(self.domains[f["scope"][j]] for j in unresolved)
        if not unresolved:
            upper = self._value(f,values)
        elif f["kind"]=="table" or size<=self.local_limit:
            upper = 0
            for point in product(*(range(self.domains[f["scope"][j]]) for j in unresolved)):
                completed = list(values)
                for j,v in zip(unresolved,point):
                    completed[j] = v
                upper = max(upper,self._value(f,completed))
                self.stats["exact_local_completions"] += 1
        else:
            # Per-position reachable residues ignore their mutual correlations.
            # This is a superset of real grams, hence a rigorous upper bound.
            self.stats["relaxed_bounds"] += 1
            reachable = []
            for position,base in enumerate(f["base"]):
                residues = {base}
                for j,(variable,value) in enumerate(zip(f["scope"],values)):
                    options = range(self.domains[variable]) if value<0 else (value,)
                    residues = {(x+f["columns"][j][position]*v)%26 for x in residues for v in options}
                reachable.append({self.model["alphabet"][i] for i in residues})
            maximum = 0
            for gram,count in self.grams:
                self.stats["observed_grams_checked"] += 1
                if all(c in allowed for c,allowed in zip(gram,reachable)):
                    maximum = count
                    break
            upper = maximum*self.model["q"]+self.model["p"]
        if len(self.cache)<self.cache_limit:
            self.cache[cache_key] = upper
        return upper

    def upper(self,assignment):
        return math.prod(self.local_upper(i,assignment)**f.get("power",1) for i,f in enumerate(self.factors))


def score_assignment(problem,assignment):
    evaluator = _Evaluator(problem,0,1)
    if not isinstance(assignment,(list,tuple)) or len(assignment)!=len(evaluator.domains) or any(type(v) is not int or not 0<=v<d for v,d in zip(assignment,evaluator.domains)):
        raise ValueError("invalid complete assignment")
    return evaluator.upper(assignment)


def _identity(problem,ordering,local_limit):
    root = Path(__file__).resolve().parent
    return {"problem_sha256":_digest(problem),"ordering":ordering,"local_exact_limit":local_limit,
            "sources":{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ("search_runtime.py","language.py")},
            "version":"adaptive-search-v1; lexicographically smallest original assignment"}


def optimize_lazy(problem,*,max_nodes=10000,time_limit_seconds=10,max_frontier=10000,
                  max_cache_entries=100000,local_exact_limit=64,ordering="impact",
                  resume_path=None,checkpoint_path=None):
    """Return exact incumbent/bound, optionally preserving the live frontier.

    Caps are cooperative (checked between node expansions). Changing a cap on
    resume is allowed; changing the objective, source, order or bound semantics
    is rejected. Caches are disposable and need not be saved for correctness.
    """
    _integer(max_nodes,"max_nodes",0,1000000)
    _integer(max_frontier,"max_frontier",1,100000)
    _integer(max_cache_entries,"max_cache_entries",0,1000000)
    _integer(local_exact_limit,"local_exact_limit",1,100000)
    if isinstance(time_limit_seconds,bool) or not isinstance(time_limit_seconds,(int,float)) or not math.isfinite(time_limit_seconds) or not 0<time_limit_seconds<=600:
        raise ValueError("time limit must be in (0,600]")
    if ordering not in ("impact","natural"):
        raise ValueError("ordering must be impact or natural")
    if checkpoint_path is not None and Path(checkpoint_path).exists():
        raise ValueError("checkpoint output exists; choose a fresh path")
    started = time.monotonic()
    evaluator = _Evaluator(problem,max_cache_entries,local_exact_limit)
    domains = evaluator.domains
    identity = _identity(problem,ordering,local_exact_limit)
    best = tuple(0 for _ in domains)
    best_score = evaluator.upper(best)
    root = tuple(-1 for _ in domains)
    frontier = [(-evaluator.upper(root),root)]
    previous_nodes = 0
    if resume_path is not None:
        record = _strict_load(resume_path)
        if not isinstance(record,dict) or set(record)!={"payload","sha256"} or _digest(record["payload"])!=record["sha256"]:
            raise ValueError("checkpoint integrity check failed")
        payload = record["payload"]
        if not isinstance(payload,dict) or set(payload)!={"schema","identity","best","score_hex","frontier","nodes_total"} or payload["schema"]!="kryptos.search-frontier.v1" or payload["identity"]!=identity:
            raise ValueError("checkpoint belongs to a different problem, source or search convention")
        best = tuple(payload["best"])
        best_score = score_assignment(problem,best)
        if not isinstance(payload["score_hex"],str) or hex(best_score)!=payload["score_hex"]:
            raise ValueError("checkpoint incumbent score changed")
        previous_nodes = _integer(payload["nodes_total"],"prior nodes",0,10**18)
        if not isinstance(payload["frontier"],list) or len(payload["frontier"])>100000:
            raise ValueError("invalid saved frontier")
        frontier,seen = [],set()
        for row in payload["frontier"]:
            if not isinstance(row,dict) or set(row)!={"assignment","upper_hex"}:
                raise ValueError("invalid frontier node")
            point = tuple(row["assignment"])
            if len(point)!=len(domains) or any(type(v) is not int or not -1<=v<d for v,d in zip(point,domains)) or point in seen:
                raise ValueError("invalid or duplicate frontier assignment")
            seen.add(point)
            bound = evaluator.upper(point)
            if not isinstance(row["upper_hex"],str) or hex(bound)!=row["upper_hex"]:
                raise ValueError("saved bound does not match recomputation")
            frontier.append((-bound,point))
        heapq.heapify(frontier)
    if len(frontier)>max_frontier:
        raise ValueError("saved frontier exceeds the requested memory cap")
    def lex_min(point):
        return tuple(max(0,v) for v in point)
    def choose(point):
        unknown = [i for i,v in enumerate(point) if v<0]
        if ordering=="natural":
            return unknown[0]
        def impact(i):
            involved = [f for f in evaluator.factors if i in f["scope"]]
            return (sum(sum(point[j]>=0 for j in f["scope"]) for f in involved),
                    sum(f.get("power",1) for f in involved),-domains[i],-i)
        return max(unknown,key=impact)
    nodes=leaves=pruned=0
    stop="exhausted"
    while frontier:
        if nodes>=max_nodes:
            stop="node_limit"
            break
        if time.monotonic()-started>=time_limit_seconds:
            stop="time_limit"
            break
        neg,point = heapq.heappop(frontier)
        bound=-neg
        nodes+=1
        if bound<best_score or (bound==best_score and lex_min(point)>=best):
            pruned+=1
            continue
        if -1 not in point:
            leaves+=1
            if bound>best_score or (bound==best_score and point<best):
                best_score,best=bound,point
            continue
        variable=choose(point)
        children=[]
        for value in range(domains[variable]):
            child=list(point)
            child[variable]=value
            child=tuple(child)
            upper=evaluator.upper(child)
            if upper<best_score or (upper==best_score and lex_min(child)>=best):
                pruned+=1
            else:
                children.append((-upper,child))
        if len(frontier)+len(children)>max_frontier:
            heapq.heappush(frontier,(neg,point))
            stop="frontier_limit"
            break
        for child in children:
            heapq.heappush(frontier,child)
    upper=max(best_score,-frontier[0][0] if frontier else best_score)
    tie=upper==best_score and not any(-neg>=best_score and lex_min(point)<best for neg,point in frontier)
    if checkpoint_path is not None:
        payload={"schema":"kryptos.search-frontier.v1","identity":identity,"best":list(best),"score_hex":hex(best_score),
                 "frontier":[{"assignment":list(point),"upper_hex":hex(-neg)} for neg,point in sorted(frontier)],"nodes_total":previous_nodes+nodes}
        checkpoint=Path(checkpoint_path)
        checkpoint.parent.mkdir(parents=True,exist_ok=True)
        with checkpoint.open("x",encoding="utf-8") as stream:
            json.dump({"payload":payload,"sha256":_digest(payload)},stream,indent=2,allow_nan=False)
    return {"assignment":list(best),"score":best_score,"lower_bound":best_score,"upper_bound":upper,
            "optimal":upper==best_score,"tie_break_proven":tie,"complete":not frontier,
            "stop_reason":stop,"nodes":nodes,"nodes_total":previous_nodes+nodes,"leaf_nodes":leaves,"pruned_nodes":pruned,
            "frontier_nodes":len(frontier),"cache_entries":len(evaluator.cache),"work":evaluator.stats,
            "assignment_space_size":math.prod(domains),"identity":identity,"resumed":resume_path is not None,
            "checkpoint_written":str(checkpoint_path) if checkpoint_path is not None else None,
            "bounds":{"max_nodes":max_nodes,"max_frontier":max_frontier,"max_cache_entries":max_cache_entries,
                      "local_exact_limit":local_exact_limit,"time_limit_seconds":time_limit_seconds},
            "ordering":ordering,"runtime_seconds":time.monotonic()-started,
            "interpretation":"Exact bounds for this product objective only. Lazy letter-domain bounds may ignore correlations; pruning remains admissible. No authentication."}
