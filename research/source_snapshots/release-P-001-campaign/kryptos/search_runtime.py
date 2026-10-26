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

from .correlated_bound import CorrelatedNgramBound

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


def factor_partition(factors, group_size=0):
    """Deterministic disjoint groups; every factor appears exactly once.

    Greedily join overlapping scopes, with original factor index breaking ties.
    Grouping is fixed before search and does not depend on incumbent scores.
    """
    _integer(group_size,"factor_group_size",0,8)
    remaining=set(range(len(factors)))
    groups=[]
    while remaining:
        first=min(remaining)
        remaining.remove(first)
        group=[first]
        scope=set(factors[first]["scope"])
        while remaining and len(group)<max(1,group_size):
            chosen=min(remaining,key=lambda i:(-len(scope.intersection(factors[i]["scope"])),i))
            if not scope.intersection(factors[chosen]["scope"]):
                break
            group.append(chosen)
            remaining.remove(chosen)
            scope.update(factors[chosen]["scope"])
        groups.append(tuple(group))
    return tuple(groups)


def evaluate_factor(f, values, domains, model):
    """Evaluate one already-validated factor before applying its power."""
    if f["kind"] == "table":
        i = 0
        for variable, value in zip(f["scope"], values):
            i = i * domains[variable] + value
        return f["values"][i]
    text = "".join(model["alphabet"][(b + sum(col[j] * v for col, v in zip(f["columns"], values))) % 26]
                   for j, b in enumerate(f["base"]))
    return model["counts"].get(text, 0) * model["q"] + model["p"]


class _Evaluator:
    def __init__(self,problem,cache_limit,local_limit,factor_group_size=0,group_exact_limit=4096,
                 elimination_bound="off", elimination_bucket_entries=256,
                 elimination_max_entries=20000, elimination_max_operations=200000,
                 cheap_bound_first=False):
        self.domains,self.factors = _validate(problem)
        self.problem = problem
        self.elimination_bound = elimination_bound
        self.elimination_options = dict(bucket_entries=elimination_bucket_entries,
            max_entries=elimination_max_entries, max_operations=elimination_max_operations)
        self.model = problem.get("model")
        self.cache_limit,self.local_limit = cache_limit,local_limit
        self.cache = {}
        self.groups=factor_partition(self.factors,factor_group_size)
        self.group_exact_limit=_integer(group_exact_limit,"group_exact_limit",1,100000)
        self.stats = {"cache_hits":0,"bound_evaluations":0,"exact_local_completions":0,"relaxed_bounds":0,"correlated_bounds":0,"observed_grams_checked":0,
                      "group_bounds":0,"group_exact_completions":0,"group_fallbacks":0,
                      "elimination_attempts":0,"elimination_tightenings":0,"elimination_fallbacks":0,
                      "elimination_operations":0,"elimination_factor_evaluations":0,
                      "factor_evaluations":0,"cheap_preparation_entries":0,
                      "cheap_bound_calls":0,"cheap_bound_rejections":0,
                      "cheap_factor_checks":0,"cheap_cached_factor_hits":0,
                      "residual_witness_factor_evaluations":0}
        self.grams = [] if self.model is None else sorted(self.model["counts"].items(),key=lambda kv:(-kv[1],kv[0]))
        self.correlated = None if self.model is None else CorrelatedNgramBound(self.model["alphabet"],self.model["counts"],self.model["p"],self.model["q"])
        self.global_factor_bounds = None
        if cheap_bound_first:
            model_max = 0
            if self.model is not None:
                self.stats["cheap_preparation_entries"] += len(self.model["counts"])
                model_max = max(self.model["counts"].values(), default=0)*self.model["q"]+self.model["p"]
            self.global_factor_bounds = []
            for factor in self.factors:
                if factor["kind"] == "table":
                    self.stats["cheap_preparation_entries"] += len(factor["values"])
                    bound = max(factor["values"])
                else:
                    bound = model_max
                self.global_factor_bounds.append(bound ** factor.get("power", 1))
            self.global_upper = math.prod(self.global_factor_bounds)

    def _value(self,f,values):
        self.stats["factor_evaluations"] += 1
        return evaluate_factor(f, values, self.domains, self.model)

    def cheap_reject(self, assignment, incumbent_score, incumbent):
        """Threshold-only gate; never supplies a persisted frontier bound.

        Replace universal maxima by already cached or fully fixed factor values.
        Every intermediate product is admissible. Equality is safe only when
        the branch's lexical minimum cannot improve the incumbent.
        """
        if self.global_factor_bounds is None:
            return False
        self.stats["cheap_bound_calls"] += 1
        lexical_cannot_improve = tuple(max(0, v) for v in assignment) >= incumbent
        def rejects(bound):
            return bound < incumbent_score or (bound == incumbent_score and lexical_cannot_improve)
        upper = self.global_upper
        if rejects(upper):
            self.stats["cheap_bound_rejections"] += 1
            return True
        for number, factor in enumerate(self.factors):
            self.stats["cheap_factor_checks"] += 1
            values = tuple(assignment[v] for v in factor["scope"])
            key = (number, values)
            if key in self.cache:
                bound = self.cache[key]
                self.stats["cheap_cached_factor_hits"] += 1
            elif -1 not in values:
                bound = self._value(factor, values)
            else:
                continue
            global_bound = self.global_factor_bounds[number]
            # A zero universal factor already makes upper=0. No division by
            # zero is needed, and a zero score is not an infeasible branch.
            if global_bound:
                upper = (upper // global_bound) * bound ** factor.get("power", 1)
            if rejects(upper):
                self.stats["cheap_bound_rejections"] += 1
                return True
        return False

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
            exact=self.correlated.upper(f["base"],f["columns"],[self.domains[i] for i in f["scope"]],values)
            if exact["applicable"]:
                self.stats["correlated_bounds"]+=1
                self.stats["observed_grams_checked"]+=exact["observed_grams_checked"]
                upper=exact["upper"]
                if len(self.cache)<self.cache_limit:
                    self.cache[cache_key]=upper
                return upper
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
        bounds=[]
        for group in self.groups:
            if len(group)==1:
                i=group[0]
                bounds.append(self.local_upper(i,assignment)**self.factors[i].get("power",1))
                continue
            scope=tuple(sorted({v for i in group for v in self.factors[i]["scope"]}))
            key=("group",group,tuple(assignment[v] for v in scope))
            if key in self.cache:
                self.stats["cache_hits"]+=1
                bounds.append(self.cache[key])
                continue
            unresolved=tuple(v for v in scope if assignment[v]<0)
            size=math.prod(self.domains[v] for v in unresolved)
            if size>self.group_exact_limit:
                self.stats["group_fallbacks"]+=1
                upper=math.prod(self.local_upper(i,assignment)**self.factors[i].get("power",1) for i in group)
            else:
                self.stats["group_bounds"]+=1
                upper=0
                point=list(assignment)
                for values in product(*(range(self.domains[v]) for v in unresolved)):
                    for v,value in zip(unresolved,values):
                        point[v]=value
                    value=math.prod(self._value(self.factors[i],tuple(point[v] for v in self.factors[i]["scope"]))**self.factors[i].get("power",1) for i in group)
                    upper=max(upper,value)
                    self.stats["group_exact_completions"]+=1
            if len(self.cache)<self.cache_limit:
                self.cache[key]=upper
            bounds.append(upper)
        upper = math.prod(bounds)
        if self.elimination_bound == "mini_bucket" and upper and any(v < 0 for v in assignment):
            key = ("mini_bucket", tuple(assignment))
            if key in self.cache:
                self.stats["cache_hits"] += 1
                return min(upper, self.cache[key])
            from .factor_decomposition import mini_bucket_upper
            report = mini_bucket_upper(self.problem, assignment, **self.elimination_options)
            self.stats["elimination_attempts"] += 1
            self.stats["elimination_operations"] += report["work"]["operations"]
            self.stats["elimination_factor_evaluations"] += report["work"]["factor_evaluations"]
            if report["bound_available"]:
                if report["upper_bound"] < upper:
                    self.stats["elimination_tightenings"] += 1
                upper = min(upper, report["upper_bound"])
            else:
                self.stats["elimination_fallbacks"] += 1
            if len(self.cache) < self.cache_limit:
                self.cache[key] = upper
        return upper


def score_assignment(problem,assignment):
    evaluator = _Evaluator(problem,0,1)
    if not isinstance(assignment,(list,tuple)) or len(assignment)!=len(evaluator.domains) or any(type(v) is not int or not 0<=v<d for v,d in zip(assignment,evaluator.domains)):
        raise ValueError("invalid complete assignment")
    return evaluator.upper(assignment)


def _identity(problem,ordering,local_limit,groups=(),group_exact_limit=4096,
              decomposition="off", decomposition_max_entries=20000, decomposition_max_operations=200000,
              elimination_bound="off", elimination_bucket_entries=256,
              elimination_max_entries=20000, elimination_max_operations=200000,
              residual_cache="off", residual_cache_max_entries=256,
              residual_cache_max_assignments=256, residual_cache_max_operations=200000,
              cheap_bound_first=False):
    root = Path(__file__).resolve().parent
    return {"problem_sha256":_digest(problem),"ordering":ordering,"local_exact_limit":local_limit,
            "factor_groups":[list(g) for g in groups],"group_exact_limit":group_exact_limit,
            "decomposition":decomposition,"decomposition_max_entries":decomposition_max_entries,
            "decomposition_max_operations":decomposition_max_operations,
            "elimination_bound":elimination_bound,"elimination_bucket_entries":elimination_bucket_entries,
            "elimination_max_entries":elimination_max_entries,"elimination_max_operations":elimination_max_operations,
            "residual_cache":residual_cache,"residual_cache_max_entries":residual_cache_max_entries,
            "residual_cache_max_assignments":residual_cache_max_assignments,
            "residual_cache_max_operations":residual_cache_max_operations,"cheap_bound_first":cheap_bound_first,
            "sources":{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ("search_runtime.py","language.py","correlated_bound.py","factor_decomposition.py","guided_search.py")},
            "version":"adaptive-search-v5; invocation-local verified component reuse; threshold-only cheap gates; full persisted bounds; original-coordinate lexical ties"}


def optimize_lazy(problem,*,max_nodes=10000,time_limit_seconds=10,max_frontier=10000,
                  max_cache_entries=100000,local_exact_limit=64,ordering="impact",
                  resume_path=None,checkpoint_path=None,factor_group_size=0,group_exact_limit=4096,
                  initial_assignments=(),elapsed_before_seconds=0,decomposition="off",
                  decomposition_max_entries=20000,decomposition_max_operations=200000,
                  elimination_bound="off",elimination_bucket_entries=256,
                  elimination_max_entries=20000,elimination_max_operations=200000,
                  residual_cache="off",residual_cache_max_entries=256,
                  residual_cache_max_assignments=256,residual_cache_max_operations=200000,
                  cheap_bound_first=False):
    """Return exact incumbent/bound, optionally preserving the live frontier.

    Caps are cooperative (checked between node expansions). Changing a cap on
    resume is allowed; changing the objective, source, order or bound semantics
    is rejected. Caches are disposable and need not be saved for correctness.
    """
    _integer(max_nodes,"max_nodes",0,1000000)
    _integer(max_frontier,"max_frontier",1,100000)
    _integer(max_cache_entries,"max_cache_entries",0,1000000)
    _integer(local_exact_limit,"local_exact_limit",1,100000)
    _integer(factor_group_size,"factor_group_size",0,8)
    _integer(group_exact_limit,"group_exact_limit",1,100000)
    if decomposition not in ("off", "auto"):
        raise ValueError("decomposition must be off or auto")
    _integer(decomposition_max_entries,"decomposition_max_entries",1,1000000)
    _integer(decomposition_max_operations,"decomposition_max_operations",1,10000000)
    if elimination_bound not in ("off", "mini_bucket"):
        raise ValueError("elimination_bound must be off or mini_bucket")
    _integer(elimination_bucket_entries,"elimination_bucket_entries",1,100000)
    _integer(elimination_max_entries,"elimination_max_entries",1,1000000)
    _integer(elimination_max_operations,"elimination_max_operations",1,10000000)
    if residual_cache not in ("off", "components"):
        raise ValueError("residual_cache must be off or components")
    _integer(residual_cache_max_entries,"residual_cache_max_entries",0,10000)
    _integer(residual_cache_max_assignments,"residual_cache_max_assignments",1,100000)
    _integer(residual_cache_max_operations,"residual_cache_max_operations",1,10000000)
    if type(cheap_bound_first) is not bool:
        raise ValueError("cheap_bound_first must be boolean")
    if isinstance(elapsed_before_seconds,bool) or not isinstance(elapsed_before_seconds,(int,float)) or not math.isfinite(elapsed_before_seconds) or elapsed_before_seconds<0:
        raise ValueError("elapsed_before_seconds must be finite and nonnegative")
    if not isinstance(initial_assignments,(list,tuple)) or len(initial_assignments)>100:
        raise ValueError("at most100 complete assignment seeds are allowed")
    if isinstance(time_limit_seconds,bool) or not isinstance(time_limit_seconds,(int,float)) or not math.isfinite(time_limit_seconds) or not 0<time_limit_seconds<=600:
        raise ValueError("time limit must be in (0,600]")
    if ordering not in ("impact","natural"):
        raise ValueError("ordering must be impact or natural")
    if checkpoint_path is not None and Path(checkpoint_path).exists():
        raise ValueError("checkpoint output exists; choose a fresh path")
    actual_started = time.monotonic()
    def elapsed():
        # Keep earlier work separate: backdating a large clock value can round
        # away a small prior duration and silently restore spent budget.
        return elapsed_before_seconds + (time.monotonic() - actual_started)
    evaluator = _Evaluator(problem,max_cache_entries,local_exact_limit,factor_group_size,group_exact_limit,
        elimination_bound,elimination_bucket_entries,elimination_max_entries,elimination_max_operations,cheap_bound_first)
    residual_solver = None
    if residual_cache == "components":
        from .factor_decomposition import ResidualComponentCache
        residual_solver = ResidualComponentCache(problem,max_entries=residual_cache_max_entries,
            max_assignments=residual_cache_max_assignments,max_operations=residual_cache_max_operations)
    domains = evaluator.domains
    identity = _identity(problem,ordering,local_exact_limit,evaluator.groups,group_exact_limit,
                         decomposition,decomposition_max_entries,decomposition_max_operations,
                         elimination_bound,elimination_bucket_entries,elimination_max_entries,elimination_max_operations,
                         residual_cache,residual_cache_max_entries,residual_cache_max_assignments,
                         residual_cache_max_operations,cheap_bound_first)
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
    seed_scores=[]
    for seed in initial_assignments:
        point=tuple(seed) if isinstance(seed,(list,tuple)) else seed
        value=score_assignment(problem,point)  # validates the domain, never trusts a supplied score
        seed_scores.append({"assignment":list(point),"score_hex":hex(value)})
        if value>best_score or (value==best_score and point<best):
            best,best_score=point,value
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
    nodes=leaves=pruned=requeued=0
    decomposition_report={"mode":decomposition,"attempts":0,"solved_residuals":0,"fallbacks":{},
                          "operations":0,"factor_evaluations":0,"max_separator_variables":0,
                          "max_components":0,"peak_planned_entries":0}
    stop="exhausted"
    while frontier:
        if nodes>=max_nodes:
            stop="node_limit"
            break
        if elapsed()>=time_limit_seconds:
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
        if residual_solver is not None and elapsed()<time_limit_seconds:
            reduced=residual_solver.solve(point,time_limit_seconds=max(1e-9,time_limit_seconds-elapsed()))
            if reduced["complete"]:
                answer=tuple(reduced["assignment"])
                if (len(answer)!=len(domains) or any(type(v) is not int or not 0<=v<d for v,d in zip(answer,domains))
                        or any(v>=0 and answer[i]!=v for i,v in enumerate(point))):
                    raise AssertionError("residual witness violates its original domain")
                value=1
                for factor in evaluator.factors:
                    evaluator.stats["residual_witness_factor_evaluations"]+=1
                    value*=evaluator._value(factor,tuple(answer[v] for v in factor["scope"]))**factor.get("power",1)
                if value!=reduced["score"]:
                    raise AssertionError("residual witness failed original factor verification")
                if value>best_score or (value==best_score and answer<best):
                    best_score,best=value,answer
                continue
            if elapsed()>=time_limit_seconds:
                heapq.heappush(frontier,(neg,point))
                requeued+=1
                stop="time_limit"
                break
        if decomposition=="auto" and decomposition_report["operations"]<decomposition_max_operations and elapsed()<time_limit_seconds:
            from .factor_decomposition import exact_decomposition
            reduced=exact_decomposition(problem,point,max_entries=decomposition_max_entries,
                max_operations=decomposition_max_operations-decomposition_report["operations"],
                time_limit_seconds=max(1e-9,time_limit_seconds-elapsed()))
            decomposition_report["attempts"]+=1
            decomposition_report["operations"]+=reduced["work"]["operations"]
            decomposition_report["factor_evaluations"]+=reduced["work"]["factor_evaluations"]
            decomposition_report["max_separator_variables"]=max(decomposition_report["max_separator_variables"],reduced["work"]["max_separator_variables"])
            decomposition_report["max_components"]=max(decomposition_report["max_components"],reduced["work"]["components"])
            decomposition_report["peak_planned_entries"]=max(decomposition_report["peak_planned_entries"],reduced["work"]["planned_entries"])
            if reduced["complete"]:
                answer=tuple(reduced["assignment"])
                # Verify the returned witness against the original factors.
                value=evaluator.upper(answer)
                if value!=reduced["score"] or any(v>=0 and answer[i]!=v for i,v in enumerate(point)):
                    raise AssertionError("decomposition witness failed original factor verification")
                if value>best_score or (value==best_score and answer<best):
                    best_score,best=value,answer
                decomposition_report["solved_residuals"]+=1
                continue
            reason=reduced["stop_reason"]
            decomposition_report["fallbacks"][reason]=decomposition_report["fallbacks"].get(reason,0)+1
            if elapsed()>=time_limit_seconds:
                heapq.heappush(frontier,(neg,point))
                requeued+=1
                stop="time_limit"
                break
        variable=choose(point)
        children=[]
        for value in range(domains[variable]):
            child=list(point)
            child[variable]=value
            child=tuple(child)
            if cheap_bound_first and evaluator.cheap_reject(child,best_score,best):
                pruned+=1
                continue
            upper=evaluator.upper(child)
            if upper<best_score or (upper==best_score and lex_min(child)>=best):
                pruned+=1
            else:
                children.append((-upper,child))
        if len(frontier)+len(children)>max_frontier:
            heapq.heappush(frontier,(neg,point))
            requeued+=1
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
            "requeued_nodes":requeued,"frontier_progress_nodes":nodes-requeued,
            "frontier_nodes":len(frontier),"cache_entries":len(evaluator.cache),"work":evaluator.stats,
            "decomposition":decomposition_report,
            "residual_cache":{"mode":residual_cache,"entries":len(residual_solver.cache) if residual_solver else 0,
                              "work":dict(residual_solver.stats) if residual_solver else {},
                              "scope":"frozen original objective and this invocation only; never restored from checkpoints",
                              "zero_score_interpretation":"all completions score zero, not infeasible"},
            "assignment_space_size":math.prod(domains),"identity":identity,"resumed":resume_path is not None,
            "verified_seeds":seed_scores,"elapsed_before_seconds":elapsed_before_seconds,
            "checkpoint_written":str(checkpoint_path) if checkpoint_path is not None else None,
            "bounds":{"max_nodes":max_nodes,"max_frontier":max_frontier,"max_cache_entries":max_cache_entries,
                      "local_exact_limit":local_exact_limit,"time_limit_seconds":time_limit_seconds,
                      "factor_group_size":factor_group_size,"group_exact_limit":group_exact_limit,
                      "decomposition":decomposition,"decomposition_max_entries":decomposition_max_entries,
                      "decomposition_max_operations":decomposition_max_operations,
                      "elimination_bound":elimination_bound,"elimination_bucket_entries":elimination_bucket_entries,
                      "elimination_max_entries":elimination_max_entries,"elimination_max_operations":elimination_max_operations,
                      "residual_cache":residual_cache,"residual_cache_max_entries":residual_cache_max_entries,
                      "residual_cache_max_assignments":residual_cache_max_assignments,
                      "residual_cache_max_operations":residual_cache_max_operations,"cheap_bound_first":cheap_bound_first},
            "ordering":ordering,"runtime_seconds":elapsed(),
            "interpretation":"Exact bounds for this product objective only. Lazy letter-domain bounds may ignore correlations; pruning remains admissible. No authentication."}
