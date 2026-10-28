"""Bounded exact ranking of explicit column-order/repeating-key completions.

This is a separate enumerator: the counting-only joint solver is unchanged.
Exhaustion or admissible strict-score pruning certifies top-k over the declared
family. Pruned branches are not counted as evaluated assignments. Crib positions
are masked. A JSON checkpoint stores the unresolved route/key frontier.
"""
from collections import Counter, defaultdict
import hashlib
from itertools import product
import json
import math
from pathlib import Path
import string
import time

from . import columnar
from .explanations import replay_recipe
from .language import CharacterNgramModel
from .joint_ranked_helpers import (FULL, values, singleton_values, equivalent_chunks,
                                    reduce_joint, SharedKeyBound, symmetry_record)

ALPHABETS = {"standard": string.ascii_uppercase, "kryptos": "KRYPTOSABCDEFGHIJLMNQUVWXZ"}


class _Limit(Exception):
    pass


class _Budget:
    def __init__(self, states, seconds):
        self.limit = states
        self.deadline = time.monotonic() + seconds
        self.work = defaultdict(int)

    def tick(self, name):
        if time.monotonic() >= self.deadline:
            raise _Limit("time_limit_seconds")
        if self.work["states"] >= self.limit:
            raise _Limit("max_states")
        self.work["states"] += 1
        self.work[name] += 1


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def rank_joint_columnar(ciphertext, cribs, *, model, period, order="ST", cipher="vigenere",
                        alphabet="kryptos", width=None, cells=None,
                        column_direction="top_to_bottom", top=20,
                        max_segmentations=2048, max_states=200000,
                        max_orders=5000, max_evaluations=100000,
                        time_limit_seconds=5, score_mask=None, pruning="off",
                        resume_path=None, checkpoint_path=None, max_frontier=20000,
                        propagation="off", early_segmentation=False, branching="prefix",
                        score_bound="independent", symmetry="off", max_bound_cache_entries=2048):
    """Return distinct-plaintext top-k and conservative coverage metadata.

    Counted keys include only phases used by this finite message. Unvisited
    declared key slots receive the alphabet's zero symbol in each representative
    recipe and are identified separately, not counted as recovered values.
    """
    started = time.monotonic()
    ciphertext, known, occupied, labels, columns = columnar._inputs(
        ciphertext, cribs, width, cells, column_direction)
    if len(ciphertext) > 512:
        raise ValueError("ranked joint messages are limited to512 letters")
    for value, name, low, high in ((period, "period", 1, 256), (top, "top", 1, 100),
        (max_segmentations, "max_segmentations", 1, 100000),
        (max_states, "max_states", 1, 5000000), (max_orders, "max_orders", 1, 100000),
        (max_evaluations, "max_evaluations", 1, 1000000),
        (max_frontier, "max_frontier", 1, 100000)):
        columnar._integer(value, name, low, high)
    if pruning not in ("off", "admissible"):
        raise ValueError("pruning must be off or admissible")
    if propagation not in ("off","fixed_point","relational") or branching not in ("prefix","constrained") or symmetry not in ("off","identical_chunks"):
        raise ValueError("invalid joint propagation, branching or symmetry option")
    if type(early_segmentation) is not bool:
        raise ValueError("early_segmentation must be boolean")
    if score_bound not in ("independent","shared_key","matching") or score_bound in ("shared_key","matching") and pruning!="admissible":
        raise ValueError("shared_key/matching bounds require pruning=admissible")
    columnar._integer(max_bound_cache_entries,"max_bound_cache_entries",0,10000)
    joint_mode=propagation!="off" or branching!="prefix" or symmetry!="off"
    options=dict(propagation=propagation,early_segmentation=early_segmentation,
        branching=branching,score_bound=score_bound,symmetry=symmetry)
    if checkpoint_path is not None and Path(checkpoint_path).exists():
        raise ValueError("checkpoint output exists; choose a fresh path")
    if order not in ("ST", "TS") or cipher not in ("vigenere", "beaufort", "variant"):
        raise ValueError("unsupported layer order or cipher equation")
    if not isinstance(alphabet, str):
        raise ValueError("alphabet must be a known uppercase permutation")
    alphabet = ALPHABETS.get(alphabet, alphabet)
    if len(alphabet) != 26 or set(alphabet) != set(string.ascii_uppercase):
        raise ValueError("alphabet must be a permutation of uppercase A-Z")
    if not isinstance(model, CharacterNgramModel) or set(model.alphabet) != set(string.ascii_uppercase) or len(model.alphabet) != 26 or model.order > 6:
        raise ValueError("supply a validated A-Z character model of order1..6")
    if type(time_limit_seconds) not in (int, float) or not math.isfinite(time_limit_seconds) or not 0 < time_limit_seconds <= 600:
        raise ValueError("time limit must be finite and in(0,600]")
    n, w, used = len(ciphertext), len(columns), min(period, len(ciphertext))
    if score_mask is None:
        score_mask = sorted(known)
    if not isinstance(score_mask, (list, tuple)) or any(type(i) is not int or not 0 <= i < n for i in score_mask) or len(set(score_mask)) != len(score_mask) or not set(known) <= set(score_mask):
        raise ValueError("score_mask must be distinct original positions including every crib")
    score_mask = sorted(score_mask)
    masked = set(score_mask)
    starts = [i for i in range(n - model.order + 1) if not any(j in masked for j in range(i, i + model.order))]
    p, q = model.alpha.as_integer_ratio()
    index = {c: i for i, c in enumerate(alphabet)}
    cvalues = [index[c] for c in ciphertext]
    lengths = [len(c) for c in columns]
    multiplicities = Counter(lengths)
    budget = _Budget(max_states, time_limit_seconds)
    # Replay of retained checkpoint rows is preparation, not a newly visited
    # assignment. Report it separately so continuation never hides objective
    # work while keeping the unique search-coverage counter meaningful.
    budget.work["checkpoint_candidate_verifications"] = 0
    budget.work["checkpoint_score_window_evaluations"] = 0
    bounds = dict(top=top, max_segmentations=max_segmentations, max_states=max_states,
                  max_orders=max_orders, max_evaluations=max_evaluations, time_limit_seconds=time_limit_seconds,
                  max_frontier=max_frontier, pruning=pruning,**options,
                  max_bound_cache_entries=max_bound_cache_entries)
    assumptions = dict(period=period, order=order, cipher=cipher, alphabet=alphabet,
                       cells=[list(c) for c in occupied], column_direction=column_direction)
    retained, evaluated, orders, segmentations = {}, 0, 0, 0
    visited_order_assignments = pruned_branches = previous_states = 0
    previous_work = {}
    reason = "exhausted_declared_family"
    frontier = [dict(kind="segment", pattern=[])]
    root = Path(__file__).resolve().parent
    identity = dict(schema="kryptos.joint-ranked-frontier.v1", ciphertext=ciphertext,
        cribs=[[i,c] for i,c in known.items()], assumptions=assumptions, top=top,
        score_mask=score_mask, pruning=pruning, joint_options=options, model_sha256=_digest(dict(
            alphabet=model.alphabet, order=model.order, counts=dict(model.counts), p=str(p), q=str(q))),
        sources={name:hashlib.sha256((root/name).read_bytes()).hexdigest()
                 for name in ("joint_ranked.py","joint_ranked_helpers.py","joint_columnar.py","columnar.py","explanations.py","language.py","factor_joint_bound.py")})
    pattern_cache = {}
    grams = sorted(model.counts.items(), key=lambda item: (-item[1], item[0])) if pruning == "admissible" else []
    shared_bound=SharedKeyBound(alphabet,cipher,model.counts,p,q,max_bound_cache_entries) if score_bound in ("shared_key","matching") else None
    if shared_bound is not None:budget.work["shared_bound_setup_grams"]=len(model.counts)
    symmetry_cache={}
    symmetry_examples={}

    def groups_for(pattern):
        if symmetry=="off":return []
        key=tuple(pattern)
        budget.tick("symmetry_cache_lookups")
        if key in symmetry_cache:
            budget.work["symmetry_cache_hits"]+=1
            return symmetry_cache[key]
        groups=equivalent_chunks(ciphertext,pattern,period,order,budget)
        if groups:budget.work["symmetry_nontrivial_plans"]+=1
        if len(symmetry_cache)<64:
            symmetry_cache[key]=groups
            symmetry_examples[key]=symmetry_record(pattern,groups)
        return groups

    def decode(column_ids, keys):
        route = [i for col in column_ids for i in columns[col]]
        plaintext = [""] * n
        for j, i in enumerate(route):
            k, c = keys[(i if order == "ST" else j) % period], cvalues[j]
            plaintext[i] = alphabet[(k-c if cipher == "beaufort" else c+k if cipher == "variant" else c-k) % 26]
        return "".join(plaintext), route

    def objective(plaintext, counted=True):
        exact = 1
        for start in starts:
            if counted:
                budget.tick("scored_windows")
            exact *= model.counts.get(plaintext[start:start+model.order], 0)*q+p
        return exact

    def retain(column_ids, keys, plaintext, exact, route):
        key_text = "".join(alphabet[v] for v in keys)
        representation = (tuple(labels[c] for c in column_ids), key_text)
        old = retained.get(plaintext)
        if old is not None and representation >= old["representation"]:
            return
        if old is None and len(retained) >= top:
            worst = max(retained, key=lambda text: (-retained[text]["exact"], text))
            if (-exact, plaintext) >= (-retained[worst]["exact"], worst):
                return
            del retained[worst]
        retained[plaintext] = dict(exact=exact, representation=representation, route=route,
            key=key_text+alphabet[0]*(period-used), columns=list(column_ids), values=list(keys))

    def compatibility(pattern):
        cache_key = tuple(pattern)
        if cache_key in pattern_cache:
            if joint_mode or early_segmentation or shared_bound is not None:
                budget.work["compatibility_cache_hits"]+=1
            return pattern_cache[cache_key]
        if joint_mode or early_segmentation or shared_bound is not None:
            budget.work["compatibility_cache_misses"]+=1
        offset, domains, requirements, offsets = 0, [], {}, []
        for slot, length in enumerate(pattern):
            offsets.append(offset)
            domain = []
            for col, positions in enumerate(columns):
                budget.tick("compatibility_pairs")
                if len(positions) != length:
                    continue
                here, valid = {}, True
                for vertical, i in enumerate(positions):
                    if i not in known:
                        continue
                    j = offset+vertical
                    c, plain = cvalues[j], index[known[i]]
                    value = (c+plain if cipher == "beaufort" else plain-c if cipher == "variant" else c-plain) % 26
                    phase = (i if order == "ST" else j) % period
                    if phase in here and here[phase] != value:
                        valid = False
                        break
                    here[phase] = value
                if valid:
                    domain.append(col)
                    requirements[slot,col] = here
            domains.append(tuple(domain))
            offset += length
        # A bounded disposable cache; no cache is required to resume correctly.
        if len(pattern_cache) < 64:
            pattern_cache[cache_key] = (domains, requirements, offsets)
        return domains, requirements, offsets

    def prefix_feasible(pattern):
        """Unknown suffix lengths have no assumed ciphertext positions."""
        before=budget.work["states"]
        try:
            budget.tick("early_segmentation_checks")
            domains,requirements,_=compatibility(pattern)
            domains=list(domains)
            requirements=dict(requirements)
            remaining=multiplicities-Counter(pattern)
            for length in sorted(remaining.elements()):
                slot=len(domains)
                domain=tuple(col for col,positions in enumerate(columns) if len(positions)==length)
                domains.append(domain)
                for col in domain:
                    budget.tick("early_suffix_edges")
                    requirements[slot,col]={}
            if propagation in ("fixed_point","relational"):
                reduced,_=reduce_joint(domains,[FULL]*used,requirements,budget,fixed_point=True,
                    pair_consistency=propagation=="relational")
                feasible=reduced is not None
            else:
                feasible=columnar._matching(domains,budget) is not None
            if not feasible:budget.work["early_segmentation_rejections"]+=1
            return feasible
        finally:
            budget.work["early_segmentation_states"]+=budget.work["states"]-before

    def cannot_reach_top(current, keys, requirements, offsets, key_domains=None):
        if pruning == "off" or len(retained) < top:
            return False
        budget.tick("score_bound_nodes")
        if key_domains is None:
            key_domains=[FULL if key is None else 1<<key for key in keys]
        reachable = [set() for _ in range(n)]
        bindings=[None]*n if shared_bound is not None else None
        for slot, domain in enumerate(current):
            for col in domain:
                forced = requirements.get((slot,col), {})
                for vertical, i in enumerate(columns[col]):
                    budget.tick("bound_letter_domains")
                    j = offsets[slot]+vertical
                    phase = (i if order == "ST" else j) % period
                    fixed = keys[phase] if keys[phase] is not None else forced.get(phase)
                    if fixed is None:
                        if key_domains[phase]==FULL:
                            reachable[i].update(alphabet)
                        else:
                            c=cvalues[j]
                            reachable[i].update(alphabet[(k-c if cipher=="beaufort" else c+k if cipher=="variant" else c-k)%26]
                                                for k in values(key_domains[phase]))
                    else:
                        c = cvalues[j]
                        reachable[i].add(alphabet[(fixed-c if cipher == "beaufort" else c+fixed if cipher == "variant" else c-fixed) % 26])
                    if bindings is not None and len(domain)==1:
                        bindings[i]=(cvalues[j],phase)
        upper = 1
        window_bounds={}
        for start in starts:
            budget.tick("bound_windows")
            maximum = 0
            domains_here = reachable[start:start+model.order]
            size = math.prod(len(domain) for domain in domains_here)
            if size <= max(1,min(64,len(grams))):
                for letters in product(*(sorted(domain) for domain in domains_here)):
                    budget.tick("bound_grams_checked")
                    maximum = max(maximum,model.counts.get("".join(letters),0))
            else:
                for gram, count in grams:
                    budget.tick("bound_grams_checked")
                    if all(c in domains_here[k] for k,c in enumerate(gram)):
                        maximum = count
                        break
            local_upper=maximum*q+p
            if shared_bound is not None:
                correlated=shared_bound.upper(bindings[start:start+model.order],key_domains,budget)
                if correlated<local_upper:budget.work["shared_bound_tightenings"]+=1
                local_upper=min(local_upper,correlated)
            upper *= local_upper
            window_bounds[start]=local_upper
        if score_bound=='matching':
            from .factor_joint_bound import compute_column_matching_bound
            matching=compute_column_matching_bound(current=current,columns=columns,offsets=offsets,
                cvalues=cvalues,requirements=requirements,key_domains=key_domains,period=period,order=order,
                starts=starts,ngram_order=model.order,shared_bound=shared_bound,window_bounds=window_bounds,budget=budget)
            if matching.get('bound_available'):
                matching_upper=matching['upper_bound']
                if matching_upper<upper:budget.work['matching_score_bound_tightenings']+=1
                upper=min(upper,matching_upper)
        threshold = min(row["exact"] for row in retained.values())
        # Equality must remain searchable: plaintext and recipe lexical ties
        # cannot be resolved from a score bound alone.
        return upper < threshold

    def valid_keys(keys, complete=False):
        return isinstance(keys,list) and len(keys)==used and all(
            (value is None and not complete) or type(value) is int and 0<=value<26 for value in keys)

    def validate_task(task):
        if not isinstance(task,dict):
            raise ValueError("malformed frontier task")
        kind = task.get("kind")
        fields = {"segment":{"kind","pattern"}, "route":{"kind","pattern","chosen","keys"},
                  "key":{"kind","columns","keys"},
                  "joint":{"kind","pattern","domains","key_domains","route_counted"}}
        if not isinstance(kind,str) or kind not in fields or set(task)!=fields[kind]:
            raise ValueError("malformed frontier task fields")
        if kind in ("segment","route","joint"):
            pattern = task["pattern"]
            if not isinstance(pattern,list) or len(pattern)>w or any(type(v) is not int or v not in multiplicities for v in pattern) or Counter(pattern)-multiplicities:
                raise ValueError("invalid segmentation frontier")
            if kind in ("route","joint") and len(pattern)!=w:
                raise ValueError("incomplete route segmentation")
        if kind=="joint":
            if not joint_mode or type(task["route_counted"]) is not bool:
                raise ValueError("joint frontier does not match declared mode")
            masks=task["key_domains"]
            if not isinstance(masks,list) or len(masks)!=used or any(type(mask) is not int or not 1<=mask<=FULL for mask in masks):
                raise ValueError("invalid key domain masks")
            domains=task["domains"]
            if domains is None:
                if task["route_counted"]:raise ValueError("counted route needs explicit domains")
            elif not isinstance(domains,list) or len(domains)!=w:
                raise ValueError("invalid slot domains")
            else:
                for slot,domain in enumerate(domains):
                    if not isinstance(domain,list) or not domain or any(type(col) is not int or not 0<=col<w or lengths[col]!=pattern[slot] for col in domain) or domain!=sorted(set(domain)):
                        raise ValueError("invalid column domain")
                if task["route_counted"] and (any(len(domain)!=1 for domain in domains) or len({d[0] for d in domains})!=w):
                    raise ValueError("counted route must be one full permutation")
        if kind in ("route","key"):
            cols = task["chosen"] if kind=="route" else task["columns"]
            if not isinstance(cols,list) or len(cols)>w or any(type(v) is not int or not 0<=v<w for v in cols) or len(set(cols))!=len(cols) or not valid_keys(task["keys"]):
                raise ValueError("invalid route/key frontier")
            if kind=="key" and len(cols)!=w or kind=="route" and any(lengths[c]!=task["pattern"][j] for j,c in enumerate(cols)):
                raise ValueError("route length mismatch")

    if resume_path is not None:
        from .search_runtime import _strict_load
        saved = _strict_load(resume_path)
        if not isinstance(saved,dict) or set(saved)!={"payload","sha256"} or _digest(saved["payload"])!=saved["sha256"]:
            raise ValueError("joint checkpoint integrity check failed")
        payload = saved["payload"]
        fields = {"identity","frontier","retained","evaluated","orders","segmentations","compatible_assignments","pruned_branches","states_total","work"}
        if not isinstance(payload,dict) or set(payload)!=fields or payload["identity"]!=identity:
            raise ValueError("joint checkpoint belongs to a different input, model, source or convention")
        if not isinstance(payload["frontier"],list) or len(payload["frontier"])>100000:
            raise ValueError("invalid checkpoint frontier")
        for task in payload["frontier"]:
            validate_task(task)
        for name in ("evaluated","orders","segmentations","compatible_assignments","pruned_branches","states_total"):
            if type(payload[name]) is not int or payload[name]<0:
                raise ValueError("invalid checkpoint counter")
        if not isinstance(payload["work"],dict) or any(not isinstance(k,str) or type(v) is not int or v<0 for k,v in payload["work"].items()):
            raise ValueError("invalid checkpoint work")
        if not isinstance(payload["retained"],list) or len(payload["retained"])>top:
            raise ValueError("invalid retained checkpoint candidates")
        for saved_row in payload["retained"]:
            if not isinstance(saved_row,dict) or set(saved_row)!={"columns","keys","plaintext","score_hex"}:
                raise ValueError("invalid checkpoint candidate fields")
            validate_task(dict(kind="key",columns=saved_row["columns"],keys=saved_row["keys"]))
            if not valid_keys(saved_row["keys"],True):
                raise ValueError("incomplete checkpoint candidate")
            plaintext, route = decode(saved_row["columns"],saved_row["keys"])
            exact = objective(plaintext,False)
            budget.work["checkpoint_candidate_verifications"] += 1
            budget.work["checkpoint_score_window_evaluations"] += len(starts)
            if saved_row["plaintext"]!=plaintext or saved_row["score_hex"]!=hex(exact) or any(plaintext[i]!=c for i,c in known.items()):
                raise ValueError("checkpoint candidate failed independent replay/score check")
            retain(saved_row["columns"],saved_row["keys"],plaintext,exact,route)
        frontier = payload["frontier"]
        evaluated, orders, segmentations = (payload[k] for k in ("evaluated","orders","segmentations"))
        visited_order_assignments, pruned_branches, previous_states = (payload[k] for k in ("compatible_assignments","pruned_branches","states_total"))
        previous_work = payload["work"]
    old_evaluated, old_orders, old_segmentations = evaluated, orders, segmentations
    progress = 0
    if len(frontier)>max_frontier:
        reason = "max_frontier"
    while frontier and len(frontier)<=max_frontier:
        task = frontier.pop()
        try:
            kind = task["kind"]
            children, delta_orders, delta_segments, delta_assignments, delta_pruned = [], 0, 0, 0, 0
            if kind == "segment":
                budget.tick("segmentation_nodes")
                pattern = task["pattern"]
                if early_segmentation and 0<len(pattern)<w and not prefix_feasible(pattern):
                    pass
                elif len(pattern)==w:
                    if segmentations-old_segmentations >= max_segmentations:
                        raise _Limit("max_segmentations")
                    delta_segments = 1
                    children = ([dict(kind="joint",pattern=pattern,domains=None,key_domains=[FULL]*used,route_counted=False)]
                                if joint_mode else [dict(kind="route",pattern=pattern,chosen=[],keys=[None]*used)])
                else:
                    remaining = multiplicities-Counter(pattern)
                    children = [dict(kind="segment",pattern=pattern+[length]) for length in sorted(remaining)]
            elif kind == "route":
                budget.tick("route_nodes")
                pattern, chosen, keys = task["pattern"],task["chosen"],task["keys"]
                domains, requirements, offsets = compatibility(pattern)
                taken = set(chosen)
                current = []
                for slot, domain in enumerate(domains):
                    current.append(tuple(col for col in domain if (col==chosen[slot] if slot<len(chosen) else col not in taken) and all(
                        keys[phase] is None or keys[phase]==value for phase,value in requirements[slot,col].items())))
                if columnar._matching(current,budget) is None:
                    budget.work["matching_rejections"] += 1
                elif (len(chosen)<w or None in keys) and cannot_reach_top(current,keys,requirements,offsets):
                    delta_pruned = 1
                elif len(chosen)==w:
                    if orders-old_orders >= max_orders:
                        raise _Limit("max_orders")
                    delta_orders, delta_assignments = 1, 26**keys.count(None)
                    children = [dict(kind="key",columns=chosen,keys=keys)]
                else:
                    slot = len(chosen)
                    for col in current[slot]:
                        child_keys = list(keys)
                        for phase,value in requirements[slot,col].items():
                            child_keys[phase] = value
                        children.append(dict(kind="route",pattern=pattern,chosen=chosen+[col],keys=child_keys))
            elif kind=="joint":
                budget.tick("joint_nodes")
                pattern=task["pattern"]
                base,requirements,offsets=compatibility(pattern)
                current=base if task["domains"] is None else task["domains"]
                masks=list(task["key_domains"])
                counted=task["route_counted"]
                if counted:
                    reduced=(current,masks)
                else:
                    reduced,_=reduce_joint(current,masks,requirements,budget,
                        fixed_point=propagation in ("fixed_point","relational"),groups=groups_for(pattern),
                        pair_consistency=propagation=="relational")
                if reduced is not None:
                    current,masks=reduced
                    keys=singleton_values(masks)
                    full_route=all(len(domain)==1 for domain in current)
                    full_key=all(value is not None for value in keys)
                    if not(full_route and full_key) and cannot_reach_top(current,keys,requirements,offsets,masks):
                        delta_pruned=1
                    else:
                        if full_route and not counted:
                            if orders-old_orders>=max_orders:raise _Limit("max_orders")
                            delta_orders=1
                            delta_assignments=math.prod(mask.bit_count() for mask in masks)
                            counted=True
                        if full_route and full_key:
                            if evaluated-old_evaluated>=max_evaluations:raise _Limit("max_evaluations")
                            budget.tick("key_completions")
                            column_ids=[domain[0] for domain in current]
                            plaintext,route=decode(column_ids,keys)
                            if any(plaintext[i]!=c for i,c in known.items()):raise ValueError("joint frontier contradicts a supplied crib")
                            exact=objective(plaintext)
                            retain(column_ids,keys,plaintext,exact,route)
                            evaluated+=1
                        else:
                            choices=[]
                            for slot,domain in enumerate(current):
                                budget.tick("branch_domain_checks")
                                if len(domain)>1:choices.append((len(domain),1,slot,"slot"))
                            if full_route or branching=="constrained":
                                for phase,mask in enumerate(masks):
                                    budget.tick("branch_domain_checks")
                                    if mask.bit_count()>1:choices.append((mask.bit_count(),0,phase,"key"))
                            if branching=="prefix":
                                selected=min(choices,key=lambda row:(row[3]!="slot",row[2]))
                            else:
                                selected=min(choices)
                            _,_,variable,decision=selected
                            budget.work["joint_decisions"]+=1
                            budget.work["joint_"+decision+"_decisions"]+=1
                            alternatives=current[variable] if decision=="slot" else list(values(masks[variable]))
                            for value in alternatives:
                                child_domains=[list(domain) for domain in current]
                                child_masks=list(masks)
                                if decision=="slot":child_domains[variable]=[value]
                                else:child_masks[variable]=1<<value
                                children.append(dict(kind="joint",pattern=pattern,domains=child_domains,
                                    key_domains=child_masks,route_counted=counted))
            else:
                budget.tick("key_nodes")
                column_ids, keys = task["columns"],task["keys"]
                offsets, offset = [], 0
                for col in column_ids:
                    offsets.append(offset)
                    offset += lengths[col]
                if None in keys and cannot_reach_top([(c,) for c in column_ids],keys,{},offsets):
                    delta_pruned = 1
                elif None in keys:
                    phase = keys.index(None)
                    for value in range(26):
                        child_keys = list(keys)
                        child_keys[phase] = value
                        children.append(dict(kind="key",columns=column_ids,keys=child_keys))
                else:
                    if evaluated-old_evaluated >= max_evaluations:
                        raise _Limit("max_evaluations")
                    budget.tick("key_completions")
                    plaintext, route = decode(column_ids,keys)
                    if any(plaintext[i]!=c for i,c in known.items()):
                        raise ValueError("frontier key contradicts a supplied crib")
                    exact = objective(plaintext)
                    retain(column_ids,keys,plaintext,exact,route)
                    evaluated += 1
            # Comparable decision instrumentation across both frontier formats:
            # materializing two or more alternatives is one branch decision.
            # Deterministic forced transitions are not decisions. Repeated
            # interrupted attempts remain counted work, not proof progress.
            if len(children)>1:
                category=decision if kind=="joint" else "segmentation" if kind=="segment" else "slot" if kind=="route" else "key"
                budget.work["branch_decisions"]+=1
                budget.work[category+"_branch_decisions"]+=1
                budget.work["branch_alternatives_materialized"]+=len(children)
            if len(frontier)+len(children)>max_frontier:
                raise _Limit("max_frontier")
            frontier.extend(reversed(children))
            orders += delta_orders
            segmentations += delta_segments
            visited_order_assignments += delta_assignments
            pruned_branches += delta_pruned
            progress += 1
        except _Limit as exc:
            frontier.append(task)
            reason = str(exc)
            break
    complete = not frontier
    total_work = dict(previous_work)
    for key,value in budget.work.items():
        total_work[key] = total_work.get(key,0)+value
    symmetry_reduced=bool(total_work.get("symmetry_edges_removed",0) or total_work.get("symmetry_rejections",0))
    enumeration_complete=complete and not pruned_branches and not symmetry_reduced
    if checkpoint_path is not None:
        payload = dict(identity=identity,frontier=frontier,
            retained=[dict(columns=row["columns"],keys=row["values"],plaintext=text,score_hex=hex(row["exact"])) for text,row in sorted(retained.items())],
            evaluated=evaluated,orders=orders,segmentations=segmentations,compatible_assignments=visited_order_assignments,
            pruned_branches=pruned_branches,states_total=previous_states+budget.work["states"],work=total_work)
        encoded = json.dumps(dict(payload=payload,sha256=_digest(payload)),sort_keys=True,allow_nan=False)
        if len(encoded.encode())>64*1024*1024:
            raise ValueError("checkpoint exceeds64MiB")
        path = Path(checkpoint_path)
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("x",encoding="utf-8") as stream:
            stream.write(encoded)
    candidates = []
    for plaintext, row in sorted(retained.items(), key=lambda pair: (-pair[1]["exact"], pair[0])):
        substitution = dict(operation="repeat_substitution", cipher=cipher, key_pattern=row["key"])
        gather = dict(operation="gather", permutation=row["route"])
        recipe = dict(schema="kryptos.encryption-recipe.v1", alphabet=alphabet, index_origin=0,
                      stages=[substitution, gather] if order == "ST" else [gather, substitution])
        replay = replay_recipe(plaintext, recipe)
        if replay["ciphertext"] != ciphertext:
            raise AssertionError("independent literal reencryption failed")
        display = model.score(plaintext, score_mask)
        candidates.append(dict(plaintext=plaintext, column_order=list(row["representation"][0]),
            key_pattern=row["key"], permutation=row["route"], encryption_recipe=recipe,
            score_exact=hex(row["exact"]), score=display.mean_log_probability,
            score_available=display.available, classification="ranked_model_consistency_witness",
            evidence=dict(literal_reencryption_matches=True, crib_matches=len(known),
                          stage_outputs=replay["stages"], authenticated_solution=False)))
    return dict(schema="kryptos.joint-ranked.v1", complete=complete, truncated=not complete,
        stop_reason=reason, feasible=True if evaluated else False if complete else None,
        top_k_exact=complete, ranking_exact_over_evaluated=True, enumeration_complete=enumeration_complete,
        total_column_orders=orders if enumeration_complete and branching!="constrained" else None,
        total_order_key_assignments=evaluated if enumeration_complete else None,
        column_orders_visited=orders if branching!="constrained" else None,
        route_completion_blocks=orders,compatible_assignment_lower_bound=visited_order_assignments,
        evaluated=evaluated, candidates=candidates, segmentations_tested=segmentations,
        bounds=bounds, work=total_work, work_this_run=dict(budget.work), assumptions=assumptions,
        evaluated_this_run=evaluated-old_evaluated, states_total=previous_states+budget.work["states"],
        states_this_run=budget.work["states"], frontier_progress_nodes=progress,
        frontier_nodes=len(frontier), pruned_score_branches=pruned_branches,
        resumed=resume_path is not None, checkpoint_written=str(checkpoint_path) if checkpoint_path is not None else None,
        checkpoint_identity_sha256=_digest(identity),
        count_convention=("Route completion blocks can revisit a labelled order after disjoint key-domain branches; distinct route counts are withheld. "
                          if branching=="constrained" else "Each visited route is one labelled column order. ")+
                         "Evaluated counts complete searched route/key assignments; symmetry representatives and score exclusions are not full labelled enumeration.",
        route_symmetry=dict(mode=symmetry,reduced=symmetry_reduced,
            rule="Equal length and identical ciphertext chunks; TS additionally requires equal offset modulo period.",
            groups_by_segmentation=list(symmetry_examples.values()),examples_limit=64,
            examples_scope="At most64 segmentation examples from this invocation's disposable cache; not an exhaustive history. The rule and declared ciphertext reconstruct all groups.",
            reconstruction="Permute source column labels within each displayed equivalent-slot group with the same key; sorted labels give the retained canonical recipe. Other groups are reconstructible from the declared rule, ciphertext and segmentation."),
        unused_key_slots=list(range(used, period)),
        scoring=dict(model_id=model.model_id, score_mask=score_mask, windows=len(starts),
                     score_available=bool(starts), alpha_numerator=str(p), alpha_denominator=str(q),
                     comparison="Exact product(count*q+p), then plaintext lexical order; duplicate plaintexts merged. Representative ties use labelled column order, then used-key lexical order."),
        provenance=dict(normalized_input_sha256=_digest(dict(ciphertext=ciphertext, cribs=known,
                        assumptions=assumptions, bounds=bounds, score_mask=score_mask, model_id=model.model_id))),
        elapsed_seconds=time.monotonic() - started, authenticated_solution=False,
        interpretation="Top-k is exact only when the frontier is exhausted, possibly using strict admissible score pruning. Pruned assignments are not enumerated coverage; exact full counts are withheld when pruning occurred. Checkpoint counters include repeated interrupted work. No solution authentication.")


def run_joint_ranked(request, target_fn):
    """Strict CLI adapter; the app separately allowlists model paths."""
    options = {"period", "order", "cipher", "alphabet", "width", "cells", "column_direction", "top",
               "max_segmentations", "max_states", "max_orders", "max_evaluations", "time_limit_seconds", "score_mask",
               "pruning", "resume_path", "checkpoint_path", "max_frontier",
               "propagation","early_segmentation","branching","score_bound","symmetry","max_bound_cache_entries"}
    if not isinstance(request, dict) or set(request) - options - {"target", "ciphertext", "cribs", "model_path"}:
        raise ValueError("unknown ranked-joint request field")
    if "period" not in request or not isinstance(request.get("model_path"), str):
        raise ValueError("ranked joint requires period and model_path")
    target, ciphertext, cribs, _ = target_fn(request)
    path = Path(request["model_path"])
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("model exceeds64MiB")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    model = CharacterNgramModel.from_json(raw.decode("utf-8"))
    result = rank_joint_columnar(ciphertext, cribs, model=model,
                                 **{key: request[key] for key in options if key in request})
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError("scoring model changed during ranked search")
    result.update(target=target, model_file_sha256=digest, model_id=model.model_id)
    return result
