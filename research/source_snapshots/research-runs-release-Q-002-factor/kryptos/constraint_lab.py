"""Bounded exact relation search for explicit experimental cipher models.

The relations, domains and integer objective are the model.  No unlisted
English, route, alphabet or K5 assumption is introduced.  Correlations are
stored as whole tuples.  Learned hard conflicts and score exclusions have
different representations and different reuse guards.
"""
from collections import defaultdict
from itertools import product
import hashlib
import json
import math


class ConstraintLimit(ValueError):
    """A bound was reached, without a feasibility/completeness verdict."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _int(value, name, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an integer in {lo}..{hi}")
    return value


def normalize(request):
    allowed = {"domains", "relations", "factors", "top", "max_work", "max_solutions", "options", "learned", "objective", "coverage"}
    if not isinstance(request, dict) or set(request)-allowed:
        raise ValueError("Unknown finite-relation request field")
    raw = request.get("domains")
    if not isinstance(raw, dict) or not 1 <= len(raw) <= 128:
        raise ValueError("domains requires 1..128 named finite integer domains")
    if any(not isinstance(name,str) or not 1<=len(name)<=80 for name in raw):
        raise ValueError('Variable names must have1..80 characters')
    names = tuple(sorted(raw))
    domains = {}
    for name in names:
        values = raw[name]
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise ValueError("Variable names must have 1..80 characters")
        if (not isinstance(values, list) or not 1 <= len(values) <= 256 or
                any(type(x) is not int for x in values) or len(set(values)) != len(values)):
            raise ValueError("Each domain requires 1..256 distinct integers")
        domains[name] = tuple(sorted(values))
    def tables(raw, scored):
        if not isinstance(raw, list) or len(raw) > 2048:
            raise ValueError("At most2048 finite tables are supported")
        out = []
        total = 0
        for table in raw:
            if not isinstance(table, dict) or set(table)-{"scope", "rows", "default", "name"}:
                raise ValueError("Unknown table field")
            scope = table.get("scope")
            rows = table.get("rows")
            if (not isinstance(scope, list) or len(scope) > 32 or len(set(scope)) != len(scope)
                    or any(v not in domains for v in scope) or not isinstance(rows, list)):
                raise ValueError("Invalid table scope or rows")
            if not scored and "default" in table:
                raise ValueError("Hard relations cannot have a default score")
            seen = set()
            normalized = []
            for row in rows:
                if not isinstance(row, list) or len(row) != len(scope)+int(scored) or any(type(x) is not int for x in row):
                    raise ValueError("Each table row has one integer per variable and, for scores, one integer score")
                key = tuple(row[:len(scope)])
                if key in seen or any(value not in domains[var] for var, value in zip(scope, key)):
                    raise ValueError("Duplicate or out-of-domain table tuple")
                seen.add(key)
                normalized.append(tuple(row))
            total += len(rows)
            if total > 200000:
                raise ConstraintLimit("Table materialization exceeds200000 rows")
            default = table.get("default", 0)
            if type(default) is not int:
                raise ValueError("Default objective contribution must be an integer")
            out.append({"scope":tuple(scope), "rows":tuple(sorted(normalized)), "default":default})
        return tuple(out)
    relations = tables(request.get("relations", []), False)
    factors = tables(request.get("factors", []), True)
    return names, domains, relations, factors


class RelationSearch:
    def __init__(self, request, *, tie_key=None):
        self.names, self.domains, self.relations, self.factors = normalize(request)
        self.objective = request.get("objective", "sum")
        if self.objective not in ("sum", "product"):
            raise ValueError("Objective must be sum or product")
        if self.objective == "product" and any(f["default"] < 0 or any(row[-1]<0 for row in f["rows"]) for f in self.factors):
            raise ValueError("Product bounds require nonnegative factor values")
        self.options = request.get("options", {})
        allowed = {"propagation", "learning", "minimize_conflicts", "backjump", "probing", "memoize", "score_exclusions", "branching", "isomorphic_cache"}
        if not isinstance(self.options, dict) or set(self.options)-allowed:
            raise ValueError("Unknown relation-search option")
        for name, value in self.options.items():
            if name == "branching":
                if value not in ("natural", "smallest"):
                    raise ValueError("branching must be natural or smallest")
            elif type(value) is not bool:
                raise ValueError("Relation switches must be Boolean")
        self.top = _int(request.get("top", 20), "top", 1, 1000)
        self.max_work = _int(request.get("max_work", 2000000), "max_work", 1, 100000000)
        self.max_solutions = _int(request.get("max_solutions", 100000), "max_solutions", 1, 1000000)
        self.work = defaultdict(int)
        self.nogoods, self.exclusions, self.dead = [], [], set()
        self.retained = []
        self.tie_key = tie_key or (lambda values: values)
        self.feasible_count = 0
        self.hard_identity = digest({"domains":self.domains, "relations":self.relations})
        self.objective_identity = digest({"hard":self.hard_identity, "factors":self.factors,"objective":self.objective})
        self._import(request.get("learned"))
        self.covered=[]
        artifacts=request.get('coverage',[])
        if not isinstance(artifacts,list) or len(artifacts)>128:
            raise ValueError('Supply at most128 JSON subtree coverage artifacts')
        if artifacts and tie_key is not None:
            raise ValueError('Coverage artifacts use the canonical assignment tie order')
        for artifact in artifacts:
            from .constraint_cover_proof import verify
            assumptions,candidates=verify(self,artifact)
            self.covered.append(assumptions)
            self.retained.extend(candidates)
            self.retained=sorted(set(self.retained),key=lambda row:(-row[0],row[1]))[:self.top]

    def tick(self, name, amount=1):
        self.work[name] += amount
        self.work["total_work"] += amount
        if self.work["total_work"] > self.max_work:
            raise ConstraintLimit("max_work")

    def _import(self, learned):
        if learned is None:
            return
        if not isinstance(learned, dict) or learned.get("hard_identity") != self.hard_identity:
            raise ValueError("Learned constraints belong to a different hard model")
        # Serialized records are untrusted. Every hard clause is independently
        # checked by complete literal enumeration before it can prune anything.
        records = learned.get("nogoods", [])
        if not isinstance(records, list) or len(records) > 1000:
            raise ValueError("At most1000 learned clauses can be imported")
        for raw in records:
            if not isinstance(raw, list) or any(not isinstance(x, list) or len(x) != 2 or not isinstance(x[0],str) or type(x[1]) is not int for x in raw):
                raise ValueError("Malformed learned conflict")
            clause = tuple((v,x) for v,x in raw)
            if len(dict(clause)) != len(clause) or any(v not in self.domains or x not in self.domains[v] for v,x in clause):
                raise ValueError("Malformed learned assignment")
            restricted = dict(self.domains)
            restricted.update({v:(x,) for v,x in clause})
            if math.prod(map(len, restricted.values())) > 200000:
                raise ConstraintLimit("Imported proof reverification exceeds200000 assignments")
            for values in product(*(restricted[v] for v in self.names)):
                self.tick("proof_reverification_assignments")
                assignment = dict(zip(self.names, values))
                if self.literal_feasible(assignment):
                    raise ValueError("Imported conflict has a feasible counterexample")
            self.nogoods.append(clause)
        exclusions=learned.get('score_exclusions',[])
        if not isinstance(exclusions,list) or len(exclusions)>1000:
            raise ValueError('At most1000 score exclusions can be imported')
        if exclusions and learned.get('objective_identity')!=self.objective_identity:
            raise ValueError('Score exclusions belong to a different objective')
        for record in exclusions:
            if not isinstance(record,dict) or set(record)!={'path','upper','threshold','objective_identity'} or record['objective_identity']!=self.objective_identity:
                raise ValueError('Malformed score exclusion')
            path=record['path']
            if not isinstance(path,list) or any(not isinstance(pair,list) or len(pair)!=2 or not isinstance(pair[0],str) or pair[0] not in self.domains or type(pair[1]) is not int or pair[1] not in self.domains[pair[0]] for pair in path) or len(dict(path))!=len(path):
                raise ValueError('Malformed score exclusion assumptions')
            if type(record['upper']) is not int or type(record['threshold']) is not int:
                raise ValueError('Score exclusion bounds must be exact integers')
            restricted=dict(self.domains)
            restricted.update({v:(x,) for v,x in path})
            if math.prod(map(len,restricted.values()))>200000:
                raise ConstraintLimit('Score exclusion reverification cap')
            for values in product(*(restricted[v] for v in self.names)):
                self.tick('score_proof_reverification_assignments')
                assignment=dict(zip(self.names,values))
                if self.literal_feasible(assignment) and self.score(assignment)>record['upper']:
                    raise ValueError('Score exclusion has a feasible counterexample above its bound')
            self.exclusions.append(record)

    def literal_feasible(self, assignment):
        for relation in self.relations:
            self.tick("literal_relation_checks")
            if tuple(assignment[v] for v in relation["scope"]) not in relation["rows"]:
                return False
        return True

    def propagate(self, domains, *, use_clauses=True):
        current = dict(domains)
        while True:
            changed = False
            for relation in self.relations:
                scope = relation["scope"]
                supports = {v:set() for v in scope}
                found = False
                for row in relation["rows"]:
                    self.tick("relation_row_checks")
                    if all(value in current[v] for v,value in zip(scope,row)):
                        found = True
                        for v,value in zip(scope,row):
                            supports[v].add(value)
                if not found:
                    return None
                for v in scope:
                    narrowed = tuple(x for x in current[v] if x in supports[v])
                    changed |= narrowed != current[v]
                    current[v] = narrowed
            if use_clauses:
                for clause in self.nogoods:
                    self.tick("learned_clause_checks")
                    # A value absent from a domain already satisfies not(clause).
                    if any(value not in current[v] for v,value in clause):
                        continue
                    undecided = [(v,value) for v,value in clause if len(current[v]) != 1]
                    if not undecided:
                        return None
                    if len(undecided) == 1:
                        v,value = undecided[0]
                        current[v] = tuple(x for x in current[v] if x != value)
                        self.tick("learned_unit_removals")
                        changed = True
            if not changed:
                return current

    def core(self, path):
        core = list(path)
        if self.options.get("minimize_conflicts", False):
            # Deletion-minimal for this propagator, not necessarily a globally
            # minimum UNSAT core. Failed probes count as preparation work.
            for pair in tuple(core):
                trial = [x for x in core if x != pair]
                domains = dict(self.domains)
                domains.update({v:(x,) for v,x in trial})
                self.tick("conflict_minimization_checks")
                if self.propagate(domains, use_clauses=False) is None:
                    core = trial
        clause = tuple(sorted(core))
        if self.options.get("learning", False) and clause not in self.nogoods:
            self.nogoods.append(clause)
            self.tick("learned_conflicts")
        return frozenset(clause)

    def upper(self, domains):
        total = int(self.objective == "product")
        for factor in self.factors:
            values = []
            compatible = 0
            for row in factor["rows"]:
                self.tick("bound_factor_rows")
                if all(x in domains[v] for v,x in zip(factor["scope"], row[:-1])):
                    values.append(row[-1])
                    compatible += 1
            # Include default only if at least one possible tuple is absent.
            possible = math.prod(len(domains[v]) for v in factor["scope"])
            if compatible < possible:
                values.append(factor["default"])
            total = total*max(values) if self.objective == "product" else total+max(values)
        return total

    def score(self, assignment):
        total = int(self.objective == "product")
        for factor in self.factors:
            key = tuple(assignment[v] for v in factor["scope"])
            self.tick("complete_factor_evaluations")
            value = next((row[-1] for row in factor["rows"] if row[:-1] == key), factor["default"])
            total = total*value if self.objective == "product" else total+value
        return total

    def visit(self, domains, path=()):
        self.tick("nodes")
        for assumptions in self.covered:
            self.tick('coverage_region_checks')
            if all(domains[v]==(x,) for v,x in assumptions.items()):
                self.tick('covered_subtrees_reused')
                return None, True
        if self.options.get("propagation", True):
            domains = self.propagate(domains)
            if domains is None:
                return self.core(path), False
        signature = None
        if self.options.get('memoize',False):
            from .constraint_reuse import residual_signature
            signature=residual_signature(self.names,domains,self.relations,
                isomorphic=self.options.get('isomorphic_cache',False),charge=self.tick)
        if self.options.get("memoize", False) and signature in self.dead:
            self.tick("dead_state_reuses")
            return frozenset(path), False
        if self.options.get("probing", False):
            for var in self.names:
                if len(domains[var]) == 1:
                    continue
                for value in tuple(domains[var]):
                    probe = dict(domains)
                    probe[var] = (value,)
                    self.tick("probe_checks")
                    if self.propagate(probe) is None:
                        domains[var] = tuple(x for x in domains[var] if x != value)
                        self.tick("probe_value_removals")
                if not domains[var]:
                    # Probes used the restricted current domains; the full path
                    # is a valid explanation, not an arc-only minimized core.
                    clause = tuple(sorted(path))
                    if self.options.get("learning", False) and clause not in self.nogoods:
                        self.nogoods.append(clause)
                        self.tick("learned_conflicts")
                    return frozenset(path), False
        threshold = self.retained[-1][0] if len(self.retained) == self.top else None
        if threshold is not None and self.factors:
            for exclusion in self.exclusions:
                self.tick("score_exclusion_checks")
                if exclusion["upper"] < threshold and all(domains[v] == (value,) for v,value in exclusion["path"]):
                    self.tick("score_exclusion_reuses")
                    return None, True
            upper = self.upper(domains)
            # Strict pruning preserves all boundary ties and lexicographic top-k.
            if upper < threshold:
                self.tick("score_pruned_nodes")
                if self.options.get("score_exclusions", False):
                    self.exclusions.append({"path":[list(x) for x in path], "upper":upper,
                        "threshold":threshold, "objective_identity":self.objective_identity})
                return None, True  # not an infeasibility proof
        pending = [v for v in self.names if len(domains[v]) > 1]
        if not pending:
            assignment = {v:domains[v][0] for v in self.names}
            self.tick("complete_candidate_evaluations")
            if not self.literal_feasible(assignment):
                # With propagation disabled, learn only the complete assignment.
                clause = tuple(sorted(path))
                if self.options.get("learning", False) and clause not in self.nogoods:
                    self.nogoods.append(clause)
                return frozenset(path), False
            self.feasible_count += 1
            if self.feasible_count > self.max_solutions:
                raise ConstraintLimit("max_solutions")
            score = self.score(assignment)
            row = (score, tuple(assignment[v] for v in self.names))
            if row not in self.retained:
                self.retained.append(row)
            self.retained.sort(key=lambda x:(-x[0],self.tie_key(x[1]),x[1]))
            del self.retained[self.top:]
            return None, True
        var = min(pending, key=lambda v:(len(domains[v]),v)) if self.options.get("branching", "natural") == "smallest" else pending[0]
        any_feasible = False
        child_explanations=set()
        for value in domains[var]:
            self.tick("branch_decisions")
            child = dict(domains)
            child[var] = (value,)
            conflict, found = self.visit(child, path+((var,value),))
            any_feasible |= found
            if conflict is not None:
                child_explanations.update((v,x) for v,x in conflict if v!=var)
            if self.options.get("backjump", False) and conflict is not None and not any(v == var for v,x in conflict):
                self.tick("backjumps")
                return conflict, any_feasible
        if not any_feasible:
            if self.options.get("memoize", False):
                self.dead.add(signature)
            # Resolve all exhausted values of this variable. If propagation
            # removed initial-domain values, conservatively retain the current
            # path as justification for those exclusions as well.
            if domains[var]!=self.domains[var]:
                child_explanations.update(path)
            conflict=frozenset(child_explanations)
            if self.options.get('learning',False) and tuple(sorted(conflict)) not in self.nogoods:
                self.nogoods.append(tuple(sorted(conflict)))
                self.tick('resolved_conflicts')
            return conflict, False
        return None, True

    def run(self):
        reason = None
        try:
            self.visit(dict(self.domains))
        except ConstraintLimit as error:
            reason = str(error)
        return {"schema":"kryptos.finite-relation-search.v1", "complete":reason is None, "limit":reason,
            "hard_identity":self.hard_identity, "objective_identity":self.objective_identity,
            "candidates":[{"assignment":dict(zip(self.names,values)), "score":score} for score,values in self.retained],
            "feasible_assignments_evaluated":self.feasible_count, "work":dict(self.work),
            "learned":{"hard_identity":self.hard_identity, "objective_identity":self.objective_identity,
                "nogoods":[[list(x) for x in clause] for clause in self.nogoods],"score_exclusions":self.exclusions},
            "score_exclusions":self.exclusions, "authenticated_solution":False,
            "interpretation":"Exact top-k only when complete; hard tuple conflicts and score exclusions are separate. Declared relations are hypotheses, not discovered Kryptos facts."}


def run(request):
    if isinstance(request,dict) and 'method' in request:
        if set(request)!={'method','parameters'}:
            raise ValueError('Method dispatch requires exactly method and parameters')
        if request['method']=='affine':
            return run_affine(request['parameters'])
        if request['method']=='smt':
            from .constraint_smt import run as run_smt
            return run_smt(request['parameters'])
        if request['method']=='family_cover':
            from .constraint_coverage import run as run_cover
            return run_cover(request['parameters'])
        if request['method']=='symmetry':
            from .constraint_symmetry import run as run_symmetry
            return run_symmetry(request['parameters'])
        if request['method']=='tools':
            from .constraint_tools import run as run_tools
            return run_tools(request['parameters'])
        if request['method']=='coverage_proof':
            from .constraint_cover_proof import create
            return create(request['parameters'])
        if request['method'] in ('autokey','null_padding','unknown_alphabet_routes'):
            from . import constraint_models
            return getattr(constraint_models,request['method'])(request['parameters'])
        raise ValueError('Unknown constraint method; omit method for explicit finite relations')
    return RelationSearch(request).run()


def run_affine(request):
    """Adapter from a real optimize-plus cipher request to exact factor tables.

    Materialization is bounded and separately counted; a rejected table cap is
    not an infeasible cipher. Each retained plaintext reconstructs its original
    keys and independently replays the literal encryption recipe.
    """
    from .__main__ import _target
    from .next_cli import _optimization_job, _verify
    from .advanced_cli import _candidate
    from .constraint_algebra import sparse_field, plaintext_coordinate_field
    from dataclasses import replace
    allowed={"cipher_request","options","top","max_work","max_solutions","max_factor_rows","sparse_basis","plaintext_coordinates"}
    if not isinstance(request,dict) or set(request)-allowed:
        raise ValueError("Unknown affine constraint adapter field")
    job=_optimization_job(request.get('cipher_request'),_target)
    if job['algebra_budget'] is not None:
        return job['algebra_budget']
    solution=job['solution']
    if not solution.feasible:
        return {"schema":"kryptos.affine-relation-search.v1","complete":True,"feasible":False,"candidates":[],"algebra":solution.summary()}
    sparse=request.get('sparse_basis',False)
    if type(sparse) is not bool:
        raise ValueError("sparse_basis must be Boolean")
    basis_reports=[]
    if type(request.get('plaintext_coordinates',False)) is not bool:
        raise ValueError('plaintext_coordinates must be Boolean')
    if sparse and request.get('plaintext_coordinates',False):
        raise ValueError('Choose sparse_basis or plaintext_coordinates; they are alternative bases')
    if request.get('plaintext_coordinates',False):
        a,ra=plaintext_coordinate_field(solution.field2)
        b,rb=plaintext_coordinate_field(solution.field13)
        if job['layer_model']=='scheduled':
            solution=replace(solution,linear=replace(solution.linear,field2=a,field13=b))
        else:
            solution=replace(solution,field2=a,field13=b)
        basis_reports=[ra,rb]
    if sparse:
        a,ra=sparse_field(solution.field2)
        b,rb=sparse_field(solution.field13)
        if job['layer_model']=='scheduled':
            solution=replace(solution,linear=replace(solution.linear,field2=a,field13=b))
        else:
            solution=replace(solution,field2=a,field13=b)
        basis_reports=[ra,rb]
    affine=solution.affine_plaintext()
    names=[f'x{i:04d}' for i in range(len(affine['domains']))]
    # A zero-dimensional affine family still has one representative.
    domains={v:list(range(size)) for v,size in zip(names,affine['domains'])} or {'constant':[0]}
    factors=[]
    p,q=job['model'].alpha.as_integer_ratio()
    mask=set(job['score_mask'])
    cap=_int(request.get('max_factor_rows',200000),'max_factor_rows',1,200000)
    table_rows=0
    for start in range(len(job['text'])-job['model'].order+1):
        positions=range(start,start+job['model'].order)
        if any(i in mask for i in positions):
            continue
        indices=[j for j,col in enumerate(affine['columns']) if any(col[i] for i in positions)]
        scope=[names[j] for j in indices]
        count=math.prod(affine['domains'][j] for j in indices)
        if table_rows+count>cap:
            raise ConstraintLimit("Affine n-gram table construction exceeds max_factor_rows; use the lazy optimizer instead")
        rows=[]
        for values in product(*(range(affine['domains'][j]) for j in indices)):
            gram=''.join(affine['alphabet'][(affine['base'][i]+sum(affine['columns'][j][i]*value for j,value in zip(indices,values)))%26] for i in positions)
            rows.append(list(values)+[job['model'].counts.get(gram,0)*q+p])
        table_rows+=len(rows)
        factors.append({'scope':scope,'rows':rows})
    def plaintext_tie(values):
        if not names:
            return solution.plaintext()
        return solution.plaintext(values[:solution.dimensions_mod2],values[solution.dimensions_mod2:])
    result=RelationSearch({'domains':domains,'factors':factors,'objective':'product',
        **{k:v for k,v in request.items() if k in ('options','top','max_work','max_solutions')}},tie_key=plaintext_tie).run()
    candidates=[]
    for row in result['candidates']:
        values=[row['assignment'][v] for v in names]
        a=values[:solution.dimensions_mod2]
        b=values[solution.dimensions_mod2:]
        candidate=solution.candidate(a,b)
        if job['layer_model']=='general':
            candidate=_candidate(candidate,job['stages'],solution.alphabet,job['text'],job['known'])
        candidate=_verify(candidate,job['text'],job['known'])
        candidate['exact_objective_hex']=hex(row['score'])
        candidate['technique']='Finite affine n-gram tables with optional sparse basis and exact relation branch search'
        candidates.append(candidate)
    result.update(schema='kryptos.affine-relation-search.v1',candidates=candidates,
        preparation={'factor_table_rows':table_rows,'algebra_scalar_operations':solution.work,'sparse_basis':basis_reports,
            'candidate_reconstruction_replays':len(candidates),
            'recipe_conversion_replays':len(candidates) if job['layer_model']=='general' else 0,
            'final_verification_replays':len(candidates),
            'literal_replays':len(candidates)*(3 if job['layer_model']=='general' else 2)},
        cipher_request=request['cipher_request'], distinct_plaintext_count=solution.distinct_plaintext_count,
        ranking_tie_convention='plaintext lexicographic order; original recipe keys reconstructed and literal replay retained')
    return result


def relational_join(left_scope, left_rows, right_scope, right_rows, *, max_rows=200000):
    """Exact natural join, usable as a meet-in-the-middle stage relation join."""
    if len(set(left_scope)) != len(left_scope) or len(set(right_scope)) != len(right_scope):
        raise ValueError("Join scopes must contain unique names")
    if len(left_rows)+len(right_rows) > max_rows:
        raise ConstraintLimit("Join input-row cap")
    shared = tuple(v for v in left_scope if v in right_scope)
    new = tuple(v for v in right_scope if v not in left_scope)
    lpositions = tuple(left_scope.index(v) for v in shared)
    rpositions = tuple(right_scope.index(v) for v in shared)
    extras = tuple(right_scope.index(v) for v in new)
    index = defaultdict(list)
    for row in right_rows:
        if len(row) != len(right_scope):
            raise ValueError("Join row width mismatch")
        index[tuple(row[i] for i in rpositions)].append(row)
    output, probes = set(), 0
    for row in left_rows:
        if len(row) != len(left_scope):
            raise ValueError("Join row width mismatch")
        for other in index[tuple(row[i] for i in lpositions)]:
            probes += 1
            output.add(tuple(row)+tuple(other[i] for i in extras))
            if len(output) > max_rows:
                raise ConstraintLimit("Join output-row cap")
    return {"scope":list(left_scope)+list(new), "rows":[list(x) for x in sorted(output)],
        "work":{"input_rows":len(left_rows)+len(right_rows), "matched_pairs":probes,
                "all_pairs_reference":len(left_rows)*len(right_rows)}}


def disjunctive_relation(scope, alternatives):
    """Literal OR of separately labeled finite crib/fractionation hypotheses."""
    rows = set()
    witnesses = defaultdict(list)
    for label, alternative in alternatives.items():
        for row in alternative:
            if len(row) != len(scope):
                raise ValueError("Disjunctive relation row width mismatch")
            row = tuple(row)
            rows.add(row)
            witnesses[row].append(label)
    return {"scope":list(scope), "rows":[list(x) for x in sorted(rows)]}, [
        {"row":list(row), "hypotheses":witnesses[row]} for row in sorted(rows)]
