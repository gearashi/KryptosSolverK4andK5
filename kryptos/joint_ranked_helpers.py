"""Optional exact reductions for the ranked whole-column/repeating-key search.

All functions operate on declared finite domains. No language heuristic removes
a compatible assignment; a score bound is an upper bound, never a witness.
"""
import math

from . import columnar
from .joint_columnar import _propagate

FULL = (1 << 26)-1


def values(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length()-1
        mask -= bit


def singleton_values(masks):
    return [next(values(mask)) if mask.bit_count()==1 else None for mask in masks]


def equivalent_chunks(ciphertext, pattern, period, order, budget):
    """Slots may exchange source columns iff the complete decryption agrees.

    Equality here is sufficient, not a maximal symmetry detector. ST uses the
    original source phase. TS additionally requires equal destination phases.
    """
    groups,offset = {},0
    for slot,length in enumerate(pattern):
        budget.tick("symmetry_setup_slots")
        budget.work["symmetry_setup_letters"]+=length
        signature = (length,ciphertext[offset:offset+length],offset%period if order=="TS" else None)
        groups.setdefault(signature,[]).append(slot)
        offset += length
    return [group for group in groups.values() if len(group)>1]


def ordered_groups(domains, groups, budget):
    """Keep supports for strictly increasing column labels within each group.

    The greedy smallest feasible prefix and largest feasible suffix characterize
    support in an increasing chain. Other constraints can only remove supports,
    so this remains a necessary filter when combined with all-different/key CSP.
    """
    current = [tuple(domain) for domain in domains]
    removed = 0
    for group in groups:
        lower,previous = {},-1
        for slot in group:
            lower[slot] = previous
            choices=[]
            for col in current[slot]:
                budget.tick("symmetry_edge_checks")
                if col>previous:choices.append(col)
            if not choices:return None,removed
            previous=min(choices)
        upper,following = {},len(current)
        for slot in reversed(group):
            upper[slot] = following
            choices=[]
            for col in current[slot]:
                budget.tick("symmetry_edge_checks")
                if col<following:choices.append(col)
            if not choices:return None,removed
            following=max(choices)
        for slot in group:
            supported=tuple(col for col in current[slot] if lower[slot]<col<upper[slot])
            removed += len(current[slot])-len(supported)
            current[slot]=supported
    return current,removed


def reduce_joint(domains,key_domains,requirements,budget,*,fixed_point=False,groups=()):
    """Sound fixed-point matching/key propagation, optionally symmetry reduced.

    With fixed_point off only assigned-edge key implications and a necessary
    perfect matching are used. With it on, the counting solver's audited exact
    matching-support filter and phase supports are reused without modification.
    """
    current,masks=[tuple(d) for d in domains],list(key_domains)
    tuples={edge:tuple(req.items()) for edge,req in requirements.items()}
    before=budget.work["states"]
    removed_total=0
    try:
        while True:
            old=(tuple(current),tuple(masks))
            if groups:
                current,removed=ordered_groups(current,groups,budget)
                removed_total+=removed
                if current is None:
                    budget.work["symmetry_rejections"]+=1
                    return None,removed_total
            if fixed_point:
                result=_propagate(current,masks,tuples,budget)
                if result is None:return None,removed_total
                current,masks,_=result
                if not groups:return (current,masks),removed_total
            else:
                filtered=[]
                for slot,domain in enumerate(current):
                    kept=[]
                    for col in domain:
                        valid=True
                        for phase,value in requirements[slot,col].items():
                            budget.tick("assigned_key_edge_checks")
                            if not masks[phase] & (1<<value):
                                valid=False
                                break
                        if valid:kept.append(col)
                    filtered.append(tuple(kept))
                if columnar._matching(filtered,budget) is None:
                    budget.work["matching_rejections"]+=1
                    return None,removed_total
                current=filtered
                for slot,domain in enumerate(current):
                    if len(domain)==1:
                        for phase,value in requirements[slot,domain[0]].items():
                            budget.tick("assigned_key_implications")
                            masks[phase]&=1<<value
                            if not masks[phase]:return None,removed_total
            if old==(tuple(current),tuple(masks)):
                return (current,masks),removed_total
    finally:
        budget.work["propagation_states"]+=budget.work["states"]-before
        budget.work["symmetry_edges_removed"]+=removed_total


class SharedKeyBound:
    """Exact gram reachability on fixed mappings; unmapped letters are relaxed.

    At a mapped position, a proposed plaintext letter determines its unique
    additive key residue. Equal phases must agree and belong to their current
    (possibly non-singleton) domain. Unmapped positions are unconstrained. Thus
    every true gram passes the test. Multiplying these independent maxima is
    still an admissible whole-message upper bound.
    """
    def __init__(self,alphabet,cipher,counts,p,q,cache_entries):
        self.index={letter:i for i,letter in enumerate(alphabet)}
        self.cipher,self.counts,self.p,self.q=cipher,counts,p,q
        self.grams=sorted(counts.items(),key=lambda item:(-item[1],item[0]))
        self.cache,self.limit={},cache_entries

    def upper(self,bindings,key_domains,budget):
        phases=sorted({binding[1] for binding in bindings if binding is not None})
        signature=(tuple(bindings),tuple((phase,key_domains[phase]) for phase in phases))
        budget.tick("shared_bound_cache_lookups")
        if signature in self.cache:
            budget.work["shared_bound_cache_hits"]+=1
            return self.cache[signature]
        budget.work["shared_bound_cache_misses"]+=1
        maximum=0
        for gram,count in self.grams:
            budget.tick("shared_bound_grams_checked")
            required={}
            valid=True
            for letter,binding in zip(gram,bindings):
                if binding is None:continue
                budget.tick("shared_bound_phase_checks")
                c,phase=binding
                plain=self.index[letter]
                key=(c+plain if self.cipher=="beaufort" else plain-c if self.cipher=="variant" else c-plain)%26
                if not key_domains[phase] & (1<<key) or (phase in required and required[phase]!=key):
                    valid=False
                    break
                required[phase]=key
            if valid:
                maximum=count
                break
        upper=maximum*self.q+self.p
        if len(self.cache)<self.limit:
            self.cache[signature]=upper
            budget.work["shared_bound_cache_inserts"]+=1
        return upper


def symmetry_record(pattern,groups):
    return dict(pattern=list(pattern),equivalent_slot_groups=[list(g) for g in groups],
        labelled_orbit_size_decimal=str(math.prod(math.factorial(len(group)) for group in groups)),
        representative="Ascending source column labels in each equivalent output-slot group; unchanged key.")
