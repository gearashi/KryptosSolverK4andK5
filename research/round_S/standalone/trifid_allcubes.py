"""Trifid over 27 symbols (26 letters + '?'), EVERY possible cube, tested against the K4 clue letters (17 Nov 2026).
Text variants: 'q' = '?' + K4 (98 cells, the '?' is a cipher symbol as on Sanborn's 14x31 worksheet); 'n' = K4 alone (97 cells).
Period p, block start s (a block starts at every cell index = s mod p; ends are short blocks, as in the classical cipher).
Direction 'enc': standard Trifid encipherment; 'dec': the maker used the deciphering procedure to encipher.
Per block of n letters with coordinates (a,b,c): stream = a1..an b1..bn c1..cn; cipher letter j has coordinates stream[3j-3..3j-1].
Each clue letter gives equalities between coordinates of symbols; a SAT solver then decides whether ANY assignment of 27 distinct
coordinate triples (any cube) satisfies them.  Exact: 'excluded' means no cube exists.
Usage: python3 trifid_allcubes.py [cipher97]   (other ciphertexts are for controls)"""
import sys, itertools
from pysat.solvers import Cadical153
from k4lib import C4 as REAL, PLAIN
SYM="ABCDEFGHIJKLMNOPQRSTUVWXYZ?"
def constraints(ct, plain, p, s, direction):
    """yield pairs ((sym,coord),(sym,coord)) that must be equal."""
    n=len(ct); starts=sorted({0}|{i for i in range(n) if i%p==s%p}); starts.append(n)
    for b0,b1 in zip(starts,starts[1:]):
        L=b1-b0
        for j in range(L):
            for t in range(3):
                k=3*j+t; src=b0+k%L; coord=k//L          # stream element k = coordinate `coord` of block letter k%L
                if direction=="enc":   # cipher[b0+j].t == plain[src].coord
                    if src in plain: yield (ct[b0+j],t),(plain[src],coord)
                else:                  # plain[b0+j].t == cipher[src].coord
                    if b0+j in plain: yield (plain[b0+j],t),(ct[src],coord)
def feasible(eqs):
    par={}
    def f(x):
        par.setdefault(x,x)
        while par[x]!=x: par[x]=par[par[x]]; x=par[x]
        return x
    for a,b in eqs: par[f(a)]=f(b)
    cls={}; var=lambda s,c: cls.setdefault(f((s,c)),len(cls))
    tri=[tuple(var(s,c) for c in range(3)) for s in SYM]
    if len(set(tri))<27: return False          # two symbols forced onto the same cell
    X=lambda k,v: 3*k+v+1
    S=Cadical153()
    for k in range(len(cls)):
        S.add_clause([X(k,0),X(k,1),X(k,2)])
        for u,v in ((0,1),(0,2),(1,2)): S.add_clause([-X(k,u),-X(k,v)])
    for a,b in itertools.combinations(range(27),2):
        for v in itertools.product(range(3),repeat=3):
            cl={-X(tri[a][c],v[c]) for c in range(3)}|{-X(tri[b][c],v[c]) for c in range(3)}
            S.add_clause(list(cl))
    r=S.solve(); S.delete(); return r
def sweep(c97, plain0, quiet=False):
    res={}
    for variant in ("q","n"):
        ct=("?"+c97) if variant=="q" else c97; sh=1 if variant=="q" else 0
        plain={i+sh:ch for i,ch in plain0.items()}
        for direction in ("enc","dec"):
            for p in range(2,len(ct)+1):
                ok=[s for s in range(p) if feasible(constraints(ct,plain,p,s,direction))]
                res[(variant,direction,p)]=ok
    return res
if __name__=="__main__":
    c97=sys.argv[1] if len(sys.argv)>1 else REAL
    res=sweep(c97,PLAIN); tot=sum(1 for (v,d,p) in res for s in range(p)); surv=sum(len(v) for v in res.values())
    print("settings tested:",tot,"surviving:",surv)
    for v in ("q","n"):
        for d in ("enc","dec"):
            line=[f"{p}:{res[(v,d,p)]}" for p in range(2,(98 if v=='q' else 97)+1) if res[(v,d,p)]]
            print(f"variant={v} direction={d} survivors (period:[block starts]):", "; ".join(line) or "none")
