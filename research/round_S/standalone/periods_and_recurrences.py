"""Exact tables for K4 (in-place reading of the clues):
 1. which periods p survive for a periodic key with (a) fixed alphabets, (b) unknown plaintext alphabet, (c) unknown ciphertext alphabet
 2. key stream obeys a linear recurrence (order d, with constant), a two-lag recurrence, or polynomial + periodic key
Optional argument: alternative 97-letter ciphertext (for controls)."""
import sys, itertools
from k4lib import C4 as REAL, STD, KRY, PLAIN
from linsolve import test
C4=sys.argv[1] if len(sys.argv)>1 else REAL
known=sorted(PLAIN); ALPH={"std":STD,"kry":KRY}
def conv_keys():
    for pn,pa in ALPH.items():
        for cn,ca in ALPH.items():
            yield f"P{pn}/C{cn}/vig",{i:(ca.index(C4[i])-pa.index(PLAIN[i]))%26 for i in known}
            yield f"P{pn}/C{cn}/beau",{i:(ca.index(C4[i])+pa.index(PLAIN[i]))%26 for i in known}
print("== 1. periodic key, exact survivors (period: residual equations) ==")
for name,K in conv_keys():
    s=[]
    for p in range(1,27):
        rows=[[1 if i%p==j else 0 for j in range(p)]+[K[i]] for i in known]; ok,sc,res=test(rows)
        if ok: s.append(f"{p}:{res}")
    print(f"fixed alphabets {name:16s} survive:",", ".join(s) or "none")
pl=sorted(set(PLAIN.values())); cl=sorted({C4[i] for i in known})
for cn,ca in ALPH.items():
    s=[]
    for p in range(1,27):
        rows=[[1 if PLAIN[i]==x else 0 for x in pl]+[1 if i%p==j else 0 for j in range(p)]+[ca.index(C4[i])] for i in known]; ok,sc,res=test(rows)
        if ok: s.append(f"{p}:{res}")
    print(f"unknown plain alphabet, cipher alphabet {cn}: survive:",", ".join(s) or "none")
for pn,pa in ALPH.items():
    s=[]
    for p in range(1,27):
        rows=[[1 if C4[i]==x else 0 for x in cl]+[1 if i%p==j else 0 for j in range(p)]+[pa.index(PLAIN[i])] for i in known]; ok,sc,res=test(rows)
        if ok: s.append(f"{p}:{res}")
    print(f"unknown cipher alphabet, plain alphabet {pn}: survive:",", ".join(s) or "none")
print("== 2. recurrences on the key stream (consistent cases with >=3 residual equations are listed) ==")
segs=[list(range(21,34)),list(range(63,74))]; n=0; hits=0
for name,K in conv_keys():
    for d in range(1,8):
        rows=[[K[i-j] for j in range(1,d+1)]+[1,K[i]] for s in segs for i in s[d:]]
        ok,sc,res=test(rows); n+=1
        if ok and res>=3: hits+=1; print("  order",d,name,"residual",res)
    for t in range(2,10):
        for s_ in range(1,t):
            rows=[[K[i-s_],K[i-t],1,K[i]] for s in segs for i in s[t:]]
            if len(rows)<6: continue
            ok,sc,res=test(rows); n+=1
            if ok and res>=3: hits+=1; print("  two-lag",s_,t,name,"residual",res)
    for deg in (2,3):
        for p in range(1,14):
            rows=[[pow(i,e,26) for e in range(1,deg+1)]+[1 if i%p==j else 0 for j in range(p)]+[K[i]] for i in known]
            ok,sc,res=test(rows); n+=1
            if ok and res>=3: hits+=1; print("  poly deg",deg,"+ period",p,name,"residual",res)
print("recurrence/polynomial models tested:",n,"consistent with >=3 residual equations:",hits)
