"""In-place grid model with an unknown plaintext (or ciphertext) alphabet:  idx(c) = S[p] + K[column] + R[row]  on a grid of width w
whose first cell is `o` cells before K4 (o=1, w=7 is the grid that starts at the "?").  Exact consistency on the clue letters; the number of
clue letters left over as a test is printed.  Usage: python3 grid_tableau.py [cipher97]"""
import sys
from k4lib import C4 as REAL, STD, KRY, PLAIN
from linsolve import test
C4=sys.argv[1] if len(sys.argv)>1 else REAL
known=sorted(PLAIN); pl=sorted(set(PLAIN.values())); cl=sorted({C4[i] for i in known}); n=0; hits=[]
for w in range(2,32):
    for o in range(w):
        rows_used=sorted({(i+o)//w for i in known})
        for side in ("plain","cipher"):
            for an,a in (("std",STD),("kry",KRY)):
                rows=[]
                for i in known:
                    L=[1 if PLAIN[i]==x else 0 for x in pl] if side=="plain" else [1 if C4[i]==x else 0 for x in cl]
                    rows.append(L+[1 if (i+o)%w==j else 0 for j in range(w)]+[1 if (i+o)//w==r else 0 for r in rows_used]+[a.index(C4[i]) if side=="plain" else a.index(PLAIN[i])])
                ok,sc,res=test(rows); n+=1
                if ok and res>=1: hits.append((res,w,o,side,an))
print("models:",n,"| consistent with at least 1 letter left over:",sorted(hits,reverse=True))
