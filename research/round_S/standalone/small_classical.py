"""Exact checks of a few classical position-preserving ciphers against the K4 clue letters (any key, any period)."""
from k4lib import C4, STD, KRY, PLAIN
known=sorted(PLAIN)
# Porta-type (reciprocal, alphabet split in halves): every plain/cipher pair must lie in opposite halves
for an,a in (("std",STD),("kry",KRY)):
    bad=[(PLAIN[i],C4[i]) for i in known if (a.index(PLAIN[i])<13)==(a.index(C4[i])<13)]
    print(f"Porta with {an} alphabet: {len(bad)} of 24 clue letters stay in the same half -> {'excluded' if bad else 'possible'}")
# Slidefair (digraphic Vigenere/Variant/Beaufort): each aligned pair needs one key letter that satisfies both letters
for an,a in (("std",STD),("kry",KRY)):
    for align in (0,1):
        pairs=[(i,i+1) for i in range(align,96,2) if i in PLAIN and i+1 in PLAIN]
        for typ in ("vig","var","beau"):
            ok=0
            for i,j in pairs:
                p1,p2,c1,c2=(a.index(x) for x in (PLAIN[i],PLAIN[j],C4[i],C4[j]))
                if typ=="vig": k1,k2=(p2-c1)%26,(c2-p1)%26
                elif typ=="var": k1,k2=(c1-p2)%26,(p1-c2)%26
                else: k1,k2=(c1+p2)%26,(c2+p1)%26
                ok+= k1==k2
            print(f"Slidefair {typ} {an} alphabet, pairs start {'even' if align==0 else 'odd'}: {ok} of {len(pairs)} known pairs consistent -> {'excluded' if ok<len(pairs) else 'possible'}")
