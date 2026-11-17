"""Running key taken from Kryptos's own texts, clue letters in place (17 Nov 2026).
key letter for position i = T[o + d*i] (wrapping), T = any Kryptos text below or its reverse, every offset o, step d = 1..20.
(a) fixed alphabets: 2 plain x 2 cipher x 2 key alphabets x (vig, beau, var): count of the 24 clue positions that agree (24 = fit).
(b) unknown plaintext alphabet:  S[p_i] = idx(c_i) -/+ idx(t_i) must be a consistent one-to-one map on the 13 clue letters.
(c) unknown ciphertext alphabet: U[c_i] = idx(p_i) +/- idx(t_i) likewise on the 14 cipher letters.
Usage: python3 selfkey.py [cipher97]"""
import sys
from k4lib import C4 as REAL, STD, KRY, PLAIN, K1P,K2P,K3P,K1C,K2C,K3C
C4=sys.argv[1] if len(sys.argv)>1 else REAL
known=sorted(PLAIN)
MORSE="VIRTUALLYINVISIBLEDIGETALINTERPRETATUTISYOURPOSITIONSOSRQSHADOWFORCESLUCIDMEMORY"
TABLEAU="ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"+"".join(STD[r]+(KRY*3)[r:r+30] for r in range(26))+"ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
TABCOLS="".join("".join(row[c] for row in [(STD[r]+(KRY*3)[r:r+30]) for r in range(26)]) for c in range(31))
src={"K1 plain":K1P,"K2 plain":K2P,"K3 plain":K3P,"K1-K3 plain":K1P+K2P+K3P,"K1 cipher":K1C,"K2 cipher":K2C,"K3 cipher":K3C,
     "K1-K3 cipher":K1C+K2C+K3C,"K1-K4 cipher":K1C+K2C+K3C+C4,"K4 cipher":C4,"Morse":MORSE,"tableau rows":TABLEAU,"tableau columns":TABCOLS,
     "KRYPTOS alphabet":KRY,"PALIMPSEST":"PALIMPSEST","ABSCISSA":"ABSCISSA","KRYPTOS":"KRYPTOS","BERLINCLOCK":"BERLINCLOCK"}
src.update({k+" reversed":v[::-1] for k,v in list(src.items())})
ALPH={"std":STD,"kry":KRY}; best=(0,None); ntest=0; fits=[]; ufits=[]
def one_to_one(pairs):
    f={};g={}
    for a,b in pairs:
        if f.setdefault(a,b)!=b or g.setdefault(b,a)!=a: return False
    return True
for name,T in src.items():
    T="".join(ch for ch in T if ch.isalpha()); n=len(T)
    for d in range(1,21):
        for o in range(n):
            t=[T[(o+d*i)%n] for i in known]
            for kn,ka in ALPH.items():
                ti=[ka.index(x) for x in t]
                for cn,ca in ALPH.items():
                    ci=[ca.index(C4[i]) for i in known]
                    for pn,pa in ALPH.items():
                        pi=[pa.index(PLAIN[i]) for i in known]
                        for eq,m in (("vig",sum((c-p-k)%26==0 for c,p,k in zip(ci,pi,ti))),("beau",sum((c+p-k)%26==0 for c,p,k in zip(ci,pi,ti))),("var",sum((p-c-k)%26==0 for c,p,k in zip(ci,pi,ti)))):
                            ntest+=1
                            if m>best[0]: best=(m,(name,d,o,kn,cn,pn,eq))
                            if m>=12: fits.append((m,name,d,o,kn,cn,pn,eq))
                    for sg in (1,-1):   # unknown plaintext alphabet
                        ntest+=1
                        if one_to_one([(PLAIN[i],(c-sg*k)%26) for i,c,k in zip(known,ci,ti)]): ufits.append(("unknown plain",name,d,o,kn,cn,sg))
                for pn,pa in ALPH.items():
                    pi=[pa.index(PLAIN[i]) for i in known]
                    for sg in (1,-1):   # unknown ciphertext alphabet
                        ntest+=1
                        if one_to_one([(C4[i],(p+sg*k)%26) for i,p,k in zip(known,pi,ti)]): ufits.append(("unknown cipher",name,d,o,kn,pn,sg))
print("tests:",ntest,"| best fixed-alphabet agreement:",best,"| fixed fits (>=12 of 24):",fits,"| unknown-alphabet fits:",ufits)
