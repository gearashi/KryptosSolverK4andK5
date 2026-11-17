"""Controls for transpo_periodic: planted messages (transposition + periodic keyed substitution) must be flagged; shuffles must not.
Usage: python3 transpo_controls.py /path/to/transpo_periodic [nshuffles]"""
import random, subprocess, sys
from k4lib import C4, STD, KRY, PLAIN
exe=sys.argv[1]; nsh=int(sys.argv[2]) if len(sys.argv)>2 else 20
rng=random.Random(3)
pt=list("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVEN"[:97])
for i,ch in PLAIN.items(): pt[i]=ch
pt="".join(pt)
def run(ct):
    out=subprocess.run([exe,ct],capture_output=True,text=True).stdout.strip().split("\n"); return [l for l in out if l.startswith("FLAG")],out[-1]
def columnar(n,w,sig,up):
    pi=[]
    for c in sig:
        col=[r*w+c for r in range((n-c+w-1)//w)]; pi+= col[::-1] if up else col
    return pi
def turn(n,w,style,seq):
    R=n//w; out=[]
    for k in range(w):
        c=w-1-k if style&1 else k
        for t in range(R):
            r=R-1-t if style&2 else t; out.append(seq[r*w+c])
    return out
# plant 1: n=97, columnar width 7, random order, read bottom-up; substitute first (KRYPTOS alphabets, vig, key PALIMPSE period 8)
sig=list(range(7)); rng.shuffle(sig); pi=columnar(97,7,sig,1); key="PALIMPSE"
sub=[KRY[(KRY.index(p)+KRY.index(key[i%8]))%26] for i,p in enumerate(pt)]
ct="".join(sub[pi[j]] for j in range(97)); fl,last=run(ct); print("PLANT 1 (97 letters, columnar 7, substitute then transpose) flags:",len(fl)); print("   ",fl[:1])
# plant 2: n=98 with '?', K3-style double turn (width 14 then width 7, bottom-up), transpose first then substitute by cipher position (std alphabets, beau, period 5)
full="?"+pt                      # the plaintext carries the non-letter; search for a setting that puts it on cipher cell 0
for w1,s1,w2,s2 in [(a,b,c,d) for a in (2,7,14,49) for b in range(4) for c in (2,7,14,49) for d in range(4)]:
    pi=turn(98,w2,s2,turn(98,w1,s1,list(range(98))))
    if pi[0]!=0 and (w1,w2)==(14,7): break
q=pi[0]; seq=list(pt); seq.insert(q,"?"); key=[3,17,9,22,5]
ct="".join(STD[(key[j%5]-STD.index(seq[pi[j]]))%26] for j in range(1,98)); assert seq[pi[0]]=="?"
fl,last=run(ct); print(f"PLANT 2 (98 cells, turns w={w1} style={s1} then w={w2} style={s2}, transpose then substitute) flags:",len(fl)); print("   ",fl[:1])
tot=0
for s in range(nsh):
    x=list(C4); rng.shuffle(x); fl,last=run("".join(x)); tot+=len(fl)
    if fl: print("SHUFFLE",s,fl[:2])
print("shuffles:",nsh,"false flags:",tot); print("real K4:",run(C4))
