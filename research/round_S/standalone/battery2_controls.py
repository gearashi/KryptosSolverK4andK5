"""Controls for linear_battery2 and an exact period table for one-unknown-alphabet periodic ciphers.
Usage: python3 battery2_controls.py /path/to/linear_battery2 [nshuffles]"""
import random, subprocess, sys
from k4lib import C4, STD, KRY
exe=sys.argv[1]; nsh=int(sys.argv[2]) if len(sys.argv)>2 else 20
N=97; crib={i:ch for s,w in ((21,"EASTNORTHEAST"),(63,"BERLINCLOCK")) for i,ch in enumerate(w,s)}
def run(ct):
    out=subprocess.run([exe,ct],capture_output=True,text=True).stdout.strip().split("\n")
    return [l for l in out if l.startswith("FLAG")], out[-1]
rng=random.Random(77)
filler="THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVEN"
P=list(filler[:N])
for i,ch in crib.items(): P[i]=ch
def perm():
    a=list(range(26)); rng.shuffle(a); return a
def plant(kind):
    S=perm(); U=perm(); Uinv=[U.index(v) for v in range(26)]; A=[rng.randrange(26) for _ in range(40)]; c=[]
    for i in range(N):
        p=STD.index(P[i])
        if kind=="A: unknown plain alphabet + period 5":      c.append(KRY[(S[p]+A[i%5])%26])
        elif kind=="B: unknown cipher alphabet + period 3 + row step 7": c.append(STD[Uinv[(KRY.index(P[i])+A[i%3]+4*((i+1)//7))%26]])
        elif kind=="A: unknown plain alphabet + period 2 + ciphertext lag 7 via unknown alphabet":
            c.append(STD[(S[p]+A[i%2]+(U[STD.index(c[i-7])] if i>=7 else A[10+i]))%26])
        elif kind=="D: period 4 + plaintext lag 7 via unknown alphabet": c.append(KRY[(KRY.index(P[i])+A[i%4]+(S[STD.index(P[i-7])] if i>=7 else 0))%26])
    return "".join(c)
planted={}
for kind in ["A: unknown plain alphabet + period 5","B: unknown cipher alphabet + period 3 + row step 7",
             "A: unknown plain alphabet + period 2 + ciphertext lag 7 via unknown alphabet","D: period 4 + plaintext lag 7 via unknown alphabet"]:
    planted[kind]=plant(kind)
    fl,last=run(planted[kind]); print("PLANT",kind,"| flags:",len(fl)); [print("   ",l) for l in fl[:2]]
tot=0
for s in range(nsh):
    ct=list(C4); rng.shuffle(ct); fl,last=run("".join(ct)); tot+=len(fl)
    if fl: print("SHUFFLE",s,len(fl),fl[0])
print("shuffles:",nsh,"total false flags:",tot); print("real K4:",run(C4))
# correctness check below the flag threshold: the true model must come out consistent (score shows how many equations were left to test it)
import re
for kind,pat in [("B: unknown cipher alphabet + period 3 + row step 7","CLET(0,0) PER(3,0) ROWLIN(7,1) |"),
                 ("A: unknown plain alphabet + period 2 + ciphertext lag 7 via unknown alphabet","PLET(0,0) PER(2,0) CAUTOunk(7,0) |"),
                 ("D: period 4 + plaintext lag 7 via unknown alphabet","mode=D rhs=6 | PER(4,0) PAUTOunk(7,0) |")]:
    pr=subprocess.Popen([exe,planted[kind],"0"],stdout=subprocess.PIPE,text=True)   # read line by line: the output is very large
    hit=[l.strip() for l in pr.stdout if pat in l]; pr.wait(); print("TRUE MODEL",kind,"->",hit[:1] or "NOT CONSISTENT (bug)")
