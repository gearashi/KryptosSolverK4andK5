"""Controls for linear_battery: planted messages inside the model class must be flagged; shuffled ciphertexts must not.
Usage: python3 battery_controls.py /path/to/linear_battery [nshuffles]"""
import random, subprocess, sys
from k4lib import C4, STD, KRY
exe=sys.argv[1]; nsh=int(sys.argv[2]) if len(sys.argv)>2 else 20
N=97; crib={i:ch for s,w in ((21,"EASTNORTHEAST"),(63,"BERLINCLOCK")) for i,ch in enumerate(w,s)}
def run(ct):
    out=subprocess.run([exe,ct],capture_output=True,text=True).stdout.strip().split("\n")
    return [l for l in out if l.startswith("FLAG")], out[-1]
rng=random.Random(2026)
def plain():
    filler="THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVEN"
    p=list(filler[:N])
    for i,ch in crib.items(): p[i]=ch
    return "".join(p)
def plant(kind):
    P=plain(); pa,ca=KRY,KRY
    A=[rng.randrange(26) for _ in range(30)]; B=[rng.randrange(26) for _ in range(40)]
    c=[]; keys=[]
    for i in range(N):
        if kind=="per7+per5": k=A[i%7]+B[i%5]
        elif kind=="per7+row7+prog": k=A[i%7]+B[(i+1)//7]+3*i
        elif kind=="per3+ptauto7":  k=A[i%3]+(5*pa.index(P[i-7]) if i>=7 else B[i])
        elif kind=="per2+ctauto7": k=A[i%2]+(11*ca.index(c[i-7]) if i>=7 else B[i])
        elif kind=="per4+keyauto5": k=A[i%4]+(7*keys[i-5] if i>=5 else B[i])
        keys.append(k%26); c.append(ca[(pa.index(P[i])+k)%26])
    return "".join(c)
for kind in ["per7+per5","per7+row7+prog","per3+ptauto7","per2+ctauto7","per4+keyauto5"]:
    fl,last=run(plant(kind)); print("PLANT",kind,"flags:",len(fl)); [print("   ",l) for l in fl[:3]]
tot=0
for s in range(nsh):
    ct=list(C4); rng.shuffle(ct); fl,last=run("".join(ct)); tot+=len(fl)
    if fl: print("SHUFFLE",s,len(fl),fl[0])
print("shuffles:",nsh,"total false flags:",tot); print("real K4:",run(C4))
