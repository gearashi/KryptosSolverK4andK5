"""Controls for trifid_allcubes: planted Trifid messages (random cube) must survive at the true setting; shuffles of K4 give the false-survivor rate."""
import random, itertools
from k4lib import C4, PLAIN
from trifid_allcubes import SYM, sweep
rng=random.Random(5)
filler="THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVENX"
def trifid_enc(pt, cube, p, s):
    inv={v:k for k,v in cube.items()}; n=len(pt); starts=sorted({0}|{i for i in range(n) if i%p==s%p})+[n]; out=[]
    for b0,b1 in zip(starts,starts[1:]):
        blk=pt[b0:b1]; stream=[cube[x][c] for c in range(3) for x in blk]
        out+= [inv[tuple(stream[3*j:3*j+3])] for j in range(len(blk))]
    return "".join(out)
def trifid_dec(ct, cube, p, s):
    inv={v:k for k,v in cube.items()}; n=len(ct); starts=sorted({0}|{i for i in range(n) if i%p==s%p})+[n]; out=[]
    for b0,b1 in zip(starts,starts[1:]):
        blk=ct[b0:b1]; L=len(blk); stream=[t for x in blk for t in cube[x]]
        out+=[inv[(stream[j],stream[L+j],stream[2*L+j])] for j in range(L)]
    return "".join(out)
triples=list(itertools.product(range(3),repeat=3))
def cube():
    t=triples[:]; rng.shuffle(t); return dict(zip(SYM,t))
for variant,p,s,direction in [("n",7,3,"enc"),("q",7,0,"enc"),("n",10,4,"dec"),("q",14,0,"dec")]:
    while True:
        cb=cube(); pt=list(filler[:97])
        for i,ch in PLAIN.items(): pt[i]=ch
        pt="".join(pt); full=("X"+pt) if variant=="q" else pt
        ct=trifid_enc(full,cb,p,s) if direction=="enc" else trifid_dec(full,cb,p,s)
        assert (trifid_dec(ct,cb,p,s) if direction=="enc" else trifid_enc(ct,cb,p,s))==full
        if variant=="n" or ct[0]=="?": break
    c97=ct[1:] if variant=="q" else ct
    res=sweep(c97,PLAIN); surv=[(k,v) for k,v in res.items() if v]
    print(f"PLANT variant={variant} period={p} start={s} dir={direction}: true setting survives:", s in res[(variant,direction,p)], "| all survivors:",surv)
tot=0
for k in range(20):
    ct=list(C4); rng.shuffle(ct); res=sweep("".join(ct),PLAIN); n=sum(len(v) for v in res.values()); tot+=n
print("20 shuffles of K4: surviving settings in total:",tot,"of",20*19204)
