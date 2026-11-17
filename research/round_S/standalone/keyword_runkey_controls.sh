#!/bin/sh
# Controls for keyword_runkey.py: 3 shuffles of K4 and one planted message (keyword alphabet PARCHMENT for plain and cipher, standard key alphabet, English running key).
TXT="$1"
python3 - "$TXT" <<'PY'
import random, subprocess, sys
from k4lib import C4, STD, PLAIN
from keyword_runkey import keyed
rng=random.Random(11)
for s in range(3):
    ct=list(C4); rng.shuffle(ct)
    print(subprocess.run([sys.executable,"keyword_runkey.py",sys.argv[1],"".join(ct),f"shuffle {s}"],capture_output=True,text=True).stdout.split("\n")[2])
A=keyed("PARCHMENT"); key="ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEF"
pt=list("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGWHILETHESHADOWSLENGTHENACROSSTHECOURTYARDANDTHECLOCKTOWERCHIMESSEVEN"[:97])
for i,ch in PLAIN.items(): pt[i]=ch
ct="".join(A[(A.index(p)+STD.index(k))%26] for p,k in zip(pt,key))
out=subprocess.run([sys.executable,"keyword_runkey.py",sys.argv[1],ct,"plant PARCHMENT"],capture_output=True,text=True).stdout.split("\n")
print(out[2]); print(out[-2])
PY
