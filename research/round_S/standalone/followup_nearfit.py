"""Follow-up of the strongest near-fit of battery 2 (score 7.1, below the 7.5 flag line):
   S[p_i] + a + g*((i+1) div 24) + b*i + al*kry(c_{i-24}) = std(c_i)   (unknown plaintext alphabet S)
Enumerate every (al,b,g), require S to be a one-to-one function on the clue letters, then print the implied letter pattern of the rest."""
from k4lib import C4, STD, KRY, PLAIN
sol=[]
for al in range(26):
    for b in range(26):
        for g in range(26):
            v={i:(STD.index(C4[i])-al*KRY.index(C4[i-24])-b*i-g*((i+1)//24))%26 for i in range(24,97)}
            f={};h={};ok=True
            for i,ch in PLAIN.items():
                if i<24: continue
                if f.setdefault(ch,v[i])!=v[i] or h.setdefault(v[i],ch)!=ch: ok=False;break
            if ok: sol.append((al,b,g,v,h))
print("solutions (al,b,g):",[(s[0],s[1],s[2]) for s in sol])
for al,b,g,v,h in sol:
    txt="".join(h.get(v[i],".") for i in range(24,97)); unk=len({v[i] for i in range(24,97) if v[i] not in h})
    print(al,b,g,"decoded from position 25 (known letters shown, '.' = letter outside the clue set):"); print("   ",txt, "| distinct unknown values:",unk)
