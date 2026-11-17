"""Battery 6: keyword-mixed alphabets with an English running key, clue letters in place (17 Nov 2026).
For every keyword W (alphabet = W's letters without repeats, then the rest of A-Z) and every assignment of {standard, KRYPTOS, W}
to the plaintext, ciphertext and key alphabets that uses W at least once (19 assignments), and the three tableau equations
(vig c=p+k, beau c=k-p, var c=p-k), derive the 24 key letters at the clue positions and score how English they look
(quadgram log-likelihood over the two fragments, 13 and 11 letters).
Usage: python3 keyword_runkey.py ENGLISH_TEXT_FILE [cipher97 [label]]"""
import sys, re, itertools, numpy as np
from k4lib import C4 as REAL, STD, KRY, PLAIN
text=re.sub(r"[^A-Z]","",open(sys.argv[1],errors="ignore").read().upper())
C4=sys.argv[2] if len(sys.argv)>2 else REAL; label=sys.argv[3] if len(sys.argv)>3 else "real K4"
known=sorted(PLAIN); half=len(text)//2
def quad_table(t):
    a=np.frombuffer(t.encode(),dtype=np.uint8).astype(np.int64)-65; q=((a[:-3]*26+a[1:-2])*26+a[2:-1])*26+a[3:]
    cnt=np.bincount(q,minlength=26**4).astype(np.float64)+0.05; return np.log(cnt/cnt.sum())
Q=quad_table(text[:half])                       # trained on the first half only
def score(L):                                   # L: int array [n,24] of key letters (0-25)
    s=np.zeros(L.shape[0])
    for a,b in ((0,13),(13,24)):
        f=L[:,a:b]; q=((f[:,:-3]*26+f[:,1:-2])*26+f[:,2:-1])*26+f[:,3:]; s+=Q[q].sum(axis=1)
    return s
def words():
    from wordfreq import top_n_list
    from english_words import get_english_words_set
    w=set(x.upper() for x in top_n_list("en",200000))|set(x.upper() for x in get_english_words_set(["web2","gcide"],alpha=True))
    w|=set(re.findall(r"[A-Z]{3,}",open(sys.argv[1],errors="ignore").read().upper()))
    return sorted(x for x in w if re.fullmatch(r"[A-Z]{3,20}",x))
def keyed(w):
    seen=[]; [seen.append(c) for c in w+STD if c not in seen]; return "".join(seen)
if __name__=="__main__":
    W=words(); alph={}
    for w in W: alph.setdefault(keyed(w),w)
    keys=list(alph); n=len(keys)
    A=np.array([[ord(c)-65 for c in a] for a in keys],dtype=np.int64)          # A[n,26]: letter at index
    INV=np.argsort(A,axis=1)                                                   # INV[n,26]: index of letter
    fixed={"std":np.arange(26),"kry":np.array([ord(c)-65 for c in KRY])}
    def letter_at(name): return A if name=="W" else np.tile(fixed[name],(n,1))
    def index_of(name): return INV if name=="W" else np.tile(np.argsort(fixed[name]),(n,1))
    P=np.array([ord(PLAIN[i])-65 for i in known]); C=np.array([ord(C4[i])-65 for i in known])
    top=[]; total=0; allbest=-1e9
    for pa,ca,ka in itertools.product(("std","kry","W"),repeat=3):
        if "W" not in (pa,ca,ka): continue
        pi=index_of(pa)[:,P]; ci=index_of(ca)[:,C]; LA=letter_at(ka)
        for eq,k in (("vig",(ci-pi)%26),("beau",(ci+pi)%26),("var",(pi-ci)%26)):
            L=np.take_along_axis(LA,k,axis=1); s=score(L); total+=n
            for j in np.argsort(s)[-3:]: top.append((float(s[j]),alph[keys[j]],pa,ca,ka,eq,"".join(chr(65+x) for x in L[j])))
    top.sort(reverse=True)
    # reference: real English fragments from the held-out half
    rng=np.random.default_rng(1); held=np.frombuffer(text[half:].encode(),dtype=np.uint8).astype(np.int64)-65
    o1=rng.integers(0,len(held)-100,5000); E=np.stack([np.concatenate([held[o:o+13],held[o+42:o+53]]) for o in o1]); es=np.sort(score(E))
    print(f"[{label}] keywords: {len(W)} distinct alphabets: {n} candidates scored: {total}")
    print(f"[{label}] English reference (held-out text, 5000 fragments): 1% {es[50]:.1f}  10% {es[500]:.1f}  median {es[2500]:.1f}")
    for t in top[:5]: print(f"[{label}] top:",f"{t[0]:.1f}",*t[1:])
    print(f"[{label}] share of English fragments scoring above this run's best: {(es>top[0][0]).mean():.3f}")
