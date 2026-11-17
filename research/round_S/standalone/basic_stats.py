import random, sys
from k4lib import *
print("key index streams at the 24 known positions (in place):")
for name, pa, ca, eq in conventions():
    ks = key_stream(pa, ca, eq)
    a = [ks[i] for i in range(21, 34)]; b = [ks[i] for i in range(63, 74)]
    vals = a + b
    ic = sum(vals.count(v) * (vals.count(v) - 1) for v in set(vals)) / (24 * 23)
    print(f"{name:18s}", " ".join(f"{v:2d}" for v in a), "|", " ".join(f"{v:2d}" for v in b), f" IC={ic:.3f}",
          "".join(STD[v] for v in a), "".join(STD[v] for v in b))
# autocorrelation of the ciphertext
print("lag coincidences C[i]==C[i+L]:", [(L, sum(C4[i] == C4[i+L] for i in range(97-L))) for L in range(1, 30)])
def lagmax(s):
    return max(sum(s[i] == s[i+L] for i in range(len(s)-L)) for L in range(1, 30))
rng = random.Random(1)
obs7 = sum(C4[i] == C4[i+7] for i in range(90))
cnt = 0; cmax = 0; N = 20000
obsmax = lagmax(C4)
for _ in range(N):
    s = list(C4); rng.shuffle(s)
    cnt += sum(s[i] == s[i+7] for i in range(90)) >= obs7
    cmax += lagmax(s) >= obsmax
print("lag-7 coincidences", obs7, "shuffles >=:", cnt / N, "; max over lags 1-29:", obsmax, "shuffles >=:", cmax / N)
# doublets by column, grids with the question mark as cell 0
T = "?" + C4
for w in (7, 14, 21, 31):
    rows = [T[i:i+w] for i in range(0, len(T), w)]
    print("width", w); print("\n".join(rows))
def adj_equal_cols(s, w):
    best = 0
    for c in range(w - 1):
        n = sum(1 for r in range(0, len(s), w) if r + c + 1 < len(s) and s[r+c] == s[r+c+1])
        best = max(best, n)
    return best
obs = adj_equal_cols(T, 7); cnt = 0; cany = 0
obs_any = max(adj_equal_cols(T, w) for w in range(3, 33))
for _ in range(N):
    s = list(C4); rng.shuffle(s); s = "?" + "".join(s)
    cnt += adj_equal_cols(s, 7) >= obs
    cany += max(adj_equal_cols(s, w) for w in range(3, 33)) >= obs_any
print("max equal adjacent-column pairs at width 7:", obs, "shuffles >=:", cnt / N, "; best over widths 3-32:", obs_any, "shuffles >=:", cany / N)
