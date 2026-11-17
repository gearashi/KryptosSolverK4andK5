"""Tiny exact linear-consistency tester mod 26 (via mod 2 and mod 13)."""
from math import log10
def _elim(rows, m):
    rows=[[x%m for x in r] for r in rows]; nc=len(rows[0])-1; rank=0
    for c in range(nc):
        piv=next((r for r in range(rank,len(rows)) if rows[r][c]),None)
        if piv is None: continue
        rows[rank],rows[piv]=rows[piv],rows[rank]; iv=pow(rows[rank][c],-1,m)
        rows[rank]=[(x*iv)%m for x in rows[rank]]
        for r in range(len(rows)):
            if r!=rank and rows[r][c]:
                f=rows[r][c]; rows[r]=[(x-f*y)%m for x,y in zip(rows[r],rows[rank])]
        rank+=1
        if rank==len(rows): break
    return rank, all(r[-1]==0 for r in rows[rank:])
def test(rows):
    """rows: list of [coefs..., rhs]. Returns (consistent, score_digits, residual_equations_min)."""
    if not rows: return True,0.0,0
    r2,c2=_elim(rows,2); r13,c13=_elim(rows,13); ne=len(rows)
    return (c2 and c13), (ne-r2)*log10(2)+(ne-r13)*log10(13), ne-max(r2,r13)
