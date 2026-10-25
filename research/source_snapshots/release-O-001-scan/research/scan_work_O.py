"""Finite work-count controls; no wall-clock or Kryptos recovery claim."""
import argparse
import itertools
import json
import math
from pathlib import Path
import random
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.accelerated import _cpu_rank, _cuda_certified_filter, scan_batch
from kryptos.certified_scores import overlapping_indices


def oracle(affine,offset,count,top,scoring,order):
    starts,codes,p,q=scoring
    rows=[]
    for number,point in enumerate(itertools.product(*(range(d) for d in affine['domains']))):
        if number<offset:
            continue
        if number>=offset+count:
            break
        text=[(base+sum(v*c[i] for v,c in zip(point,affine['columns'])))%26
              for i,base in enumerate(affine['base'])]
        factors=[]
        for start in starts:
            code=sum(text[start+j]*26**(order-1-j) for j in range(order))
            factors.append(codes.get(code,0)*q+p)
        rows.append((math.prod(factors),''.join(affine['alphabet'][c] for c in text),number))
    return [(s,n) for s,t,n in sorted(rows,key=lambda row:(-row[0],row[1],row[2]))[:top]]


def run(cuda=False):
    rng=random.Random(97025)
    cases=points=0
    for length,order,p in itertools.product((7,13),(1,2,3),(0,1,3)):
        affine={'base':[rng.randrange(26) for _ in range(length)],'domains':[2,3,5],
            'columns':[[rng.choice((0,0,0,1,13)) for _ in range(length)] for _ in range(3)],
            'alphabet':'BACDEFGHIJKLMNOPQRSTUVWXYZ'}
        starts=[i for i in range(length-order+1) if 3 not in range(i,i+order)]
        scoring=(starts,{rng.randrange(26**order):rng.randrange(1,9) for _ in range(30)},p,4)
        for offset,count in ((0,30),(4,7),(13,17),(29,1)):
            top=min(5,count)
            expected=oracle(affine,offset,count,top,scoring,order)
            work={}
            actual,_=_cpu_rank(affine,offset,count,top,scoring,order,work=work)
            assert expected==actual
            assert work['window_factor_evaluations']<=count*len(starts)
            cases+=1
            points+=count
    comparisons=[]
    for name,columns in [('sparse',[[13]+[0]*39,[2]+[0]*39]),('dense',[[13]*40,[2]*40])]:
        affine={'base':[0]*40,'domains':[2,13],'columns':columns,'alphabet':'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
        scoring=(list(range(38)),{0:9,2*26**2:7},1,2)
        a,b={},{}
        baseline,_=_cpu_rank(affine,0,26,8,scoring,3,incremental=False,work=a)
        actual,_=_cpu_rank(affine,0,26,8,scoring,3,work=b)
        assert baseline==actual==oracle(affine,0,26,8,scoring,3)
        comparisons.append({'case':name,'baseline':a,'incremental':b,'exact_ranking_equal':True})
    result={'schema':'kryptos.scan-work-O.v1','cpu_oracle_cases':cases,'oracle_candidate_visits':points,
        'comparisons':comparisons,'cuda':{'executed':False},
        'limits':['Fixed mechanistic controls, previously observed during tests; no reserved recovery-rate claim.',
                  'Candidate counts are unchanged; fewer factor evaluations are a separate metric.',
                  'GPU compaction changes host transfer, not the set of mathematical candidates.',
                  'Optional measured backend calibration adds work; it is not a search-efficiency improvement.']}
    if cuda:
        from kryptos.cuda_environment import load_cupy
        from kryptos.accelerated import probe_backend
        hardware=probe_backend()
        assert hardware['cuda']['ready'] and hardware['cuda']['compiled_kernel_verified']
        cp=load_cupy()
        interval_cases=0
        samples=[([0]*64,[0]*64),([2**64-10]*33,[2**64-1]*33)]
        for size in (1,17,256):
            lows=[rng.randrange(2**63,2**63+1024) for _ in range(size)]
            samples.append((lows,[v+rng.randrange(8) for v in lows]))
        for low,high in samples:
            for top in sorted({1,min(5,len(low)),len(low)}):
                expected,cutoff=overlapping_indices(low,high,top)
                indices,actual,width=_cuda_certified_filter(cp.asarray(low,dtype=cp.uint64),cp.asarray(high,dtype=cp.uint64),top)
                assert indices.get().tolist()==expected and cutoff==actual
                assert width==max(b-a for a,b in zip(low,high))
                interval_cases+=1
        request={'ciphertext':'BCDEFGHIJKLM','cribs':[],'alphabet':'standard',
                 'stages':[{'operation':'substitution','period':2}],
                 'model_path':str(ROOT/'research/models/multilingual-001/artifacts/pg1342-english-trigram.json')}
        rows=[]
        for offset in (0,256,512):
            cpu=scan_batch(request,offset=offset,batch_size=128,top=5)
            gpu=scan_batch(request,backend='cuda',offset=offset,batch_size=128,top=5)
            extract=lambda r:[(c['plaintext'],c['score_exact'],c['index']) for c in r['candidates']]
            assert extract(cpu)==extract(gpu)
            rows.append({'offset':offset,'evaluated_per_backend':128,'certification':gpu['certification'],
                         'retained_exact_ranking_equal':True,'cpu_work':cpu['work']})
        auto=scan_batch(request,backend='auto-measured',batch_size=128,top=5)
        cached=scan_batch(request,backend='auto-measured',offset=128,batch_size=128,top=5)
        assert auto['backend_selection'].get('exact_sample_agreement')
        assert cached['backend_selection']['cache_hit']
        result['cuda']={'executed':True,'hardware':hardware,'interval_oracle_cases':interval_cases,'pages':rows,
            'calibration':auto['backend_selection'],'cached_calibration':cached['backend_selection']}
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--cuda',action='store_true')
    args=parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Preserve prior evidence; use a fresh output')
    result=run(args.cuda)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'cpu_oracle_cases':result['cpu_oracle_cases'],'cuda_executed':result['cuda']['executed']}))
