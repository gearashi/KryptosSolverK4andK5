"""Independent tiny irregular-cell oracle for the P joint source review.

Fixed before execution: four plaintext positions with unsorted/nonconsecutive
physical column labels, two directions, ST/TS, all three equations, period2.
This is a geometry/tie regression, not a performance benchmark or K4 search.
"""
import argparse
import hashlib
from itertools import permutations, product
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.joint_ranked import rank_joint_columnar
from kryptos.language import CorpusDocument,train_ngram_model

FILES=['research/review_P_joint_oracle.py','kryptos/joint_ranked.py',
       'kryptos/joint_ranked_helpers.py','kryptos/joint_columnar.py','kryptos/columnar.py',
       'kryptos/language.py','kryptos/explanations.py','kryptos/search_runtime.py',
       'kryptos/ciphers.py','kryptos/data.py']


def run():
    before={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}
    letters='BACDEFGHIJKLMNOPQRSTUVWXYZ'
    cells=[(3,7),(-2,-5),(0,7),(9,-5)]
    ciphertext='ABAB'
    model=train_ngram_model([CorpusDocument('ABABAAAABACBBAAC','independent irregular-cell review')],
                            label='P irregular-cell review',order=2)
    p,q=model.alpha.as_integer_ratio(); rows=[]; oracle_visits=0
    for reverse,order,cipher in product((False,True),('ST','TS'),('vigenere','beaufort','variant')):
        answers={}
        for labels in permutations((-5,7)):
            route=[]
            for label in labels:
                route.extend(sorted((i for i,(_,column) in enumerate(cells) if column==label),
                                    key=lambda i:cells[i][0],reverse=reverse))
            for key in product(range(26),repeat=2):
                plain=['']*4
                for j,i in enumerate(route):
                    c=letters.index(ciphertext[j]); k=key[(i if order=='ST' else j)%2]
                    residue=(k-c if cipher=='beaufort' else c+k if cipher=='variant' else c-k)%26
                    plain[i]=letters[residue]
                text=''.join(plain); score=1
                for i in range(3):score*=model.counts.get(text[i:i+2],0)*q+p
                representative=(labels,''.join(letters[v] for v in key))
                if text not in answers or representative<answers[text][1]:
                    answers[text]=(score,representative)
                oracle_visits+=1
        expected=sorted(answers.items(),key=lambda item:(-item[1][0],item[0]))[:5]
        result=rank_joint_columnar(ciphertext,[],model=model,period=2,order=order,cipher=cipher,
            alphabet=letters,cells=cells,column_direction='bottom_to_top' if reverse else 'top_to_bottom',
            top=5,propagation='fixed_point',early_segmentation=True,branching='constrained',
            score_bound='shared_key',symmetry='identical_chunks',pruning='admissible',
            max_states=200000,time_limit_seconds=5)
        actual=[(c['plaintext'],(int(c['score_exact'],16),(tuple(c['column_order']),c['key_pattern'])))
                for c in result['candidates']]
        assert result['complete'] and actual==expected,(reverse,order,cipher)
        assert result['top_k_exact'] and not result['enumeration_complete']
        assert result['column_orders_visited'] is None and result['total_column_orders'] is None
        rows.append(dict(direction='bottom_to_top' if reverse else 'top_to_bottom',order=order,cipher=cipher,
                         complete=True,canonical_top5_matches=True,oracle_assignments=1352))
    after={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}
    assert before==after
    return dict(schema='kryptos.review-P-joint-irregular.v1',passed=True,cases=rows,
        oracle_assignments=oracle_visits,inputs_before=before,inputs_after=after,
        scope='Only twelve fixed irregular-cell cases. No efficacy, general proof or K4/K5 claim.')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Use a fresh output')
    result=run();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(passed=True,cases=len(result['cases']),oracle_assignments=result['oracle_assignments'])))
