"""Independent finite controls for optional phase P ranked-joint reductions."""
import itertools
import json
from pathlib import Path
import random
import shutil
import tempfile
import unittest

from kryptos.joint_ranked import rank_joint_columnar, _Budget
from kryptos.joint_ranked_helpers import FULL, reduce_joint, SharedKeyBound, equivalent_chunks
from kryptos.language import CorpusDocument, train_ngram_model
from kryptos.explanations import replay_recipe

A="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALL=dict(propagation="fixed_point",early_segmentation=True,branching="constrained",
         score_bound="shared_key",symmetry="identical_chunks",pruning="admissible")


def encrypt(plain,width,key,cols,order="ST",cipher="vigenere",alphabet=A):
    route=[i for col in cols for i in range(col,len(plain),width)]
    def substitute(letter,phase):
        p,k=alphabet.index(letter),key[phase%len(key)]
        return alphabet[(k-p if cipher=="beaufort" else p-k if cipher=="variant" else p+k)%26]
    if order=="ST":
        intermediate=[substitute(c,i) for i,c in enumerate(plain)]
        return "".join(intermediate[i] for i in route)
    return "".join(substitute(plain[i],j) for j,i in enumerate(route))


def oracle(text,known,width,period,model,order="ST",cipher="vigenere",alphabet=A,mask=None):
    mask=set(known if mask is None else mask)
    starts=[i for i in range(len(text)-model.order+1) if not mask.intersection(range(i,i+model.order))]
    p,q=model.alpha.as_integer_ratio()
    answers={};count=0;route_count=0
    for columns in itertools.permutations(range(width)):
        route=[i for col in columns for i in range(col,len(text),width)]
        this_route=False
        for key in itertools.product(range(26),repeat=min(period,len(text))):
            plain=[None]*len(text)
            for j,i in enumerate(route):
                c=alphabet.index(text[j]);k=key[(i if order=="ST" else j)%period]
                plain[i]=alphabet[(k-c if cipher=="beaufort" else c+k if cipher=="variant" else c-k)%26]
            if any(plain[i]!=c for i,c in known.items()):continue
            count+=1;this_route=True
            plain="".join(plain);score=1
            for i in starts:score*=model.counts.get(plain[i:i+model.order],0)*q+p
            rep=(columns,"".join(alphabet[k] for k in key)+alphabet[0]*max(0,period-len(text)))
            if plain not in answers or rep<answers[plain][1]:answers[plain]=(score,rep)
        route_count+=this_route
    return sorted(answers.items(),key=lambda row:(-row[1][0],row[0])),count,route_count


def fixtures():
    rng=random.Random(71031)
    masks=([0,3],[0,1,4],[1,2,5,6])
    result=[]
    for number in range(12):
        plain="".join(rng.choice("ABCDEFGH") for _ in range(7))
        key=[rng.randrange(6),rng.randrange(6)]
        cols=list(range(3));rng.shuffle(cols)
        order=("ST","TS")[number%2]
        cipher=("vigenere","beaufort","variant")[number%3]
        alphabet=(A,"BACDEFGHIJKLMNOPQRSTUVWXYZ")[number%2]
        result.append(dict(id=f"seeded-{number}",ciphertext=encrypt(plain,3,key,cols,order,cipher,alphabet),
            known={i:plain[i] for i in masks[number%3]},width=3,period=2,order=order,cipher=cipher,alphabet=alphabet))
    return result


class JointPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model=train_ngram_model([CorpusDocument("ABACABADABACABAEABCDEFFEDCBA","P authored")],label="P tests",order=2)

    def check(self,case,options,top=5):
        case=dict(case);case.pop("id",None);known=case.pop("known",{})
        text=case.pop("ciphertext")
        expected,assignments,routes=oracle(text,known,model=self.model,**case)
        actual=rank_joint_columnar(text,[dict(start=i+1,text=c) for i,c in known.items()],
            model=self.model,top=top,max_states=2000000,time_limit_seconds=10,**case,**options)
        self.assertTrue(actual["complete"],actual["stop_reason"])
        self.assertEqual(len(actual["candidates"]),min(top,len(expected)))
        for row,(plain,(score,(cols,key))) in zip(actual["candidates"],expected):
            self.assertEqual((row["plaintext"],int(row["score_exact"],16),tuple(row["column_order"]),row["key_pattern"]),(plain,score,cols,key))
            self.assertEqual(replay_recipe(plain,row["encryption_recipe"])["ciphertext"],text)
        self.assertLessEqual(actual["evaluated"],assignments)
        if actual["total_order_key_assignments"] is not None:self.assertEqual(actual["total_order_key_assignments"],assignments)
        if actual["total_column_orders"] is not None:self.assertEqual(actual["total_column_orders"],routes)
        return actual

    def test_all_32_option_combinations_and_score_ties(self):
        case=dict(ciphertext="AAAA",known={},width=2,period=1,alphabet=A)
        for flags in itertools.product((False,True),repeat=5):
            options=dict(propagation="fixed_point" if flags[0] else "off",early_segmentation=flags[1],
                branching="constrained" if flags[2] else "prefix",score_bound="shared_key" if flags[3] else "independent",
                symmetry="identical_chunks" if flags[4] else "off",pruning="admissible")
            self.check(case,options)
        result=rank_joint_columnar("AAAA",[],width=2,period=1,model=self.model,alphabet=A,
            score_mask=list(range(4)),top=5,**ALL)
        self.assertTrue(result["complete"])
        self.assertEqual([r["plaintext"] for r in result["candidates"]],[c*4 for c in "ABCDE"])
        self.assertTrue(all(r["column_order"]==[0,1] for r in result["candidates"]))

    def test_twelve_frozen_authored_controls(self):
        for case in fixtures():
            with self.subTest(case=case["id"]):self.check(case,ALL)

    def test_early_ragged_prefix_and_suffix_wildcards(self):
        for order in ("ST","TS"):
            plain="ABCDEFG"
            case=dict(ciphertext=encrypt(plain,3,[2,7],[2,0,1],order),known={i:plain[i] for i in [0,1,4,6]},width=3,period=2,order=order,alphabet=A)
            self.check(case,dict(early_segmentation=True))
            self.check(case,dict(early_segmentation=True,propagation="fixed_point"))

    def test_symmetry_phase_guard_and_canonical_recipe(self):
        for order in ("ST","TS"):
            result=self.check(dict(ciphertext="AAAAAA",known={},width=3,period=2,order=order,alphabet=A),dict(symmetry="identical_chunks"))
            self.assertTrue(result["route_symmetry"]["reduced"])
            self.assertFalse(result["enumeration_complete"])
            self.assertTrue(all(r["column_order"]==[0,1,2] for r in result["candidates"]))
            self.assertEqual(result["evaluated"],26**2)
        budget=_Budget(1000,10)
        self.assertEqual(equivalent_chunks("AAAAAA",[2,2,2],3,"TS",budget),[])
        self.assertEqual(equivalent_chunks("AAAAAA",[2,2,2],3,"ST",budget),[[0,1,2]])

    def test_supported_edge_and_phase_propagation_preserves_every_solution(self):
        domains=[(0,1),(0,1),(1,2)]
        requirements={(0,0):{0:1},(0,1):{0:2},(1,0):{0:2},(1,1):{0:1},(2,1):{0:1},(2,2):{0:2}}
        masks=[sum(1<<v for v in (0,1,2))]
        valid=[(permutation,key) for permutation in itertools.permutations(range(3)) for key in range(3)
               if all(col in domains[slot] and requirements[slot,col].get(0,key)==key for slot,col in enumerate(permutation))]
        reduced,_=reduce_joint(domains,masks,requirements,_Budget(10000,10),fixed_point=True)
        self.assertTrue(valid)
        self.assertIsNotNone(reduced)
        for route,key in valid:
            self.assertTrue(all(c in reduced[0][slot] for slot,c in enumerate(route)))
            self.assertTrue(reduced[1][0]&(1<<key))
        self.assertLess(sum(map(len,reduced[0])),sum(map(len,domains)))

    def test_shared_key_bound_all_restricted_domains_and_equations(self):
        rng=random.Random(71032)
        counts={"".join(rng.choice(A[:5]) for _ in range(4)):rng.randrange(1,20) for _ in range(60)}
        for cipher in ("vigenere","beaufort","variant"):
            for alphabet in (A,"BACDEFGHIJKLMNOPQRSTUVWXYZ"):
                helper=SharedKeyBound(alphabet,cipher,counts,1,10,100)
                for _ in range(12):
                    options=[sorted(rng.sample(range(26),3)),sorted(rng.sample(range(26),4))]
                    masks=[sum(1<<v for v in domain) for domain in options]
                    bindings=[(rng.randrange(26),i%2) for i in range(4)]
                    actual=0
                    for key in itertools.product(*options):
                        gram="".join(alphabet[(key[phase]-c if cipher=="beaufort" else c+key[phase] if cipher=="variant" else c-key[phase])%26] for c,phase in bindings)
                        actual=max(actual,counts.get(gram,0)*10+1)
                    budget=_Budget(100000,10)
                    self.assertEqual(helper.upper(bindings,masks,budget),actual)
                    self.assertEqual(helper.upper(bindings,masks,budget),actual)
                    self.assertEqual(budget.work["shared_bound_cache_hits"],1)

    def test_combined_continuation_and_changed_option_identity(self):
        root=Path(__file__).resolve().parents[1]/"research"/"manual-checks"
        root.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(prefix="joint-P-",dir=root))
        try:
            args=dict(width=2,period=1,model=self.model,alphabet=A,top=4,**ALL)
            whole=rank_joint_columnar("BDBC",[],**args)
            previous=None;total=0
            for number in range(100):
                path=folder/f"{number}.json"
                part=rank_joint_columnar("BDBC",[],**args,max_evaluations=4,max_states=800,
                    resume_path=previous,checkpoint_path=path)
                total+=part["evaluated_this_run"]
                self.assertEqual(total,part["evaluated"])
                previous=path
                if part["complete"]:break
            self.assertTrue(part["complete"])
            self.assertEqual(part["candidates"],whole["candidates"])
            self.assertEqual(part["evaluated"],whole["evaluated"])
            self.assertEqual(part["route_completion_blocks"],whole["route_completion_blocks"])
            self.assertIsNone(part["column_orders_visited"])
            with self.assertRaises(ValueError):
                rank_joint_columnar("BDBC",[],**dict(args,branching="prefix"),resume_path=path)
            limited=rank_joint_columnar("BDBC",[],**args,max_frontier=1,checkpoint_path=folder/"tiny.json")
            self.assertFalse(limited["complete"])
            final=rank_joint_columnar("BDBC",[],**args,resume_path=folder/"tiny.json")
            self.assertEqual(final["candidates"],whole["candidates"])
        finally:
            resolved=folder.resolve()
            self.assertEqual(resolved.parent,root.resolve())
            self.assertTrue(resolved.name.startswith("joint-P-"))
            shutil.rmtree(resolved)

    def test_default_counts_and_invalid_options(self):
        model=train_ngram_model([CorpusDocument("AAAAAAAAAAAAAAAAAABCDEFFEDCBA","phase-O synthetic")],label="Phase O",order=1)
        default=rank_joint_columnar("AAAAA",[],model=model,period=1,width=3,alphabet=A,top=3,pruning="admissible")
        self.assertEqual((default["evaluated"],default["states_total"]),(156,1566))
        self.assertEqual(default["work"]["branch_decisions"],
            sum(default["work"].get(kind+"_branch_decisions",0) for kind in ("slot","key","segmentation")))
        for setting in (dict(early_segmentation=1),dict(propagation=True),dict(branching="random"),dict(score_bound="shared_key"),dict(symmetry=True),dict(max_bound_cache_entries=True)):
            with self.assertRaises(ValueError):rank_joint_columnar("ABCD",[],model=self.model,period=1,width=2,**setting)


if __name__=="__main__":unittest.main()
