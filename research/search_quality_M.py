"""Bounded release-M audit: joint bounds, verified scanner seed, and protocols.

The presets and discriminator are fixed independently of their output. Run once
under the outer computation-audit wrapper after the shared sources are frozen.
"""
import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.__main__ import _target
from kryptos.advanced_cli import json_safe_integers
from kryptos.next_cli import run_next
from kryptos.search_runtime import SCHEMA,_Evaluator,optimize_lazy
from kryptos.validation_protocols import run_validation


def input_paths():
    files=[str(p.relative_to(ROOT)).replace("\\","/") for p in sorted((ROOT/"kryptos").glob("*.py"))]
    files += ["research/search_quality_M.py","tests/test_search_enhancements.py","tests/test_validation_protocols.py",
              "examples/optimize-lazy.json","examples/validate-holdout.json","examples/validate-controls.json"]
    for name in ("optimize-lazy","validate-holdout","validate-controls"):
        request=json.loads((ROOT/"examples"/(name+".json")).read_text())
        files.extend(request.get("model_paths",[request["model_path"]] if "model_path" in request else []))
    return tuple(sorted(set(files)))


def file_hashes():
    return {p:sha256((ROOT/p).read_bytes()).hexdigest() for p in input_paths()}


def grouping_control():
    problem={"schema":SCHEMA,"domains":[2]*4,"factors":[
        {"kind":"table","scope":[i],"values":values} for i in range(4) for values in ([9,1],[1,8])]}
    # Direct scalar expression independent of evaluator code.
    def direct(p):
        value=1
        for x in p: value*=9 if x==0 else 8
        return value
    points=list(product(range(2),repeat=4))
    exact=_Evaluator(problem,0,1,2,2)
    partials=list(product(range(-1,2),repeat=4))
    for partial in partials:
        wanted=max(direct(p) for p in points if all(x<0 or p[i]==x for i,x in enumerate(partial)))
        if exact.upper(partial)!=wanted:
            raise AssertionError("grouped bound differs from exhaustive oracle")
    baseline=optimize_lazy(problem,factor_group_size=0)
    grouped=optimize_lazy(problem,factor_group_size=2,group_exact_limit=2)
    assert baseline["assignment"]==grouped["assignment"]==[0]*4
    assert baseline["score"]==grouped["score"]==9**4
    return {"problem":problem,"partial_assignments_checked":len(partials),"full_assignments":len(points),
            "baseline":baseline,"grouped":grouped,"claim":"Exact bound and unchanged optimum on this fixed discriminator only."}


def run(backend):
    before=file_hashes()
    grouped=grouping_control()
    request=json.loads((ROOT/"examples/optimize-lazy.json").read_text())
    plain=run_next("optimize-plus",request,_target)
    request["seed_scan"]={"backend":backend,"batch_size":26,"top":3}
    seeded=run_next("optimize-plus",request,_target)
    a,b=plain["optimization"],seeded["optimization"]
    assert (a["search"]["assignment"],a["search"]["score"])==(b["search"]["assignment"],b["search"]["score"])
    protocols={}
    for name in ("validate-holdout","validate-controls"):
        protocol=json.loads((ROOT/"examples"/(name+".json")).read_text())
        protocols[name]=run_validation(name,protocol)
    if not all(r["complete"] for r in protocols.values()):
        raise AssertionError("frozen audit protocol was censored; increase no bounds here, investigate separately")
    after=file_hashes()
    if before!=after:
        raise RuntimeError("an audited source or input changed")
    return {"schema":"kryptos.search-quality-audit.v1","backend":backend,"group_bounds":grouped,
            "seed":{"baseline":plain,"seeded":seeded},"protocols":protocols,
            "input_sha256_before":before,"input_sha256_after":after,
            "nonclaims":["No K4 decipherment or false-positive probability.","Authored contiguous-mask controls are not the actual separated K4 clue layout.","One small pruning discriminator establishes no general speedup."]}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend",choices=("cpu","cuda"),default="cpu")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--inputs",action="store_true")
    args=parser.parse_args()
    if args.inputs:
        print(json.dumps(input_paths(),indent=2)); sys.exit(0)
    if args.output is None or args.output.exists():
        parser.error("--output requires a fresh file")
    value=run(args.backend)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(json_safe_integers(value),stream,indent=2,allow_nan=False); stream.write("\n")
    print(json.dumps({"backend":args.backend,"control_summary":value["protocols"]["validate-controls"]["summary"],
                      "baseline_nodes":value["group_bounds"]["baseline"]["nodes"],"grouped_nodes":value["group_bounds"]["grouped"]["nodes"]}))
