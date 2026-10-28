"""Explicit bounded research commands, with original model and technique trace."""
import hashlib
import json
from pathlib import Path

COMMANDS={"constraint-lab","factor-lab","model-lab","grammar-lab"}


def catalog():
    root=Path(__file__).resolve().parents[1]
    plan=json.loads((root/"research/phase_Q_plan.json").read_text(encoding="utf-8"))
    examples=[]
    for command,pattern in (("constraint-lab","constraint-Q-*.json"),("factor-lab","factor-Q-*.json"),("model-lab","model-lab-*.json"),("grammar-lab","grammar-Q-*.json")):
        for path in sorted((root/"examples").glob(pattern)):
            examples.append({"id":path.stem,"label":path.stem.replace("-"," "),"command":command,
                             "request":json.loads(path.read_text(encoding="utf-8"))})
    return {"entries":plan["entries"],"examples":examples,"interpretation":plan["primary_acceptance"]}


def execute(command,request):
    if command == "constraint-lab":
        from .constraint_lab import run
    elif command == "factor-lab":
        from .factor_advanced import run_factor_request as run
    elif command == "model-lab":
        from .model_lab import run
    elif command == "grammar-lab":
        from .recipe_grammar import run
    else:
        raise ValueError("Unknown research method command")
    result=run(request)
    # Generic assignments and path witnesses are not plaintext candidates.
    complete=result.get("complete")
    if complete is None and isinstance(result.get("reports"),list):
        complete=all(report.get("complete") is True for report in result["reports"])
    return {"schema":"kryptos.research-method.v1","command":command,
            "authenticated_solution":False,"candidates":[],"analysis":result,
            "complete":complete,
            "explanation":{"supplied_request":request,
                "request_sha256":hashlib.sha256(json.dumps(request,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest(),
                "interpretation":"A bounded declared model or technique experiment. See analysis for assumptions, witnesses, counted work and resource cutoffs. Generic assignments are not authenticated Kryptos plaintexts."}}
