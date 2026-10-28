"""Bounded request API for optional geometry, language and K5 hypotheses."""
from . import geometry_constraints as geometry
from . import language_constraints as language


METHODS = {
    "geometry": geometry.search_paths,
    "geometry_frontier": geometry.frontier_paths,
    "geometry_meet": geometry.meet_paths,
    "turn_grammar": geometry.learn_turn_grammar,
    "tableau_registrations": geometry.tableau_registrations,
    "morphology": language.expand_morphology,
    "language_lattice": language.segment_lattice,
    "verify_seeds": language.verify_suggestions,
    "codebook": language.decode_codebook,
    "source_keys": language.source_keys,
    "robust_rank": language.robust_rank,
    "joint_cribs": language.compile_joint_cribs,
    "extractions": language.extraction_bank,
}


def run(request):
    if not isinstance(request, dict) or set(request) != {"method", "parameters"}:
        raise ValueError("model-lab request requires method and parameters")
    method = request["method"]
    if not isinstance(method, str) or method not in METHODS or not isinstance(request["parameters"], dict):
        raise ValueError("unknown model-lab method or invalid parameters")
    import inspect
    function = METHODS[method]
    try:
        inspect.signature(function).bind(**request["parameters"])
    except TypeError as error:
        raise ValueError(str(error)) from error
    return {"schema": "kryptos.model-lab.v1", "method": method, "complete": True,
            "scope": "Complete only within the explicit finite input model; not a Kryptos solution claim.",
            "result": function(**request["parameters"])}
