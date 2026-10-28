"""JSON boundary for bounded exact constraint-building and reuse operations."""
from .constraint_lab import ConstraintLimit


def run(request):
    if not isinstance(request,dict) or set(request)!={'operation','parameters'} or not isinstance(request['parameters'],dict):
        raise ValueError('Finite tools require operation and parameters objects')
    from . import constraint_algebra as algebra
    from . import constraint_reuse as reuse
    from . import recipe_algebra as recipe
    from . import constraint_models as models
    from .constraint_lab import relational_join, disjunctive_relation
    operations={
        'join':relational_join,
        'components':reuse.enumerate_components,
        'dominance_one_best':reuse.dominates_one_best,
        'transfer_conflicts':reuse.transfer_conflicts,
        'score_projection':reuse.score_projection_groups,
        'affine_relation':algebra.affine_relation,
        'disjoint_affine_cover':algebra.disjoint_finite_cover,
        'field_order':algebra.choose_field,
        'crib_differences':algebra.crib_difference_constraints,
        'compile_recipe':recipe.compile_recipe,
        'family_from_compiled':recipe.family_from_compiled,
        'phase_partition':recipe.canonical_phase_partition,
        'primitive_keys':recipe.primitive_key_bank,
        'alphabet_equivalence':recipe.alphabet_affine_equivalence,
        'fractionation_relation':models.fractionation_relation,
        'disjunction':disjunctive_relation,
    }
    function=operations.get(request['operation'])
    if function is None:
        raise ValueError('Unknown bounded finite-tool operation')
    try:
        result=function(**request['parameters'])
    except TypeError as exc:
        raise ValueError('Operation parameters do not match the declared interface') from exc
    return {'schema':'kryptos.constraint-tools.v1','operation':request['operation'],'complete':True,
        'result':result,'authenticated_solution':False,
        'interpretation':'Exact bounded helper result under explicit input assumptions; not a standalone Kryptos solution or a universal search-efficiency claim.'}
