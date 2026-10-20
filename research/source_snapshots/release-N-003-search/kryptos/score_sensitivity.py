"""Reporting-only sensitivity to letters forced by a declared cipher family.

The ordinary candidate ranking is never changed. Exact marginal letter images
determine an additional mask; they do not imply independent letter choices or
prove that an arbitrary supplied string belongs to the joint affine family.
"""
from .language import CharacterNgramModel


def affine_marginals(affine):
    """Exact finite-domain image at every position, without family enumeration."""
    if not isinstance(affine, dict) or set(affine) != {"alphabet", "base", "columns", "domains"}:
        raise ValueError("Expected an affine plaintext alphabet/base/columns/domains record")
    alphabet, base, columns, domains = (affine[k] for k in ("alphabet", "base", "columns", "domains"))
    if not isinstance(alphabet, str) or len(alphabet) != 26 or set(alphabet) != set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        raise ValueError("affine alphabet must be an uppercase A-Z permutation")
    if not isinstance(base, (list, tuple)) or not 1 <= len(base) <= 4096 or any(type(v) is not int or not 0 <= v < 26 for v in base):
        raise ValueError("base must contain1..4096 residues modulo26")
    if not isinstance(columns, (list, tuple)) or not isinstance(domains, (list, tuple)) or len(columns) != len(domains) or len(columns) > 512:
        raise ValueError("at most512 finite affine parameters are supported")
    if any(type(d) is not int or not 1 <= d <= 26 for d in domains):
        raise ValueError("affine domains must have sizes1..26")
    if any(not isinstance(c, (list, tuple)) or len(c) != len(base) or any(type(v) is not int or not 0 <= v < 26 for v in c) for c in columns):
        raise ValueError("columns must match base length and contain residues modulo26")
    result = []
    for position, offset in enumerate(base):
        residues = {offset}
        for column, domain in zip(columns, domains):
            coefficient = column[position]
            if not coefficient or domain == 1:
                continue
            increment = {coefficient * value % 26 for value in range(domain)}
            residues = {(left + right) % 26 for left in residues for right in increment}
            if len(residues) == 26:
                break
        result.append("".join(c for i, c in enumerate(alphabet) if i in residues))
    return tuple(result)


def report(solution, model, plaintext, known):
    """Report ordinary and additionally model-fixed masked scores for a candidate.

    known is the zero-based position-to-letter mapping used by the solution.
    Caller must already validate complete joint membership/re-encryption.
    """
    if not isinstance(model, CharacterNgramModel):
        raise ValueError("a validated CharacterNgramModel is required")
    if not hasattr(solution, "affine_plaintext"):
        raise ValueError("solution must expose its finite affine plaintext image")
    affine = solution.affine_plaintext()
    domains = affine_marginals(affine)
    if set(model.alphabet) != set(affine["alphabet"]):
        raise ValueError("scoring and plaintext alphabets disagree")
    if not isinstance(plaintext, str) or len(plaintext) != len(domains) or any(c not in d for c, d in zip(plaintext, domains)):
        raise ValueError("plaintext must match all exact marginal domains")
    if not isinstance(known, dict) or any(type(i) is not int or not 0 <= i < len(plaintext) or not isinstance(c, str) or len(c) != 1 or c != plaintext[i] for i, c in known.items()):
        raise ValueError("known must map valid zero-based positions to matching letters")
    fixed = tuple(i for i, domain in enumerate(domains) if len(domain) == 1)
    if any(domains[i] != c for i, c in known.items()):
        raise ValueError("supplied letters are not fixed by the provided conditioned solution")
    explicit = tuple(sorted(known))
    ordinary = model.score(plaintext, explicit)
    sensitivity = model.score(plaintext, fixed)
    return {"schema": "kryptos.model-fixed-score-sensitivity.v1", "reporting_only": True,
            "changes_candidate_ranking": False, "model_id": model.model_id,
            "supplied_positions_zero_based": list(explicit), "model_fixed_positions_zero_based": list(fixed),
            "additional_fixed_positions_zero_based": [i for i in fixed if i not in known],
            "variable_positions_zero_based": [i for i, d in enumerate(domains) if len(d) > 1],
            "exact_marginal_letter_domains": list(domains),
            "supplied_mask_score": ordinary.to_dict(), "model_fixed_mask_score": sensitivity.to_dict(),
            "interpretation": "Conditional sensitivity only. Scores with different masks are not like-for-like likelihood evidence. Zero surviving windows means unavailable, not a score of zero. Marginal compatibility does not replace joint candidate replay."}
