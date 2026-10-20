"""Exact correlated affine n-gram bounds under a verified subgroup condition.

This additive helper does not alter checkpoint-K search. A domain that is not a
complete cyclic parameter returns an explicit fallback. All arithmetic used to
test joint reachability is exact in F2 and F13; scores remain integer products.
"""
from collections.abc import Mapping


def _basis(vectors, modulus, width):
    rows = []
    reductions = 0
    for vector in vectors:
        row = [value % modulus for value in vector]
        for pivot, existing in rows:
            if row[pivot]:
                factor = row[pivot]
                row = [(a - factor * b) % modulus for a, b in zip(row, existing)]
                reductions += 1
        pivot = next((i for i, v in enumerate(row) if v), None)
        if pivot is None:
            continue
        inverse = pow(row[pivot], -1, modulus)
        row = [v * inverse % modulus for v in row]
        updated = []
        for old_pivot, existing in rows:
            factor = existing[pivot]
            if factor:
                existing = tuple((a - factor * b) % modulus for a, b in zip(existing, row))
                reductions += 1
            updated.append((old_pivot, existing))
        updated.append((pivot, tuple(row)))
        rows = sorted(updated)
    assert all(len(row) == width for _, row in rows)
    return tuple(rows), reductions


def _contains(vector, rows, modulus):
    reduced = [v % modulus for v in vector]
    for pivot, row in rows:
        if reduced[pivot]:
            factor = reduced[pivot]
            reduced = [(a - factor * b) % modulus for a, b in zip(reduced, row)]
    return not any(reduced)


class CorrelatedNgramBound:
    """Cache one immutable observed-gram table, then bound affine windows.

    The score of a gram is count*q+p, with positive integer smoothing p/q.
    Zero-count/unobserved grams score p. Returned upper is the exact maximum
    for this factor when applicable, but multiplying factor maxima is still an
    upper bound for a multi-factor objective with shared variables.
    """

    def __init__(self, alphabet, counts, p, q):
        if not isinstance(alphabet, str) or len(alphabet) != 26 or len(set(alphabet)) != 26:
            raise ValueError("alphabet must contain 26 distinct symbols")
        if any(type(v) is not int or not 1 <= v <= 1 << 1075 for v in (p, q)):
            raise ValueError("p and q must be positive integers <=2**1075")
        if not isinstance(counts, Mapping) or len(counts) > 2000000:
            raise ValueError("counts must be a mapping with at most two million entries")
        index = {c: i for i, c in enumerate(alphabet)}
        width = None
        grams = []
        for gram, count in counts.items():
            if (not isinstance(gram, str) or not 1 <= len(gram) <= 6 or any(c not in index for c in gram)
                    or type(count) is not int or count < 0):
                raise ValueError("invalid observed n-gram/count")
            if width is None:
                width = len(gram)
            if len(gram) != width:
                raise ValueError("observed grams must have one common order")
            if count:
                grams.append((count, gram, tuple(index[c] for c in gram)))
        self.alphabet, self.p, self.q, self.order = alphabet, p, q, width
        self.grams = tuple(sorted(grams, key=lambda row: (-row[0], row[1])))

    def upper(self, base, columns, domains, values):
        """Bound one affine window with -1 for unfixed variable assignments.

        For an unfixed variable of size d, {0,...,d-1} times its vector is a
        full cyclic subgroup if d divides 26 and d*vector=0 mod26. Domain-one
        and zero-vector variables contribute zero. Other cases explicitly
        return applicable=False so callers retain their existing safe bound.
        """
        if (not isinstance(base, (list, tuple)) or not 1 <= len(base) <= 6
                or any(type(v) is not int or not 0 <= v < 26 for v in base)):
            raise ValueError("base must contain 1..6 residues modulo26")
        if self.order is not None and len(base) != self.order:
            raise ValueError("window width differs from scoring order")
        if not all(isinstance(x, (list, tuple)) for x in (columns, domains, values)) or not len(columns) == len(domains) == len(values) or len(columns) > 512:
            raise ValueError("columns/domains/values require equal lengths <=512")
        if any(type(d) is not int or not 1 <= d <= 26 for d in domains):
            raise ValueError("domains must contain sizes1..26")
        if any(type(v) is not int or not -1 <= v < d for v, d in zip(values, domains)):
            raise ValueError("values must be -1 or a valid domain value")
        if any(not isinstance(c, (list, tuple)) or len(c) != len(base) or any(type(v) is not int or not 0 <= v < 26 for v in c) for c in columns):
            raise ValueError("columns must match base width with residues modulo26")
        offset = list(base)
        generators = []
        for variable, (column, domain, value) in enumerate(zip(columns, domains, values)):
            if value >= 0:
                offset = [(a + value * b) % 26 for a, b in zip(offset, column)]
            elif domain == 1 or not any(column):
                continue
            elif domain not in (2, 13, 26) or any(domain * v % 26 for v in column):
                return {"applicable": False, "upper": None, "fallback_reason": "unfixed_domain_is_not_verified_full_cyclic_subgroup",
                        "variable": variable, "domain": domain, "column": list(column), "observed_grams_checked": 0}
            else:
                generators.append(column)
        basis2, work2 = _basis(generators, 2, len(base))
        basis13, work13 = _basis(generators, 13, len(base))
        checked, maximum, witness = 0, 0, None
        for count, gram, encoded in self.grams:
            checked += 1
            target = [(a - b) % 26 for a, b in zip(encoded, offset)]
            if _contains(target, basis2, 2) and _contains(target, basis13, 13):
                maximum, witness = count, gram
                break
        return {"applicable": True, "upper": maximum * self.q + self.p, "maximum_count": maximum,
                "maximizing_observed_gram": witness, "fallback_reason": None,
                "offset": offset, "rank_mod2": len(basis2), "rank_mod13": len(basis13),
                "reachable_gram_count": 2 ** len(basis2) * 13 ** len(basis13),
                "observed_grams_checked": checked, "basis_row_reductions": work2 + work13,
                "basis_mod2": [[pivot, list(row)] for pivot, row in basis2],
                "basis_mod13": [[pivot, list(row)] for pivot, row in basis13]}
