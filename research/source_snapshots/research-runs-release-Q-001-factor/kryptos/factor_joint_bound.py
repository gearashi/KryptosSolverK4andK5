"""A column-matching language bound for the ranked joint route/key solver."""
import math


def compute_column_matching_bound(*, current, columns, offsets, cvalues,
        requirements, key_domains, period, order, starts, ngram_order,
        shared_bound, window_bounds, budget, max_matching_states=50000):
    """Bound column-local windows under one-to-one output-slot matching.

    For a permitted slot->column edge, each wholly column-local window is
    maximized over its shared key phases, intersected with the edge's crib key
    requirements. A matching selects every physical column once. Products of
    these edge bounds therefore count each local window exactly once. Windows
    crossing columns keep their independently certified supplied bounds.

    This ignores correlations between different windows/columns and is an
    upper bound, not a feasible plaintext. No qualifying windows or a local
    DP cap returns unavailable and leaves the caller's previous bound intact.
    The caller's budget exception is intentionally allowed to propagate.
    """
    width = len(columns)
    if width > 16:
        budget.work["matching_bound_width_fallbacks"] += 1
        return dict(bound_available=False, upper_bound=None, eligible_windows=0,
                    stop_reason="matching_width_limit")
    position_column, vertical_indices = {}, {}
    for col, positions in enumerate(columns):
        for vertical, position in enumerate(positions):
            budget.tick("matching_bound_position_planning")
            position_column[position] = col
            vertical_indices[position] = vertical
    local, crossing = {col: [] for col in range(width)}, []
    for start in starts:
        budget.tick("matching_bound_window_planning")
        owners = {position_column[position] for position in range(start, start + ngram_order)}
        if len(owners) == 1:
            local[next(iter(owners))].append(start)
        else:
            crossing.append(start)
    eligible = sum(len(v) for v in local.values())
    if not eligible:
        budget.work["matching_bound_no_local_windows"] += 1
        return dict(bound_available=False, upper_bound=None, eligible_windows=0,
                    stop_reason="no_column_local_windows")
    weights, allowed = [], []
    for slot, domain in enumerate(current):
        row, permitted = [0] * width, []
        for col in domain:
            budget.tick("matching_bound_edges")
            domains = list(key_domains)
            for phase, key in requirements.get((slot, col), {}).items():
                domains[phase] &= 1 << key
            if not all(domains):
                continue
            permitted.append(col)
            value = 1
            for start in local[col]:
                bindings = []
                for position in range(start, start + ngram_order):
                    budget.tick("matching_bound_window_bindings")
                    cipher_position = offsets[slot] + vertical_indices[position]
                    phase = (position if order == "ST" else cipher_position) % period
                    bindings.append((cvalues[cipher_position], phase))
                value *= shared_bound.upper(bindings, domains, budget)
            row[col] = value
        weights.append(row)
        allowed.append(permitted)
    frontier, transitions = {0: 1}, 0
    for slot in range(width):
        following = {}
        for mask, value in frontier.items():
            for col in allowed[slot]:
                transitions += 1
                if transitions > max_matching_states:
                    budget.work["matching_bound_dp_fallbacks"] += 1
                    return dict(bound_available=False, upper_bound=None, eligible_windows=eligible,
                                stop_reason="matching_state_limit")
                budget.tick("matching_bound_dp_transitions")
                bit = 1 << col
                if mask & bit:
                    continue
                next_mask = mask | bit
                following[next_mask] = max(following.get(next_mask, 0), value * weights[slot][col])
        frontier = following
    upper = frontier.get((1 << width) - 1, 0)
    for start in crossing:
        budget.tick("matching_bound_crossing_products")
        upper *= window_bounds[start]
    budget.work["matching_bound_completed"] += 1
    return dict(bound_available=True, upper_bound=upper, eligible_windows=eligible,
                stop_reason="column_matching_relaxation")
