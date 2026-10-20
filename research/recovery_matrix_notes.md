# Deterministic in-family recovery matrix

This experiment asks whether the current exact layer solver and masked English
ranking recover known synthetic plaintexts when the generating model is in the
search bank. It does not test whether K4 belongs to that family. Its four short
surrounding texts were authored for this experiment; they are not a language
benchmark, and have not been selected by their scores.

The contract is twelve cases: the two already recorded K3-inspired ragged routes,
all three substitution/transposition orders (`SST`, `STS`, `TSS`), and generating
period pairs `(2,3)` and `(4,2)`. The first pair is coprime; the second is not.
Every fixture has length 97 and the same 24 disclosed letters in the same original
plaintext positions. The remaining letters come from four ordinary prose themes,
rotated across cases. Inserting cribs can break grammar at the joins. Keys are
deterministic, varied by case, and checked to have their stated fundamental
periods. Both substitutions use the shared fixed KRYPTOS alphabet.

`recover(ciphertext, known, bank, candidate_budget)` receives no plaintext, keys,
generating route, order, or period pair. It searches all 384 combinations of the
two routes, three orders, and both periods independently from 1 through 8. The
fixture-generation function and the later evaluator have access to truth. This
separation prevents truth from steering this recovery loop; it is not a claim of
an independently held-out benchmark or protection against someone reading the
generator source.

The compiled graph solver checks every combination exactly. Crib-feasible models
whose plaintext dimension is zero or one are eligible for complete enumeration
(one or 26 distinct plaintexts per model). Larger dimensions are recorded but
excluded. Counts of raw model completions are summed **before** enumeration. If
the total exceeds the per-input cap, that entire case is `budget-skipped`: there
is no partial search, ranking, or success/failure verdict. The default and maximum
cap is 5,000 raw completions per input. It counts repetitions across equivalent
models; it is not a cap on distinct plaintext strings.

Every evaluated completion is checked against all 24 cribs and re-encrypted using
the literal stage composition in `research/layer_constraints.py`. This is separate
from the graph equations used to obtain the keys and plaintext. Complete strings
are then deduplicated across models. Each stored candidate has its score,
multiplicity, and one re-encrypting model/key witness; route permutations and their
hashes are stored at the top level. Different key gauges are not different
plaintexts, and a representative key need not equal a planted key.

The existing English heuristic scores the 73 unmasked letters and excludes every
feature touching a crib. Candidates sort by descending score, then lexical
plaintext for reproducibility. Evaluation records the exact true-plaintext rank,
competition rank (one plus the number scoring strictly higher), score tie count,
and the number of distinct feasible plaintexts. A rank of one with alternatives
still represents ambiguity. Uniqueness applies only to the enumerated low
dimension subset, never all feasible models or Kryptos generally.

The output contains all ranked distinct candidates, all feasible model dimensions,
the materialized fixtures, source hashes before and after, a resolved-input hash,
the Python version, and literal re-encryption counts. A source change during the
run fails closed. There is no random seed, network operation, K4-ciphertext
search, or application test. Parameter combinations are not independent cipher
families. The matrix gives a bounded software/recovery control, not evidence that
these routes, periods, or English ranking can solve the sculpture.

Run once with a fresh output path, under the project's bounded experiment runner
when recording a scientific artifact:

```powershell
python research/recovery_matrix.py --output research/runs/recovery-matrix-001/results.json
```

`analyze(candidate_budget=5000)` also returns the evidence dictionary for the
runner. A deliberately smaller budget can verify explicit skip behavior without
partially ranking an input. No resume journal is needed for this small fixed
matrix; it must complete or be rerun from a fresh output destination.
