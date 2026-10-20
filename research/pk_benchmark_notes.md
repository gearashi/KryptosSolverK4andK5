# Published PK1 and PK3 recovery controls

This adds two independently authored plaintexts to our recovery checks. It does
not test discovery of an unknown method. The alphabet, identity transposition,
and periods are supplied, while the recovery function receives no published
keys or undisclosed plaintext letters.

## Sources and fixture verification

The complete published pairs are assembled from two independent source roles:

- **Ciphertexts:** the official [PK1](https://www.paradigm.xyz/kryptos-ctf/pk1)
  and [PK3](https://www.paradigm.xyz/kryptos-ctf/pk3) site's publicly linked
  [application asset](https://www.paradigm.xyz/kryptos-ctf/_next/static/chunks/0h1ap~1.6ljs6.js).
  Its ciphertext literals are read as text. JavaScript is never executed, and
  its stale status labels are not used.
- **Plaintexts:** a firsthand researcher's
  [PK1 result](https://github.com/benjacasas02/independent-cryptography-research/blob/main/research/paradigm-kryptos/selected-results/01_pk1_quagmire_solve/README.md)
  and
  [PK3 result](https://github.com/benjacasas02/independent-cryptography-research/blob/main/research/paradigm-kryptos/selected-results/03_pk3_longperiod_solve/README.md).
  These supply complete plaintexts and digest prefixes; the latter also gives
  an effective period-40 key.
- **Layered method:** the [firsthand reconstruction](https://asynchronous.win/post/solving-pk1-pk7-at-paradigms-ctf/)
  uses additive indices in `KRYPTOSABCDEFGHIJLMNQUVWXZ`: PK1 has key
  `PROVENANCE`; PK3 applies `PENTIMENTO` then `ORDINATE`.

Exact source bytes, retrieval times, URLs and SHA-256 values are retained in
[source_snapshots/pk-benchmarks/sources.json](source_snapshots/pk-benchmarks/sources.json).
The download date is October 12, 2026 locally, October 13 UTC. Raw text files
are authoritative inputs. No third-party program was imported or executed.
The downloaded verifier refers to `code/data/solutions.json`, absent from the
retrieved repository file listing. We therefore use the official ciphertext
asset and the published plaintext reports rather than depend on that verifier.

Our literal forward and reverse operations reproduce all 192 PK1 letters and
all 280 PK3 letters. PK3 also passes a separate check with the result report's
period-40 key. These are exact mathematical pair checks, not a new submission
to the owner's validator or an independent authentication of the authors' work.

| Pair | Full plaintext SHA-256 | Full ciphertext SHA-256 |
| --- | --- | --- |
| PK1 | `c52a2399f1f4f3f526f583c4fd533b596fb345b28dfcb8865bf24f383b760a1a` | `86748db025480f076695474ee4a94da721ad7435f84a3f7a1186548b3ee9ff8c` |
| PK3 | `8f8b1cc851def197868be586e8f83cf37e141efc8dd6a74180f3e85d980cd34a` | `660ff56d93e5b99dc02823a360d7d2e8ac1fbf232fc07f22e5efa7adbc76fb84` |

## Fixed recovery contract

Use the **full messages** consistently, without cropping to 97 characters.
Supply exactly 24 plaintext letters at one-based positions 22–34 and 64–74,
the positions of our K4 cribs. Each supplied letter comes from that PK fixture;
we neither insert K4 phrases nor alter the published message. These are
**artificial supplied cribs, not official PK clues**.

The two fixed method-known models are:

| Pair | Compiled periods | Route and order |
| --- | --- | --- |
| PK1 | `(10, 1)` | Identity route, `SST` |
| PK3 | `(10, 8)` | Identity route, `SST` |

An unknown constant second shift makes the PK1 representation exactly
equivalent to one arbitrary period-10 shift stream. It adds key gauge freedom,
not extra plaintext freedom. Recovery never receives the published keys.

`recover(ciphertext, known, period_a, period_b, candidate_budget)` uses the
existing `compile_layer_plan` API. For a feasible model it enumerates every
distinct plaintext, subject to a hard cap of 676 per case. If the whole case
exceeds the cap, it returns `budget-skipped`, with no partial rank or success/
failure verdict. Every candidate is checked by an independent literal
stage-by-stage encryption, and scored with all crib positions excluded.
Only afterward does the evaluator compare candidates with the published text.

The output records graph dimension, the complete prediction mask, candidate
count, representative keys, both encryption-stage hashes, complete ranked
plaintexts, exact true-plaintext rank, ties, and uniqueness within the supplied
model. Gauge-equivalent keys need not reproduce the published key words.
When the dimension is zero, successful recovery is algebraic; its rank of one
does not exercise the language scorer's ability to distinguish alternatives.

## Execution and limits

Small literal controls and published-pair verification:

```powershell
python research/pk_benchmarks.py --self-test
```

The preparatory run passed these checks in 0.398 seconds. It did not run the
canonical PK recovery experiment. The controls include a standard-alphabet
two-stage hand vector, a KRYPTOS-alphabet hand vector, compiled recovery of
the hand example, and rejection of a deliberately inconsistent hand crib.

Canonical bounded recovery, to a fresh output path:

```powershell
python research/pk_benchmarks.py --output research/runs/pk-benchmarks-001/results.json
```

`SOURCE_PATHS` is the exact ten-file input list for the runner manifest. The
script also records hashes before and after, resolved fixture/contract hash,
Python version, elapsed time, all fixture source metadata, and all results.
Changing the candidate cap requires an explicit CLI argument in `1..676`.

The recorded [pk-benchmarks-001 output](runs/pk-benchmarks-001/results.json)
contains:

| Pair | Dimension | Compatible plaintexts | Recorded outcome |
| --- | --- | --- | --- |
| PK1 | 0 | 1 | Full published plaintext recovered uniquely; literal re-encryption passed |
| PK3 | 3 | 17,576 | Whole case skipped at the declared 676-candidate budget; no recovery verdict or rank |

The PK3 skip is a resource-contract outcome, not evidence that the solver or
method fails. PK1's uniqueness follows from the supplied algebraic constraints;
its first-place score is not a language-ranking test.

## Separate PK3 completion protocol

[pk3_extended.py](pk3_extended.py) extends only the completion budget to
exactly `26^3 = 17,576`, retaining the original full PK3 text, alphabet, model,
periods, and supplied 24 letters. The original benchmark script, inputs and
saved results are unchanged. The extension refuses any other length or
dimension, and has an internal 45-second enumeration limit. A timeout raises
an error without writing a partial rank as a completed result. Use a 60-second
outer runner limit to allow source verification and evidence serialization.

```powershell
python research/pk3_extended.py --check-plan
python research/pk3_extended.py --output research/runs/pk3-extended-001/results.json
```

The preflight passed in 0.378 seconds: feasible dimension three and precisely
17,576 completions, without enumerating the candidates. The subsequent
[canonical extended run](runs/pk3-extended-001/results.json) completed in
11.42 seconds: all 17,576 distinct plaintexts were enumerated and literally
re-encrypted. The published plaintext ranked first, with no score tie.
The runner's input list is the new script plus the original benchmark's ten
inputs, exposed as `SOURCE_PATHS`.

The extension must re-encrypt every candidate, check all supplied letters,
exclude their positions from scoring, and retain every distinct plaintext,
representative key pair, score, freedom values and first-stage digest. Rank
and ties are evaluated only after complete enumeration. Even a rank-one true
plaintext leaves the other compatible texts as algebraic alternatives; it
does not turn this English heuristic into an authentication test.

A success verifies recovery for these two published examples with their
methods, periods and 24 letters supplied. It does not calibrate general
English ranking, discover the method blindly, identify a K4/K5 method, or
authenticate a K4 candidate. No column-order search, PK2 extension, external
submission, GPU job or application-wide tests are part of this experiment.
