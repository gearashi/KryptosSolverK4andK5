# Round S: exact clue tests

**K4 is not solved here and no candidate plaintext is reported.** This round adds tests that decide whole key spaces from the 24 published clue letters with one algebraic check each, so no key and no 97-letter candidate is ever tried.

Two working hypotheses motivated the round:

- **Clue letters in place.** Sanborn's 2010 clue was given as ciphertext letters NYPVTT standing for BERLIN at positions 64 to 69. Most batteries therefore take ciphertext letter *i* to come from plaintext letter *i*. This is a hypothesis, not a certainty; one battery drops it.
- **A 7-wide structure once the "?" before K4 is counted as a cell** (98 = 14 x 7). K4 has nine repeats at distance 7 (0.4% of shuffles), and on the 7-wide grid that starts at the "?" columns 6 and 7 hold the same letter in 5 of 14 rows (0.06% of shuffles at width 7, 1.6% over every width from 3 to 32). On that grid NORTHEAST and BERLIN each end at a row end. The cause of this pattern is still unexplained.

## What is in the application

`kryptos/exact_batteries.py` (standard library only) and the dashboard page **Exact clue tests** run seven batteries:

| Battery | Family | Settings on K4 | Result |
|---|---|---|---|
| `periodic` | Periodic key in place, periods 1 to 26; fixed alphabets (standard or KRYPTOS, c=p+k or c=k-p), or one unknown mixed alphabet solved as unknowns | 312 | No period survives with fixed alphabets. With one unknown alphabet only periods 13, 16, 18, 19, 20, 23 to 26 remain consistent, each with at most one clue letter left over (undecidable). |
| `compound` | In place: two periodic keys, or periodic key + a key letter per grid row or a row step, optional steady drift, optional multiple of an earlier ciphertext or plaintext letter | 154,128 (92,432 decidable) | No survivor |
| `recurrence` | Key stream from a linear recurrence (order 1 to 7), a two-lag recurrence, or a quadratic or cubic formula plus a periodic key | 552 | No survivor |
| `grid` | In place: unknown alphabet + one key letter per column + one per row, every grid width 2 to 31 and every grid start | 1,980 | Nothing with two or more clue letters left over |
| `trifid` | Trifid on 27 symbols ("?" as the 27th), **every possible cube**, periods 2 to 98, every block start, both directions, with or without the "?" cell | 19,204 | No survivor: every setting forces two different symbols onto one cube cell |
| `pairs` | Porta and Slidefair, any key and period | 14 | Excluded |
| `transposition` | Not in place: transposition layered with a periodic keyed substitution in either order (key period 1 to 13). 97 letters: every columnar order up to 8 columns (9 with `--max-width 9`); 98 cells: every column order of the complete 14 x 7 grid and K3-style single and double grid turns; all with inverses | 42,773,120 (width 8) or 344,689,280 (width 9) | No survivor |

The periodic, compound and transposition tests report fits with at least six residual clue letters. The recurrence screen lists fits with three or more residuals, and the grid screen uses two. Trifid looks for forced cube-coordinate clashes. Porta and Slidefair check structural identities. Read the criterion for the selected battery before interpreting a survivor or an empty result.

```
python -B -m kryptos.exact_batteries            # all batteries on K4
python -B -m kryptos.exact_batteries trifid --out trifid.json
python -B -m kryptos.exact_batteries transposition --max-width 9
python -B -m kryptos.exact_batteries periodic --cipher <97 letters>   # controls
```

`tests/test_exact_batteries.py` plants messages inside each family (unknown alphabet with period 5, two periodic keys, lagged ciphertext feedback, a recurrence, a random Trifid cube, a columnar transposition with the key PALIMPSE) and checks that each battery finds its plant, that shuffled ciphertexts give no survivor, and that the dashboard endpoints accept only guarded requests.

## Larger standalone runs

`standalone/` holds the programs used for the wider run of 17 November 2026. They need a C compiler and, for two scripts, third-party Python packages (`numpy`, `python-sat`, `wordfreq`, `english-words`), which is why they are not part of the application. `sh standalone/run_all.sh ENGLISH_TEXT_FILE [--controls]` reruns everything; `results/run_all_2026-11-17.log` is the log of that run.

| Program | Family | Size | Result | Controls |
|---|---|---|---|---|
| `linear_battery.c` | In-place key models with fixed alphabets, including feedback from an earlier plaintext, ciphertext or key letter combined with two-part keys | 11,583,936 models, 2,566,038 decidable | 0 flagged | 5 planted messages flagged; 0 flags in 20 shuffles |
| `linear_battery2.c` | The same with one unknown mixed alphabet, and lagged letters through a second unknown alphabet | 32,214,000 models, 4,706,000 decidable | 0 flagged; the best near-fit maps S and B to one value (`followup_nearfit.py`) | Planted period-5 message flagged; 0 flags in 20 shuffles |
| `selfkey.py` | Running key read from the sculpture's own texts (K1 to K3 plaintext and ciphertext, Morse text, tableau), any start, step 1 to 20, forwards or backwards | 9,360,000 settings | Best agreement 9 of 24 letters, which is chance level | 5 shuffles: 8 or 9 of 24 |
| `keyword_runkey.py` | Keyword-mixed alphabet from 390,446 words in any role, with an English running key | 18,328,806 candidates | Best score equals shuffled text | Planted keyword recovered with a readable key |
| `transpo_periodic.c` | The `transposition` battery at width 9 | 1,657,160 transpositions | 0 flagged | 2 planted messages flagged; 0 flags in 20 shuffles |

### Battery 2 coverage correction (24 November 2026)

The 17 November counts and controls above describe the archived program. Its rank estimate skipped models with nested periods or other dependent columns. For example, each period-8 column is the sum of two period-16 columns. On the 24 clues the combined design has 24 occupied columns but rank 16 over both fields. This leaves eight independent checks.

The current `standalone/linear_battery2.c` computes both ranks directly. A K4 rerun gave 32,214,000 labelled models, **4,726,044 at or above the score threshold** and **zero flags**. The archived threshold count was 4,706,000. This count uses a score of at least 7.5 decimal digits from the residuals over the two fields. The two residual counts can differ. Consistency permits partial letter assignments and any positive result still requires an injective alphabet. The historical shuffle totals in the table refer to the archived rank filter.

The four actual planted ciphertexts in `battery2_controls.py` leave 7, 5, 0 and 0 independent checks at their generating settings. The original low-threshold diagnostic restarted the random sequence at the second plant and checked different ciphertexts. The diagnostic now uses the same four messages as the main controls.

With exact ranks, the period-5 plant gave 219 flags including the generating model. All 20 matched shuffles were rerun. Of their 644,280,000 labelled settings, 91,889,822 met the weighted threshold and zero flagged. On real K4, requiring six residuals in each prime field gave 2,565,368 eligible settings in battery 1 and 4,717,772 in corrected battery 2, with zero flags in either family.

## Limits

- Every result assumes the published clue letters and positions are right and that the 24 ciphertext letters at those positions carry no enciphering slip.
- Models with more unknowns than 24 clue letters can pin down are undecidable: two unknown alphabets at once, key periods above about 12 with an unknown alphabet, seven independent column alphabets with a row shift.
- Running keys from outside texts are covered only as English with a dictionary keyword alphabet. Key lists such as the place names on the Berlin World Clock are not covered.
- Transpositions wider than 9 columns with arbitrary order, irregular routes, and transposition combined with anything other than a periodic key are not covered by this round.
- Digraph tables without structure, homophones, nulls, Gromark with an unknown alphabet, large Hill ciphers and one-time pads are not covered.

## Open question for the next round

Which method makes columns 6 and 7 of the 7-wide grid agree (N,O to Q,Q; S,T to S,S; I,N to T,T) while keeping the clue letters in place? None of the tested families does.
