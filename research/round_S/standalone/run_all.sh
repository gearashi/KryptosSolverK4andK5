#!/bin/sh
# Reruns every K4 battery of 17 Nov 2026.  Usage: sh run_all.sh ENGLISH_TEXT_FILE [--controls]
# Needs: gcc, python3 with numpy, python-sat, wordfreq, english-words (pip install numpy python-sat wordfreq english-words).
# ENGLISH_TEXT_FILE: any large plain English text (about 1 MB or more) for letter statistics in battery 6.
# The compiled programs are built in a temporary folder because some shared drives do not allow running programs.
set -eu
TXT="$1"; CTRL="${2:-}"; HERE=$(cd "$(dirname "$0")" && pwd); B=$(mktemp -d); cd "$HERE"
gcc -O2 -o "$B/lb1" linear_battery.c -lm; gcc -O2 -o "$B/lb2" linear_battery2.c -lm; gcc -O2 -o "$B/tp" transpo_periodic.c
echo "== basic statistics =="; python3 basic_stats.py | tail -25
echo "== battery 1: key models, fixed alphabets =="; "$B/lb1"
echo "== battery 2: unknown mixed alphabets =="; "$B/lb2"
echo "== battery 3: periods, recurrences, polynomials =="; python3 periods_and_recurrences.py
echo "== battery 4: Trifid, every cube =="; python3 trifid_allcubes.py
echo "== battery 5: running key from Kryptos's own texts =="; python3 selfkey.py
echo "== battery 6: keyword alphabets with an English running key =="; python3 keyword_runkey.py "$TXT"
echo "== battery 7: transposition + periodic keyed substitution =="; "$B/tp"
echo "== battery 2b: unknown alphabet + column key + row key on every grid =="; python3 grid_tableau.py
echo "== small classical checks =="; python3 small_classical.py; python3 followup_nearfit.py
if [ "$CTRL" = "--controls" ]; then
  echo "== controls 1 =="; python3 battery_controls.py "$B/lb1" 20
  echo "== controls 2 =="; python3 battery2_controls.py "$B/lb2" 20
  echo "== controls 4 =="; python3 trifid_controls.py
  echo "== controls 6 =="; sh keyword_runkey_controls.sh "$TXT"
  echo "== controls 7 =="; python3 transpo_controls.py "$B/tp" 20
  echo "== controls 3 and 5 (5 shuffles each) =="
  python3 - <<'PY'
import random, subprocess, sys
from k4lib import C4
rng=random.Random(9)
for s in range(5):
    x=list(C4); rng.shuffle(x); x="".join(x)
    a=subprocess.run([sys.executable,"periods_and_recurrences.py",x],capture_output=True,text=True).stdout.strip().split("\n")[-1]
    b=subprocess.run([sys.executable,"selfkey.py",x],capture_output=True,text=True).stdout.strip()[:140]
    print("shuffle",s,"|",a,"|",b)
PY
fi
rm -rf "$B"
