#!/usr/bin/env sh
set -eu
usage() {
    printf '%s\n' 'Usage: sh Setup.sh [--gpu] [--sat] [--python /path/to/python] [--help]' \
        'Create/reuse .venv and verify CPU imports. Only --gpu installs pinned CUDA packages.' \
        'Existing .venv is preserved; --python selects the interpreter only when creating it.'
}
gpu=0
sat=0
chosen=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --gpu) gpu=1; shift ;;
        --sat) sat=1; shift ;;
        --python) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; chosen=$2; shift 2 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
cd "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
if [ ! -e .venv ]; then
    if [ -z "$chosen" ]; then
        for candidate in python3.12 python3 python; do
            if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
                chosen=$candidate
                break
            fi
        done
    fi
    [ -n "$chosen" ] || { printf '%s\n' 'Python 3.10+ is required; supply --python if needed.' >&2; exit 1; }
    "$chosen" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
    "$chosen" -m venv .venv
fi
python=.venv/bin/python
[ -x "$python" ] || { printf '%s\n' 'Existing .venv has no Unix Python interpreter. It was preserved; repair it manually.' >&2; exit 1; }
"$python" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"; import kryptos.app; print("CPU application ready on Python " + sys.version.split()[0])'
if [ "$gpu" -eq 1 ]; then
    "$python" -c 'import struct; assert struct.calcsize("P") == 8, "CUDA setup requires 64-bit Python"'
    "$python" -m pip install --requirement requirements-gpu.txt
    printf '%s\n' 'GPU packages installed. The dashboard checks CUDA on launch; a compatible NVIDIA driver is required.'
fi
if [ "$sat" -eq 1 ]; then
    "$python" -m pip install --requirement requirements-sat.txt
    "$python" -c 'import z3; print("Optional SMT backend ready: Z3 " + z3.get_version_string())'
fi
printf '%s\n' 'Run sh OpenDashboard.sh to open the idle local application.'
