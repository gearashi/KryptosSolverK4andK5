#!/usr/bin/env sh
set -eu
usage() {
    printf '%s\n' 'Usage: sh OpenDashboard.sh [--port 8767] [--no-browser] [--skip-gpu-probe] [--state-dir path] [--python path] [--help]' \
        'Open the idle local dashboard. Uses .venv or Python 3.10+. Installs nothing.'
}
port=8767
no_browser=0
skip_gpu=0
state_dir=''
python=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --port|--state-dir|--python)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            case "$1" in --port) port=$2 ;; --state-dir) state_dir=$2 ;; --python) python=$2 ;; esac
            shift 2 ;;
        --no-browser) no_browser=1; shift ;;
        --skip-gpu-probe) skip_gpu=1; shift ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
cd "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
if [ -z "$python" ]; then
    if [ -x .venv/bin/python ]; then
        python=.venv/bin/python
    else
        for candidate in python3 python; do
            if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
                python=$candidate
                break
            fi
        done
    fi
fi
[ -n "$python" ] || { printf '%s\n' 'Python 3.10+ is required. Run Setup.sh or supply --python.' >&2; exit 1; }
"$python" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
set -- -B -m kryptos.app --port "$port"
[ "$no_browser" -eq 0 ] || set -- "$@" --no-browser
[ "$skip_gpu" -eq 0 ] || set -- "$@" --skip-gpu-probe
[ -z "$state_dir" ] || set -- "$@" --state-dir "$state_dir"
exec "$python" "$@"
