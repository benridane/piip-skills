#!/usr/bin/env bash
# Start (or stop) the local Presidio Analyzer server used by `piip -e hybrid|presidio`.
#
#   presidio-start.sh [start|stop|status]
#
# The Python environment and spaCy models live in ~/.cache/piip, not in the
# skill directory. The server only listens on 127.0.0.1.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$SKILL_DIR/presidio/server.py" ]]; then
	PROJECT="$SKILL_DIR/presidio"            # Installed skill.
else
	PROJECT="$SKILL_DIR/../../presidio"      # Source repository.
fi

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/piip"
PORT="${PIIP_PRESIDIO_PORT:-5002}"
URL="http://127.0.0.1:$PORT"
PIDFILE="$CACHE/presidio.pid"
LOG="$CACHE/presidio.log"
export UV_PROJECT_ENVIRONMENT="$CACHE/presidio-venv"
mkdir -p "$CACHE"

is_up() { curl -sf --max-time 2 "$URL/health" >/dev/null 2>&1; }

case "${1:-start}" in
stop)
	if [[ -f "$PIDFILE" ]] && kill "$(cat "$PIDFILE")" 2>/dev/null; then
		rm -f "$PIDFILE"
		echo "Presidio stopped."
	else
		echo "Presidio is not running (or was not started by this script)."
	fi
	exit 0
	;;
status)
	if is_up; then echo "Presidio is up at $URL"; else echo "Presidio is not running at $URL"; exit 1; fi
	exit 0
	;;
start) ;;
*)
	echo "usage: $0 [start|stop|status]" >&2
	exit 2
	;;
esac

if is_up; then
	echo "Presidio is already running at $URL"
	exit 0
fi

if ! command -v uv >/dev/null; then
	echo "uv is required to set up Presidio: https://docs.astral.sh/uv/getting-started/installation/" >&2
	exit 1
fi

if [[ ! -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]]; then
	echo "Setting up Presidio and spaCy models (en, ja) in $UV_PROJECT_ENVIRONMENT (first run only)..."
fi
uv sync --project "$PROJECT" --frozen --quiet

nohup "$UV_PROJECT_ENVIRONMENT/bin/python" "$PROJECT/server.py" --port "$PORT" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"

for _ in $(seq 1 180); do
	if is_up; then
		echo "Presidio is up at $URL (log: $LOG)"
		exit 0
	fi
	if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		echo "Presidio failed to start; last log lines:" >&2
		tail -20 "$LOG" >&2
		exit 1
	fi
	sleep 1
done

echo "Presidio did not come up within 180s; see $LOG" >&2
exit 1
