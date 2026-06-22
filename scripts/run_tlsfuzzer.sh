#!/usr/bin/env bash
# run_tlsfuzzer.sh -- run tlsfuzzer scenarios against our TLS server.
#
# tlsfuzzer is a Python-based TLS test suite that drives a server over
# real TCP and asserts on the handshake / record bytes. We launch our
# server shim (bin/socket_shim server PORT) in the background, then
# run a tlsfuzzer scenario against it.
#
# Prerequisites:
#   - Python 3.8+
#   - pip install tlsfuzzer
#   - MLton (to build the shim)
#
# Expected to FAIL until J2.
#
# Usage:
#   scripts/run_tlsfuzzer.sh [scenario.py]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SHIM="$ROOT/bin/socket_shim"
SCENARIO="${1:-$HERE/tlsfuzzer_1rtt.py}"
PORT="${BOGO_PORT:-44330}"

echo "==> Building shim (mlton)"
( cd "$ROOT" && make bin/socket_shim )

echo "==> Launching sml-tls server on port $PORT"
"$SHIM" server "$PORT" &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Give the server a moment to bind.
sleep 0.5

echo "==> Checking tlsfuzzer is installed"
if ! python3 -c "import tlsfuzzer" 2>/dev/null; then
  echo "tlsfuzzer not installed; run: pip install tlsfuzzer" >&2
  exit 2
fi

echo "==> Running scenario: $SCENARIO"
python3 "$SCENARIO" "127.0.0.1" "$PORT" || {
  echo "run_tlsfuzzer: scenario failed (expected until J2)" >&2
  exit 1
}

echo "run_tlsfuzzer: ok"
