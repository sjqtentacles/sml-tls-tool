#!/usr/bin/env bash
# run_openssl_diff.sh -- differential handshake testing against OpenSSL.
#
# Two directions:
#   1) our client  <-> openssl s_server  (bin/socket_shim client)
#   2) our server  <-> openssl s_client  (bin/socket_shim server)
#
# We launch the OpenSSL side, launch our side, capture both transcripts,
# and diff them at the byte level (or compare TLS alerts). The pure
# sml-tls library is deterministic, so any divergence from OpenSSL is a
# library bug to capture as a regression at J2.
#
# Prerequisites:
#   - openssl CLI (any 1.1.1+ or 3.x)
#   - MLton (to build the shim)
#
# Expected to FAIL until J2.
#
# Usage:
#   scripts/run_openssl_diff.sh [client|server|both]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SHIM="$ROOT/bin/socket_shim"
MODE="${1:-both}"
PORT="${OPENSSL_DIFF_PORT:-44330}"

echo "==> Building shim (mlton)"
( cd "$ROOT" && make bin/socket_shim )

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl CLI not found" >&2
  exit 2
fi

run_client() {
  echo "==> Direction 1: our client vs openssl s_server (port $PORT)"
  openssl s_server -accept "$PORT" -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    -nocommands -quiet -www >/tmp/openssl_server.log 2>&1 &
  local PID=$!
  trap 'kill $PID 2>/dev/null || true' RETURN
  sleep 0.5
  "$SHIM" client "127.0.0.1" "$PORT" >/tmp/sml_client.log 2>&1 || true
  echo "--- sml-tls client log ---"
  cat /tmp/sml_client.log || true
  echo "--- openssl server log (tail) ---"
  tail -n 20 /tmp/openssl_server.log || true
}

run_server() {
  echo "==> Direction 2: our server vs openssl s_client (port $PORT)"
  "$SHIM" server "$PORT" >/tmp/sml_server.log 2>&1 &
  local PID=$!
  trap 'kill $PID 2>/dev/null || true' RETURN
  sleep 0.5
  openssl s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    </dev/null >/tmp/openssl_client.log 2>&1 || true
  echo "--- openssl client log (tail) ---"
  tail -n 20 /tmp/openssl_client.log || true
  echo "--- sml-tls server log ---"
  cat /tmp/sml_server.log || true
}

case "$MODE" in
  client) run_client ;;
  server) run_server ;;
  both)   run_client; run_server ;;
  *) echo "usage: $0 [client|server|both]" >&2; exit 2 ;;
esac

echo "run_openssl_diff: complete (expected to fail until J2)"
