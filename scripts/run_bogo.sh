#!/usr/bin/env bash
# run_bogo.sh -- fetch and run BoringSSL BoGo against our shim.
#
# BoGo is the BoringSSL Go-based TLS conformance runner. It spawns a
# shim binary (ours: bin/bogo_shim) with command-line flags describing
# each test case. We implement a starter subset of the protocol; the
# runner drives the full BoringSSL test list, and we skip / xfail most
# of them until J2.
#
# Prerequisites:
#   - Go toolchain (go >= 1.20)
#   - make, cmake, ninja (for BoringSSL build)
#   - MLton (to build the shim)
#
# Expected to FAIL until J2 (the library is not feature-complete yet).
#
# Usage:
#   scripts/run_bogo.sh                # full default subset
#   scripts/run_bogo.sh -test=TestBasic # single test
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BOGO_ROOT="${BOGO_ROOT:-$ROOT/vendor/boringssl}"
BOGO_RUNNER="$BOGO_ROOT/ssl/test/runner"
SHIM="$ROOT/bin/bogo_shim"

echo "==> Building shim (mlton)"
( cd "$ROOT" && make bin/bogo_shim )

echo "==> Ensuring BoringSSL is present at $BOGO_ROOT"
if [ ! -d "$BOGO_ROOT" ]; then
  mkdir -p "$(dirname "$BOGO_ROOT")"
  git clone --depth=1 https://boringssl.googlesource.com/boringssl "$BOGO_ROOT"
fi

echo "==> Building BoGo runner (go test)"
( cd "$BOGO_RUNNER" && go build -o "$ROOT/bin/bogo_runner" . )

echo "==> Running BoGo against shim (starter subset)"
# The runner takes -shim-path, -port (loopback), and many -test flags.
# We restrict to a single handshake-success test for now.
"$ROOT/bin/bogo_runner" \
  -shim-path "$SHIM" \
  -port 0 \
  "$@" \
  -test=TestBasic-Client || {
    echo "run_bogo: tests failed (expected until J2)" >&2
    exit 1
  }

echo "run_bogo: ok"
