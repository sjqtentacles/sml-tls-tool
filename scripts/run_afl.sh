#!/usr/bin/env bash
# run_afl.sh -- run AFL++ against one or all of the decoder harnesses.
#
# Prerequisites:
#   - afl-fuzz (AFL++ recommended; `brew install afl-fuzz` on macOS)
#   - MLton (to build the harnesses)
#   - python3 (to generate the seed corpus)
#
# The harnesses are persistent-mode (AFL_PERSISTENT=1) for throughput.
# Seed corpora live under fuzz/corpus/<decoder>/ and are regenerated
# from scripts/generate_corpus.py.
#
# Usage:
#   scripts/run_afl.sh                  # fuzz all decoders in parallel
#   scripts/run_afl.sh record           # fuzz one decoder
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

DECODERS=(record ciphertext clienthello serverhello certificate extensions recordprotect)

if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "afl-fuzz not found; install AFL++ (e.g. brew install afl-fuzz)" >&2
  exit 2
fi

echo "==> Building all AFL harnesses (mlton)"
( cd "$ROOT" && make afl-all )

echo "==> Regenerating seed corpus"
( cd "$ROOT" && python3 scripts/generate_corpus.py )

TARGET="${1:-}"
if [ -n "$TARGET" ]; then
  DECODERS=("$TARGET")
fi

OUT="$ROOT/out"
mkdir -p "$OUT"

PIDS=()
for d in "${DECODERS[@]}"; do
  echo "==> Launching AFL for $d"
  AFL_PERSISTENT=1 afl-fuzz \
    -i "$ROOT/fuzz/corpus/$d" \
    -o "$OUT/$d" \
    -- "$ROOT/bin/afl_$d" &
  PIDS+=($!)
done

echo "==> AFL PIDs: ${PIDS[*]}"
echo "==> Stop with: kill ${PIDS[*]}"
wait "${PIDS[@]}" || true
