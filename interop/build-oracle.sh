#!/usr/bin/env bash
# Builds the dev-time Go interop oracle(s) against a local checkout of tailscale/tailscale.
# Usage: interop/build-oracle.sh <path-to-tailscale-checkout> <output-dir>
set -euo pipefail
TS="${1:?path to tailscale checkout}"; OUT="${2:?output dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
for d in "$HERE"/go-*/; do
  name="$(basename "$d")"
  tmp="$TS/cmd/_jtail_$name"
  rm -rf "$tmp"; cp -r "$d" "$tmp"
  (cd "$TS" && go build -o "$OUT/$name" "./cmd/_jtail_$name") || { rm -rf "$tmp"; exit 1; }
  rm -rf "$tmp"
done
