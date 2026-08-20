#!/usr/bin/env bash
# Requires: cargo install cross  +  Docker running
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

echo "[*] Building Windows x86_64 (cross)..."
cross build --release --target x86_64-pc-windows-gnu \
    --manifest-path "$ROOT/Cargo.toml" -p imugi-node

cp "$ROOT/target/x86_64-pc-windows-gnu/release/imugi-node.exe" \
   "$DIST/imugi-node-windows-x86_64.exe"

echo "[+] Done:"
ls -lh "$DIST/imugi-node-windows-x86_64.exe"
