#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

echo "[*] Building Linux x86_64 (musl static)..."
rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
cargo build --release --target x86_64-unknown-linux-musl \
    --manifest-path "$ROOT/Cargo.toml"

cp "$ROOT/target/x86_64-unknown-linux-musl/release/imugi-proxy" "$DIST/imugi-proxy-linux-x86_64"
cp "$ROOT/target/x86_64-unknown-linux-musl/release/imugi-node"  "$DIST/imugi-node-linux-x86_64"

echo "[+] Done:"
ls -lh "$DIST/imugi-proxy-linux-x86_64" "$DIST/imugi-node-linux-x86_64"
