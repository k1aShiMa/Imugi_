#!/usr/bin/env bash
set -e

export PATH="$HOME/.cargo/bin:$PATH"

# A script könyvtárához képest meghatározzuk a projekt gyökerét
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

TARGET="x86_64-pc-windows-gnu"

echo "[*] Navigating to project root: $ROOT"
cd "$ROOT"

echo "[*] Cross-compiling imugi-node for $TARGET..."
# Belépés után elég a relative path, vagy ha ez egy Cargo Workspace,
# akkor a gyökér Cargo.toml-t fogja használni és a -p imugi-node választja ki a crate-et.
cross build --release --target "$TARGET" -p imugi-node

cp "$ROOT/target/$TARGET/release/imugi-node.exe" "$DIST/imugi-node-windows-x86_64.exe"

echo "[+] Done:"
ls -lh "$DIST/imugi-node-windows-x86_64.exe"
echo ""
echo "[!] Remember: drop wintun.dll alongside the binary on the target."
echo "    Get it from https://wintun.net/ — pick the amd64 .dll"