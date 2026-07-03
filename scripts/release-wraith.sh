#!/usr/bin/env bash
# release-wraith.sh — package the three Wraith Wallet binaries into a
# versioned tarball + machine-readable manifest, optionally GPG-signed.
#
# Output:
#   dist/wraith-wallet-<version>-<host-triple>.tar.gz
#   dist/wraith-wallet-<version>-<host-triple>.tar.gz.sha256
#   dist/wraith-wallet-<version>-<host-triple>.manifest.json
#   dist/wraith-wallet-<version>-<host-triple>.manifest.json.asc   (if signed)
#
# Layout inside the tarball:
#   wraith-wallet-<version>/
#     bin/wraithd
#     bin/wraith
#     bin/wraith-gui
#     completions/wraith.bash
#     completions/_wraith            (zsh)
#     completions/wraith.fish
#     README.md                       (the wallet README, not the repo root)
#     LICENSE                         (MIT)
#     BUILDINFO.txt
#
# Manifest schema (consumed by `wraith update check` + `wraith verify`):
#   {
#     "version":   "1.8.0",
#     "triple":    "x86_64-unknown-linux-gnu",
#     "built":     "2026-05-06T17:42:11Z",
#     "commit":    "abcd…",
#     "rustc":     "rustc 1.93.0 …",
#     "tarball":   "wraith-wallet-1.8.0-x86_64-unknown-linux-gnu.tar.gz",
#     "tarball_sha256": "…",
#     "binaries": {
#       "wraithd":     {"sha256": "…", "size": 12345678},
#       "wraith":      {"sha256": "…", "size":  4567890},
#       "wraith-gui":  {"sha256": "…", "size": 23456789}
#     }
#   }
#
# Signing: set WRAITH_RELEASE_SIGNING_KEY to a GPG key id (or fingerprint).
# When set, gpg --detach-sign --armor produces the .asc next to the manifest.
# When unset, the manifest still ships unsigned — useful for dev / CI dry-runs.
# An update client should refuse to act on an unsigned manifest in production.
#
# Usage:
#   bash scripts/release-wraith.sh [version]
#   WRAITH_RELEASE_SIGNING_KEY=0xDEADBEEF bash scripts/release-wraith.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(awk -F'"' '/^version *=/ {print $2; exit}' Cargo.toml)}"
TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
NAME="wraith-wallet-${VERSION}-${TRIPLE}"
STAGING="dist/${NAME}"
TARBALL="dist/${NAME}.tar.gz"
MANIFEST="dist/${NAME}.manifest.json"
SIGNING_KEY="${WRAITH_RELEASE_SIGNING_KEY:-}"

# Pure-shell sha256 + size helpers — sha256sum is in coreutils on every
# distro we care about; macOS hosts use shasum -a 256 in CI and pipe in
# the same way, but we don't auto-detect to keep the script honest.
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
size_of() { wc -c < "$1" | tr -d ' '; }

echo "==> Wraith Wallet release ${VERSION} for ${TRIPLE}"
mkdir -p dist
rm -rf "$STAGING" "$TARBALL" "${TARBALL}.sha256" "$MANIFEST" "${MANIFEST}.asc"
mkdir -p "$STAGING/bin" "$STAGING/completions"

echo "==> Building daemon + CLI (this will take a while on a cold cache)"
# Build the daemon + CLI first: the GUI's Tauri sidecar (externalBin) needs a
# freshly-built `wraithd` staged under src-tauri/binaries/ with a target-triple
# suffix before its build.rs runs, otherwise tauri-build fails resolving it.
cargo build --release \
  -p wraith-wallet-daemon \
  -p wraith-wallet-cli

echo "==> Staging wraithd as the Tauri sidecar (wraithd-${TRIPLE})"
SIDECAR_DIR="apps/wraith-wallet/gui/src-tauri/binaries"
mkdir -p "$SIDECAR_DIR"
cp target/release/wraithd "$SIDECAR_DIR/wraithd-${TRIPLE}"

echo "==> Building GUI"
cargo build --release -p wraith-wallet-gui

cp target/release/wraithd      "$STAGING/bin/"
cp target/release/wraith       "$STAGING/bin/"
cp target/release/wraith-gui   "$STAGING/bin/"

echo "==> Stripping debug info"
strip "$STAGING/bin/wraithd" "$STAGING/bin/wraith" "$STAGING/bin/wraith-gui" 2>/dev/null || true

echo "==> Generating shell completions"
"$STAGING/bin/wraith" completions bash > "$STAGING/completions/wraith.bash"
"$STAGING/bin/wraith" completions zsh  > "$STAGING/completions/_wraith"
"$STAGING/bin/wraith" completions fish > "$STAGING/completions/wraith.fish"

echo "==> Copying docs"
cp apps/wraith-wallet/README.md "$STAGING/README.md"
if [[ -f LICENSE ]]; then
  cp LICENSE "$STAGING/LICENSE"
else
  printf 'MIT — see https://github.com/bitcoin-ghost/ghost\n' > "$STAGING/LICENSE"
fi

echo "==> Recording build metadata"
BUILT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
RUSTC="$(rustc --version)"
{
  echo "version: ${VERSION}"
  echo "triple:  ${TRIPLE}"
  echo "built:   ${BUILT}"
  echo "commit:  ${COMMIT}"
  echo "rustc:   ${RUSTC}"
} > "$STAGING/BUILDINFO.txt"

echo "==> Packing tarball"
( cd dist && tar czf "${NAME}.tar.gz" "${NAME}" )
( cd dist && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )

echo "==> Writing manifest"
WRAITHD_SHA="$(sha256_of "$STAGING/bin/wraithd")"
WRAITHD_SIZE="$(size_of "$STAGING/bin/wraithd")"
WRAITH_SHA="$(sha256_of "$STAGING/bin/wraith")"
WRAITH_SIZE="$(size_of "$STAGING/bin/wraith")"
WRAITH_GUI_SHA="$(sha256_of "$STAGING/bin/wraith-gui")"
WRAITH_GUI_SIZE="$(size_of "$STAGING/bin/wraith-gui")"
TARBALL_SHA="$(sha256_of "$TARBALL")"
cat > "$MANIFEST" <<EOF
{
  "version":        "${VERSION}",
  "triple":         "${TRIPLE}",
  "built":          "${BUILT}",
  "commit":         "${COMMIT}",
  "rustc":          "${RUSTC}",
  "tarball":        "${NAME}.tar.gz",
  "tarball_sha256": "${TARBALL_SHA}",
  "binaries": {
    "wraithd":    {"sha256": "${WRAITHD_SHA}",    "size": ${WRAITHD_SIZE}},
    "wraith":     {"sha256": "${WRAITH_SHA}",     "size": ${WRAITH_SIZE}},
    "wraith-gui": {"sha256": "${WRAITH_GUI_SHA}", "size": ${WRAITH_GUI_SIZE}}
  }
}
EOF

if [[ -n "$SIGNING_KEY" ]]; then
  echo "==> Signing manifest with key ${SIGNING_KEY}"
  gpg --detach-sign --armor \
    --local-user "$SIGNING_KEY" \
    --output "${MANIFEST}.asc" \
    "$MANIFEST"
else
  echo "==> WRAITH_RELEASE_SIGNING_KEY unset; skipping signature"
  echo "    (set it to a GPG key id to produce ${NAME}.manifest.json.asc)"
fi

echo "==> Done"
echo "    $TARBALL"
echo "    ${TARBALL}.sha256"
echo "    $MANIFEST"
[[ -f "${MANIFEST}.asc" ]] && echo "    ${MANIFEST}.asc"
( cd dist && cat "${NAME}.tar.gz.sha256" )
