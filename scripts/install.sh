#!/usr/bin/env bash
# Client installer — prefers server-hosted install when DOMAIN is known.
# Usage: curl -sSL https://<domain>/install | bash
# Fallback (GitHub): curl -sSL .../scripts/install.sh | bash

set -euo pipefail

REPO="devnonla/nonla-tunnel"
INSTALL_DIR="${HOME}/.nonla-tunnel/bin"
mkdir -p "$INSTALL_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux) OS_LABEL=linux ;;
  darwin) OS_LABEL=darwin ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH_LABEL=amd64 ;;
  aarch64|arm64) ARCH_LABEL=arm64 ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

FILE="nonla-tunnel-${OS_LABEL}-${ARCH_LABEL}"
CURL="curl --proto =https --tlsv1.2 -fsSL"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# verify <sums-url> <name-in-sums> <file>
verify() {
  $CURL "$1" -o "$TMP/sums" || { echo "❌ Could not download $1 — refusing to install unverified binary"; exit 1; }
  want="$(awk -v f="$2" '$2 == f || $2 == "*"f { print $1 }' "$TMP/sums" | head -1)"
  got="$(sha256 "$3")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "❌ Checksum mismatch for $2 (want ${want:-none}, got $got)"; exit 1
  fi
  echo "▸ Checksum OK"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ -n "${NONLA_TUNNEL_BASE:-}" ]; then
  BASE="${NONLA_TUNNEL_BASE%/}"
  case "$BASE" in https://*) ;; *) echo "❌ NONLA_TUNNEL_BASE must be https://"; exit 1 ;; esac
  echo "▸ Downloading ${FILE}..."
  $CURL "${BASE}/download/${FILE}" -o "$TMP/$FILE"
  verify "${BASE}/download/SHA256SUMS" "$FILE" "$TMP/$FILE"
  install -m 755 "$TMP/$FILE" "$INSTALL_DIR/nonla-tunnel"
else
  TAG=$($CURL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  case "$TAG" in v[0-9]*) ;; *) echo "Could not resolve latest release"; exit 1 ;; esac
  TARBALL="nonla-tunnel-${TAG}-${OS_LABEL}-${ARCH_LABEL}.tar.gz"
  REL="https://github.com/${REPO}/releases/download/${TAG}"
  echo "▸ Downloading ${TARBALL}..."
  $CURL "${REL}/${TARBALL}" -o "$TMP/$TARBALL"
  verify "${REL}/SHA256SUMS.txt" "$TARBALL" "$TMP/$TARBALL"
  mkdir -p "$TMP/x"
  tar -xzf "$TMP/$TARBALL" -C "$TMP/x"
  install -m 755 "$TMP/x/nonla-tunnel" "$INSTALL_DIR/nonla-tunnel"
fi

SHELL_RC=""
case "${SHELL:-}" in
  */zsh) SHELL_RC="$HOME/.zshrc" ;;
  */bash) SHELL_RC="$HOME/.bashrc" ;;
  *) SHELL_RC="$HOME/.profile" ;;
esac
if [ -n "$SHELL_RC" ] && ! grep -q '.nonla-tunnel/bin' "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$HOME/.nonla-tunnel/bin:$PATH"' >> "$SHELL_RC"
fi
export PATH="$INSTALL_DIR:$PATH"

echo "✅ nonla-tunnel installed to $INSTALL_DIR/nonla-tunnel"
echo
echo "Next:"
echo "  nonla-tunnel config set --server connect.<domain>:443 --token TOKEN"
echo "  nonla-tunnel http 3000"
