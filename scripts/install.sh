#!/bin/sh
# nonla-tunnel installer — Linux and macOS (POSIX sh: works on Alpine/busybox).
#
#   curl -fsSL https://<domain>/install | sh -s -- --invite nti_...      # from your server
#   curl -fsSL https://raw.githubusercontent.com/devnonla/nonla-tunnel/main/scripts/install.sh | sh
#
# Options (or env vars):
#   --invite CODE      NONLA_INVITE        enroll right after installing
#   --server ADDR      NONLA_SERVER        control address, e.g. connect.example.com
#   --version X.Y.Z    NONLA_VERSION       default: the server's version, else latest
#   --dir PATH         NONLA_INSTALL_DIR   default: ~/.nonla-tunnel/bin
#   --no-modify-path   NONLA_NO_MODIFY_PATH=1
#   NONLA_DOWNLOAD_BASE=URL   mirror with <asset> + SHA256SUMS.txt (default: GitHub Releases)
#
# Downloads the release binary for this OS/arch from GitHub Releases and
# verifies it against the release's SHA256SUMS.txt before installing.
set -eu

REPO="devnonla/nonla-tunnel"
# Filled in by the server when served from https://<domain>/install.
NONLA_DEFAULT_VERSION=""
NONLA_DEFAULT_SERVER=""
NONLA_DEFAULT_ENROLL_FLAGS=""

INVITE="${NONLA_INVITE:-}"
SERVER="${NONLA_SERVER:-$NONLA_DEFAULT_SERVER}"
VERSION="${NONLA_VERSION:-$NONLA_DEFAULT_VERSION}"
INSTALL_DIR="${NONLA_INSTALL_DIR:-$HOME/.nonla-tunnel/bin}"
NO_MODIFY_PATH="${NONLA_NO_MODIFY_PATH:-0}"
PATH_START="# >>> nonla-tunnel >>>"
PATH_END="# <<< nonla-tunnel <<<"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --invite) INVITE="${2:-}"; shift 2 ;;
    --invite=*) INVITE="${1#*=}"; shift ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --server=*) SERVER="${1#*=}"; shift ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    --no-modify-path) NO_MODIFY_PATH=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# --- platform -------------------------------------------------------------
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS $(uname -s) — on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
# A shell running under Rosetta reports x86_64 on Apple Silicon.
if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  ARCH=arm64
fi
ASSET="nonla-tunnel-$OS-$ARCH"

# --- tools ----------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() { curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "need curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
else
  die "need sha256sum, shasum or openssl to verify the download"
fi

# --- download + verify ----------------------------------------------------
if [ -n "${NONLA_DOWNLOAD_BASE:-}" ]; then
  BASE="${NONLA_DOWNLOAD_BASE%/}"
  # A mirror may be plain http/file on an internal network; checksums still apply.
  fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"; else wget -q -O "$2" "$1"; fi; }
elif [ -n "$VERSION" ]; then
  BASE="https://github.com/$REPO/releases/download/v${VERSION#v}"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t nonla-tunnel)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $ASSET ${VERSION:+v${VERSION#v} }from $BASE ..."
fetch "$BASE/$ASSET" "$TMP/$ASSET" || die "download failed: $BASE/$ASSET"
fetch "$BASE/SHA256SUMS.txt" "$TMP/SHA256SUMS.txt" || die "download failed: $BASE/SHA256SUMS.txt"
WANT="$(awk -v f="$ASSET" '$2 == f || $2 == "*"f { print $1; exit }' "$TMP/SHA256SUMS.txt")"
GOT="$(sha256 "$TMP/$ASSET")"
[ -n "$WANT" ] || die "$ASSET is not listed in SHA256SUMS.txt"
[ "$WANT" = "$GOT" ] || die "checksum mismatch for $ASSET (expected $WANT, got $GOT)"
say "Checksum OK"

mkdir -p "$INSTALL_DIR"
chmod 755 "$TMP/$ASSET"
mv -f "$TMP/$ASSET" "$INSTALL_DIR/nonla-tunnel"
BIN="$INSTALL_DIR/nonla-tunnel"
say "Installed $("$BIN" --version) → $BIN"

# --- PATH -----------------------------------------------------------------
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ON_PATH=1 ;;
  *) ON_PATH=0 ;;
esac
if [ "$ON_PATH" = 0 ] && [ "$NO_MODIFY_PATH" != 1 ]; then
  case "${SHELL:-}" in
    */zsh) RCS="$HOME/.zshrc" ;;
    */bash) if [ "$OS" = darwin ]; then RCS="$HOME/.bash_profile"; else RCS="$HOME/.bashrc"; fi ;;
    */fish) RCS="$HOME/.config/fish/config.fish" ;;
    *) RCS="$HOME/.profile" ;;
  esac
  for RC in $RCS; do
    if ! grep -qF "$PATH_START" "$RC" 2>/dev/null; then
      mkdir -p "$(dirname "$RC")"
      case "$RC" in
        *.fish) LINE="fish_add_path \"$INSTALL_DIR\"" ;;
        *) LINE="export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
      esac
      printf '\n%s\n%s\n%s\n' "$PATH_START" "$LINE" "$PATH_END" >> "$RC"
      say "Added $INSTALL_DIR to PATH in $RC (open a new shell to pick it up)"
    fi
  done
fi

# --- enroll ---------------------------------------------------------------
if [ -n "$INVITE" ]; then
  [ -n "$SERVER" ] || die "--invite needs --server connect.<domain> (or install from https://<domain>/install)"
  say "Enrolling with one-time invite..."
  # Passed via env so the invite does not show up in `ps`.
  # shellcheck disable=SC2086 # flags are intentionally word-split
  NONLA_INVITE="$INVITE" "$BIN" enroll --server "$SERVER" $NONLA_DEFAULT_ENROLL_FLAGS
else
  say ""
  say "Next:"
  say "  $BIN enroll --server ${SERVER:-connect.<domain>} --invite <nti_...>"
  say "  $BIN http 3000 --name my-app -d"
fi
