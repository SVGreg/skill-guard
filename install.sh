#!/bin/sh
# Install skill-guard from GitHub Releases (no Go toolchain required).
#
#   curl -fsSL https://raw.githubusercontent.com/SVGreg/skill-guard/main/install.sh | sh
#
# Environment overrides:
#   VERSION      release tag to install (e.g. v0.1.0); default: latest
#   INSTALL_DIR  target directory; default: /usr/local/bin
set -eu

REPO="SVGreg/skill-guard"
BINARY="skill-guard"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

err() { echo "install.sh: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar >/dev/null 2>&1 || err "tar is required"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) err "unsupported OS: $os (on Windows, download the .zip from https://github.com/$REPO/releases)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    grep -m1 '"tag_name"' | cut -d '"' -f 4)
  [ -n "$VERSION" ] || err "could not determine the latest release tag"
fi

vnum="${VERSION#v}"
asset="${BINARY}_${vnum}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $BINARY $VERSION ($os/$arch)..."
curl -fsSL -o "$tmp/$asset" "$base/$asset" || err "download failed: $base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || err "download failed: $base/checksums.txt"

(
  cd "$tmp"
  expected=$(grep " $asset\$" checksums.txt | cut -d ' ' -f 1)
  [ -n "$expected" ] || err "no checksum for $asset in checksums.txt"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$asset" | cut -d ' ' -f 1)
  else
    actual=$(shasum -a 256 "$asset" | cut -d ' ' -f 1)
  fi
  [ "$expected" = "$actual" ] || err "checksum mismatch for $asset"
)

tar -xzf "$tmp/$asset" -C "$tmp" "$BINARY"

echo "Installing to $INSTALL_DIR/$BINARY..."
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
else
  echo "$INSTALL_DIR is not writable; retrying with sudo..."
  sudo install -m 0755 "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "Installed: $("$INSTALL_DIR/$BINARY" version | head -1)"
