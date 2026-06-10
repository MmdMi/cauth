#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [--prefix <dir>] [--uninstall]

Install or uninstall the cauth binary.

Options:
  --prefix <dir>   Install to <dir>/bin (default: /usr/local)
  --uninstall      Remove the installed cauth binary
  --help           Show this help

Examples:
  $0                     # build & install to /usr/local/bin
  $0 --prefix ~/.local   # build & install to ~/.local/bin
  $0 --uninstall         # remove from /usr/local/bin
EOF
    exit 0
}

PREFIX="/usr/local"
UNINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

BINDIR="$PREFIX/bin"
BINARY="cauth"
INSTALL_PATH="$BINDIR/$BINARY"

if [[ "$UNINSTALL" -eq 1 ]]; then
    if [[ -f "$INSTALL_PATH" ]]; then
        rm -f "$INSTALL_PATH"
        echo "Removed $INSTALL_PATH"
    else
        echo "Not installed ($INSTALL_PATH not found)"
    fi
    exit 0
fi

cd "$(dirname "$0")"

# build
if [[ ! -x build/cauth ]]; then
    echo "Building cauth..."
    bash build.sh build
fi

mkdir -p "$BINDIR"
cp build/cauth "$INSTALL_PATH"
echo "Installed $INSTALL_PATH"
