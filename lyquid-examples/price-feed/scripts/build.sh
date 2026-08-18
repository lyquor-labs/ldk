#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_SHAKER_MANIFEST="$EXAMPLE_DIR/../../../toolchain/shaker/Cargo.toml"
usage() {
    cat <<'EOF'
Usage: scripts/build.sh

Build the Price Feed Lyquid. Its Cargo build script prepares the hosted frontend
assets before compiling the Lyquid.
EOF
}

case "${1:-}" in
    "") ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if shaker inspect --help >/dev/null 2>&1; then
    SHAKER=(shaker)
elif [[ -f "$WORKSPACE_SHAKER_MANIFEST" ]]; then
    SHAKER=(cargo run --quiet --manifest-path "$WORKSPACE_SHAKER_MANIFEST" --)
else
    echo "Price Feed requires a Shaker version with the inspect command." >&2
    exit 1
fi

"${SHAKER[@]}" build "$EXAMPLE_DIR/Cargo.toml"
