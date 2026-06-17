#!/bin/bash

# Bring up a local Lyquor network natively (no Docker, no docker-compose) and
# leave it running until you press Ctrl-C.
#
#   ./localnet.sh single   # one node that spawns its own Anvil devnet (default)
#   ./localnet.sh multi     # a shared Anvil + a 4-node UPC mesh
#
# Bartender is pulled from a released GHCR image rather than built. Pick a
# specific build with LYQUOR_IMAGE_TAG (e.g. v0.1.0) or LYQUOR_BARTENDER_REFERENCE.
#
# Requirements on PATH: lyquor, shaker (install via shakenup.sh), plus the
# Foundry tools cast and anvil, and curl. If lyquor/shaker are not on PATH, set
# LYQUOR_BIN_DIR to the directory that holds them.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ldk/scripts/lib/localnet.sh
. "$HERE/lib/localnet.sh"

usage() {
    echo "Usage: $0 [single|multi]" >&2
}

TOPOLOGY="${1:-single}"
case "$TOPOLOGY" in
    single|multi) ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
esac

trap localnet_down EXIT INT TERM

localnet_up "$TOPOLOGY"
localnet_print_endpoints

echo "Localnet is running. Press Ctrl-C to stop and clean up."

# Block until interrupted, exiting early if any node or Anvil process dies.
while :; do
    for pid in "${_LOCALNET_PIDS[@]}"; do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            echo "A localnet process (pid ${pid}) exited unexpectedly." >&2
            exit 1
        fi
    done
    sleep 2
done
