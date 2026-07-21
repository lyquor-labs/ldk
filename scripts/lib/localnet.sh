#!/bin/bash

# Reusable helpers to bring up a Lyquor "localnet" natively, without Docker.
#
# This library is the shared core behind the `localnet.sh` demo and the
# repository's native end-to-end test. Source it, then drive it with:
#
#     . lib/localnet.sh
#     trap localnet_down EXIT
#     localnet_up single   # or: localnet_up multi
#
# After `localnet_up` returns, the following globals describe the running
# topology (single-value strings are space-separated lists where plural):
#
#     LOCALNET_TOPOLOGY          single | multi
#     LOCALNET_WORK_DIR          scratch dir holding configs, data and logs
#     LOCALNET_NODE_COUNT        number of nodes started
#     LOCALNET_NODE_API_URLS     http API URLs, one per node
#     LOCALNET_NODE_WS_URLS      ws API URLs, one per node
#     LOCALNET_PRIMARY_WS        ws endpoint of the bootstrap node (node 1)
#     LOCALNET_PRIMARY_API       http API endpoint of the bootstrap node
#     LOCALNET_SECONDARY_WS      ws endpoint of a second node (== primary for single)
#     LOCALNET_SECONDARY_API     http API endpoint of a second node (== primary for single)
#     LOCALNET_REGISTRY_REPO     OCI repo peers pull deployed lyquids from
#                                (node 1's built-in registry for multi; empty for single)
#
# Bartender is never built from source here: it is deployed straight from a
# released GHCR image via `shaker deploy --is-bartender --reference ...`. Override
# the image with LYQUOR_BARTENDER_REFERENCE, or pick a tag with LYQUOR_IMAGE_TAG.
#
# This file targets bash 3.2 (the system bash on macOS): no `wait -n`, no
# associative arrays, no `${var^^}`.

# Deterministic devnet node identities, indexed by node seed (0x..00, 0x..01, ...).
# These match docker/multi/node*.toml so the peer mesh is stable across runs.
_LOCALNET_NODE_IDS=(
    "Node-ve3tav5jw5ico7or34gcb6ni7rtmd35uokriuijygabd3tsltd7fj6ia"
    "Node-j3fcdy5twah7csa6pr4jhgxcvszycxdms2hsen5m7lrvtezqlv52cqaa"
    "Node-2folhfgf4kuyfdenaq3l4dnamv7yxrnqq3zbp64thfa5esqgxhv6wzqa"
    "Node-oq2lcra5u4ksufzsv2ciqbl56dkp5c653ikzkx3lh62tai566d7dseia"
)

# Anvil-funded account keys used as per-node submitter keys in the multi-node topology.
_LOCALNET_SUBMITTER_KEYS=(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    "0x59c6995e998f97a5a0044966f094538b292d4b6ec65dc1d614831ea8775e8ece"
    "0x5de4111b365a7a9898a14f3e60feec33b047b1c4ae38d8e76cfb7ec4fe99e995"
    "0x7c852118294d6bd9e0f73f6a7f9ff8ad6dde4170f18a30b8f78cd9a50b2e5c9f"
)

# Host ports. Node i (0-based) listens on API 10087+1000*i and UPC 10080+1000*i,
# matching the host-exposed ports in docker/multi/docker-compose.yaml.
_LOCALNET_API_BASE=10087
_LOCALNET_UPC_BASE=10080
_LOCALNET_ANVIL_PORT=8545

# Process IDs we started, so localnet_down can stop them.
_LOCALNET_PIDS=()

_localnet_log() {
    printf '%s\n' "$*" >&2
}

# Resolve the bartender OCI reference to deploy. Precedence:
#   1. LYQUOR_BARTENDER_REFERENCE (full reference)
#   2. ghcr.io/lyquor-labs/lyquids:bartender-<LYQUOR_IMAGE_TAG> (defaults to v0.4.0)
localnet_bartender_reference() {
    if [[ -n "${LYQUOR_BARTENDER_REFERENCE:-}" ]]; then
        printf '%s' "$LYQUOR_BARTENDER_REFERENCE"
    else
        printf 'ghcr.io/lyquor-labs/lyquids:bartender-%s' "${LYQUOR_IMAGE_TAG:-v0.4.0}"
    fi
}

# Make sure the binaries we need are on PATH; fall back to common locations.
# anvil is required for both topologies: the single node spawns its own Anvil
# devnet, and multi shares one started here.
localnet_ensure_tools() {
    if ! command -v lyquor >/dev/null 2>&1 || ! command -v shaker >/dev/null 2>&1; then
        local candidate
        for candidate in "${LYQUOR_BIN_DIR:-}" "${E2E_BIN_DIR:-}" "./target/debug" "./target/release"; do
            if [[ -n "$candidate" && -x "$candidate/lyquor" && -x "$candidate/shaker" ]]; then
                PATH="$candidate:$PATH"
                export PATH
                break
            fi
        done
    fi

    local tool
    for tool in anvil cast curl lyquor shaker; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            _localnet_log "Required tool '$tool' is not available on PATH."
            return 1
        fi
    done
}

_localnet_node_api_port() {
    echo "$(( _LOCALNET_API_BASE + 1000 * $1 ))"
}

_localnet_node_upc_port() {
    echo "$(( _LOCALNET_UPC_BASE + 1000 * $1 ))"
}

# Poll a node's API until GetNodeInfo answers, failing fast if its PID died.
_localnet_wait_node() {
    local http_url="$1"
    local pid="$2"
    local i
    for i in $(seq 1 180); do
        if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
            _localnet_log "Lyquor node (pid ${pid}) exited before becoming ready."
            return 1
        fi
        if curl --data '{}' --header 'content-type: application/json' \
            -sf "${http_url}/lyquor.node.v1.NodeService/GetNodeInfo" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    _localnet_log "Lyquor node did not become ready at ${http_url}."
    return 1
}

# Poll a node until it reports a deployed bartender contract.
_localnet_wait_bartender() {
    local http_url="$1"
    local i
    for i in $(seq 1 120); do
        if curl --data '{}' --header 'content-type: application/json' \
            -sf "${http_url}/lyquor.lyquid.v1.LyquidService/GetLyquidInfo" | _localnet_has_bartender_contract; then
            return 0
        fi
        sleep 1
    done
    _localnet_log "Bartender did not become visible through GetLyquidInfo at ${http_url}."
    return 1
}

# Deploy bartender from the released GHCR image (idempotent).
_localnet_deploy_bartender() {
    local ws_url="$1"
    local http_url="$2"
    local reference
    reference="$(localnet_bartender_reference)"

    if curl --data '{}' --header 'content-type: application/json' \
        -sf "${http_url}/lyquor.lyquid.v1.LyquidService/GetLyquidInfo" | _localnet_has_bartender_contract; then
        _localnet_log "Bartender already deployed."
        return 0
    fi

    _localnet_log "Deploying bartender from ${reference}"
    shaker deploy --is-bartender --reference "$reference" --endpoint "$ws_url"
    _localnet_wait_bartender "$http_url"
}

_localnet_wait_anvil() {
    local rpc_url="$1"
    local i
    for i in $(seq 1 60); do
        if cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    _localnet_log "Anvil did not become ready at ${rpc_url}."
    return 1
}

_localnet_has_bartender_contract() {
    grep -Eq '"value"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]{40}"'
}

_localnet_write_submitter_key() {
    local idx="$1"
    local path="$2"
    local key="${_LOCALNET_SUBMITTER_KEYS[$idx]:-}"
    if [[ -z "$key" ]]; then
        _localnet_log "No Anvil submitter key configured for localnet node index ${idx}."
        return 1
    fi
    printf '%s\n' "$key" > "$path"
    chmod 600 "$path"
}

# Write a multi-node config for node index $1 (0-based) to file $2.
_localnet_write_multi_config() {
    local idx="$1"
    local file="$2"
    local seed
    local submitter_key_file
    seed="0x$(printf '%064d' "$idx")"
    submitter_key_file="$(dirname "$file")/eth-submitter.key"

    {
        printf '[profile]\n'
        printf 'base = "devnet"\n'
        printf 'sequencer = "ws://127.0.0.1:%s"\n\n' "$_LOCALNET_ANVIL_PORT"
        printf '[submitter]\n'
        printf 'key_file = "%s"\n\n' "$submitter_key_file"
        printf '[node_key]\n'
        printf 'type = "seed"\n'
        printf 'value = "%s"\n\n' "$seed"
        printf '[network]\n'
        printf 'api_addr = "127.0.0.1:%s"\n' "$(_localnet_node_api_port "$idx")"
        printf 'upc_addr = "127.0.0.1:%s"\n\n' "$(_localnet_node_upc_port "$idx")"
        printf '[image]\n'
        # Peers pull deployed lyquids from node 1's built-in registry; GHCR is the
        # fallback for bartender and any pre-published example images.
        printf 'fallback_repos = ["http://127.0.0.1:%s/lyquids", "ghcr.io/lyquor-labs/lyquids"]\n' \
            "$_LOCALNET_API_BASE"

        local peer
        for peer in 0 1 2 3; do
            if [[ "$peer" -eq "$idx" ]]; then
                continue
            fi
            printf '\n[[peers]]\n'
            printf 'node_id = "%s"\n' "${_LOCALNET_NODE_IDS[$peer]}"
            printf 'upc_addr = "127.0.0.1:%s"\n' "$(_localnet_node_upc_port "$peer")"
        done
    } > "$file"
}

_localnet_prepare_work_dir() {
    if [[ -n "${LOCALNET_WORK_DIR:-}" ]]; then
        mkdir -p "$LOCALNET_WORK_DIR"
        _LOCALNET_CLEAN_WORK_DIR=0
    else
        LOCALNET_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lyquor-localnet.XXXXXX")"
        _LOCALNET_CLEAN_WORK_DIR=1
    fi
}

# The LOCALNET_* assignments below are this library's public interface, read by
# scripts that source it; they are not all referenced within this file.
# shellcheck disable=SC2034
_localnet_up_single() {
    LOCALNET_NODE_COUNT=1
    local api_port="$_LOCALNET_API_BASE"
    local upc_port="$_LOCALNET_UPC_BASE"
    local http_url="http://127.0.0.1:${api_port}"
    local ws_url="ws://127.0.0.1:${api_port}/ws"
    local data_dir="$LOCALNET_WORK_DIR/node0/data"
    local log="$LOCALNET_WORK_DIR/node0/lyquor.log"
    mkdir -p "$data_dir" "$(dirname "$log")"

    _localnet_log "Starting single Lyquor node at ${http_url} (spawns its own Anvil devnet)"
    LYQUOR_LOG="${LYQUOR_LOG:-info}" \
    LYQUOR_DATA_DIR="$data_dir" \
        lyquor \
        --config-override "network.api_addr=127.0.0.1:${api_port}" \
        --config-override "network.upc_addr=127.0.0.1:${upc_port}" \
        > "$log" 2>&1 &
    local pid=$!
    _LOCALNET_PIDS+=("$pid")
    _localnet_wait_node "$http_url" "$pid"
    _localnet_deploy_bartender "$ws_url" "$http_url"

    LOCALNET_NODE_API_URLS="${http_url}/api"
    LOCALNET_NODE_WS_URLS="$ws_url"
    LOCALNET_PRIMARY_WS="$ws_url"
    LOCALNET_PRIMARY_API="${http_url}/api"
    LOCALNET_SECONDARY_WS="$ws_url"
    LOCALNET_SECONDARY_API="${http_url}/api"
    LOCALNET_REGISTRY_REPO=""
}

# See _localnet_up_single: the LOCALNET_* globals here are the public interface.
# shellcheck disable=SC2034
_localnet_up_multi() {
    LOCALNET_NODE_COUNT=4
    local anvil_rpc="http://127.0.0.1:${_LOCALNET_ANVIL_PORT}"
    local anvil_log="$LOCALNET_WORK_DIR/anvil.log"

    _localnet_log "Starting shared Anvil sequencer at ${anvil_rpc}"
    anvil --host 127.0.0.1 --port "$_LOCALNET_ANVIL_PORT" --silent > "$anvil_log" 2>&1 &
    _LOCALNET_PIDS+=("$!")
    _localnet_wait_anvil "$anvil_rpc"

    LOCALNET_NODE_API_URLS=""
    LOCALNET_NODE_WS_URLS=""
    local node_http_urls=""

    local idx
    for idx in 0 1 2 3; do
        local api_port http_url ws_url cfg data_dir log
        api_port="$(_localnet_node_api_port "$idx")"
        http_url="http://127.0.0.1:${api_port}"
        ws_url="ws://127.0.0.1:${api_port}/ws"
        cfg="$LOCALNET_WORK_DIR/node${idx}/node.toml"
        data_dir="$LOCALNET_WORK_DIR/node${idx}/data"
        log="$LOCALNET_WORK_DIR/node${idx}/lyquor.log"
        mkdir -p "$data_dir" "$(dirname "$cfg")"
        _localnet_write_submitter_key "$idx" "$(dirname "$cfg")/eth-submitter.key" || return 1
        _localnet_write_multi_config "$idx" "$cfg" || return 1

        _localnet_log "Starting Lyquor node $((idx + 1)) at ${http_url}"
        LYQUOR_LOG="${LYQUOR_LOG:-info}" \
        LYQUOR_DATA_DIR="$data_dir" \
            lyquor --config "$cfg" > "$log" 2>&1 &
        _LOCALNET_PIDS+=("$!")

        node_http_urls="${node_http_urls:+$node_http_urls }${http_url}"
        LOCALNET_NODE_API_URLS="${LOCALNET_NODE_API_URLS:+$LOCALNET_NODE_API_URLS }${http_url}/api"
        LOCALNET_NODE_WS_URLS="${LOCALNET_NODE_WS_URLS:+$LOCALNET_NODE_WS_URLS }${ws_url}"
    done

    local primary_http="http://127.0.0.1:${_LOCALNET_API_BASE}"
    local primary_ws="ws://127.0.0.1:${_LOCALNET_API_BASE}/ws"
    local secondary_port secondary_http secondary_ws
    secondary_port="$(_localnet_node_api_port 1)"
    secondary_http="http://127.0.0.1:${secondary_port}"
    secondary_ws="ws://127.0.0.1:${secondary_port}/ws"

    # Wait for *every* node's API before returning so a still-booting node 3/4
    # does not flake callers. Then bootstrap bartender via node 1 and confirm it
    # propagated to node 2 (so cross-node calls in the demo/e2e are ready).
    local node_http
    for node_http in $node_http_urls; do
        _localnet_wait_node "$node_http" ""
    done
    _localnet_deploy_bartender "$primary_ws" "$primary_http"
    _localnet_wait_bartender "$secondary_http"

    LOCALNET_PRIMARY_WS="$primary_ws"
    LOCALNET_PRIMARY_API="${primary_http}/api"
    LOCALNET_SECONDARY_WS="$secondary_ws"
    LOCALNET_SECONDARY_API="${secondary_http}/api"
    LOCALNET_REGISTRY_REPO="http://127.0.0.1:${_LOCALNET_API_BASE}/lyquids"
}

# Bring up a localnet of the requested topology: single | multi.
localnet_up() {
    local topology="${1:-single}"
    case "$topology" in
        single|multi) ;;
        *)
            _localnet_log "Unknown topology '${topology}'. Expected 'single' or 'multi'."
            return 1
            ;;
    esac

    localnet_ensure_tools

    LOCALNET_TOPOLOGY="$topology"
    _localnet_prepare_work_dir

    if [[ "$topology" == "single" ]]; then
        _localnet_up_single
    else
        _localnet_up_multi
    fi
}

localnet_dump_logs() {
    local log
    while IFS= read -r log; do
        echo "===== ${log} ====="
        cat "$log"
    done < <(find "${LOCALNET_WORK_DIR:-/nonexistent}" -name '*.log' -type f 2>/dev/null | sort)
}

# Stop everything started by localnet_up. Safe to use as an EXIT/INT/TERM trap;
# dumps node logs when tearing down after a genuine failure.
localnet_down() {
    local status=$?
    trap - EXIT INT TERM

    if [[ "$status" -ne 0 && "$status" -ne 130 && "$status" -ne 143 ]]; then
        localnet_dump_logs
    fi

    local pid
    # Stop in reverse start order: nodes before the shared Anvil they depend on.
    local i
    for (( i = ${#_LOCALNET_PIDS[@]} - 1; i >= 0; i-- )); do
        pid="${_LOCALNET_PIDS[$i]}"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill -TERM "$pid" >/dev/null 2>&1 || true
        fi
    done
    for (( i = ${#_LOCALNET_PIDS[@]} - 1; i >= 0; i-- )); do
        pid="${_LOCALNET_PIDS[$i]}"
        [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true
    done
    _LOCALNET_PIDS=()

    if [[ "${_LOCALNET_CLEAN_WORK_DIR:-0}" -eq 1 && -n "${LOCALNET_WORK_DIR:-}" ]]; then
        rm -rf "$LOCALNET_WORK_DIR"
        # Forget the temp dir so a later localnet_up allocates a fresh one (e.g.
        # when bringing up several topologies from one process).
        LOCALNET_WORK_DIR=""
        _LOCALNET_CLEAN_WORK_DIR=0
    elif [[ -n "${LOCALNET_WORK_DIR:-}" ]]; then
        _localnet_log "Localnet work directory preserved at ${LOCALNET_WORK_DIR}"
    fi

    if [[ "$status" -ne 0 ]]; then
        exit "$status"
    fi
}

# Print a human-friendly summary of the running localnet (used by the demo CLI).
localnet_print_endpoints() {
    echo
    echo "Lyquor localnet (${LOCALNET_TOPOLOGY}) is up with ${LOCALNET_NODE_COUNT} node(s)."
    echo
    local i=1
    local api ws
    # Iterate the space-separated URL lists in lockstep.
    local apis="$LOCALNET_NODE_API_URLS"
    local wss="$LOCALNET_NODE_WS_URLS"
    for api in $apis; do
        ws="$(echo "$wss" | cut -d' ' -f"$i")"
        echo "  Node ${i}:"
        echo "    API:       ${api}"
        echo "    WebSocket: ${ws}"
        i=$(( i + 1 ))
    done
    echo
    echo "Deploy the hello example (built from source) against node 1:"
    if [[ -n "$LOCALNET_REGISTRY_REPO" ]]; then
        echo "  shaker deploy --endpoint ${LOCALNET_PRIMARY_WS} \\"
        echo "    --reference ${LOCALNET_REGISTRY_REPO}:hello lyquid-examples/hello/Cargo.toml"
    else
        echo "  shaker deploy --endpoint ${LOCALNET_PRIMARY_WS} lyquid-examples/hello/Cargo.toml"
    fi
    echo
}
