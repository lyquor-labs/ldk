#!/usr/bin/env bash

# Shared localnet lifecycle and Lyquid deployment helpers for example run scripts.
# Source this file, add the example-specific setup, then run a foreground shaker
# command to keep the localnet alive until Ctrl-C.

DEMO_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_EXAMPLES_DIR="$(cd "$DEMO_LIB_DIR/../.." && pwd)"
DEMO_LDK_DIR="$(cd "$DEMO_EXAMPLES_DIR/.." && pwd)"
DEMO_LOCALNET_SCRIPT="${DEMO_LOCALNET_SCRIPT:-$DEMO_LDK_DIR/scripts/localnet.sh}"

DEMO_PRIMARY_WS="ws://127.0.0.1:10087/ws"
DEMO_REGISTRY_REPO="http://127.0.0.1:10087/lyquids"
DEMO_SIGNER_KEY="${DEMO_SIGNER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEMO_NODE_WS=(
    "ws://127.0.0.1:10087/ws"
    "ws://127.0.0.1:11087/ws"
    "ws://127.0.0.1:12087/ws"
    "ws://127.0.0.1:13087/ws"
)

DEMO_LOCALNET_PID=""
DEMO_TOPOLOGY=""
LYQUID_ID=""
LYQUID_CONTRACT=""
LYQUID_TARGET=""

demo_die() {
    echo "$*" >&2
    exit 1
}

demo_require_tools() {
    if [[ -n "${LYQUOR_BIN_DIR:-}" ]]; then
        PATH="$LYQUOR_BIN_DIR:$PATH"
        export PATH
    fi

    local tool
    for tool in cast curl jq lyquor python3 shaker; do
        command -v "$tool" >/dev/null 2>&1 || demo_die "Required tool '$tool' is not available on PATH."
    done
    [[ -x "$DEMO_LOCALNET_SCRIPT" ]] || demo_die "Localnet script is not executable: $DEMO_LOCALNET_SCRIPT"
}

demo_cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$DEMO_LOCALNET_PID" ]] && kill -0 -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1; then
        echo
        echo "Stopping localnet."
        kill -TERM -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1 || true
        wait "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || true
    fi
    return "$status"
}

demo_start_localnet() {
    local deadline
    local ports=(8545 10080 10087)
    DEMO_TOPOLOGY="${1:-single}"
    case "$DEMO_TOPOLOGY" in
        single) DEMO_NODE_WS=("$DEMO_PRIMARY_WS") ;;
        multi) ports+=(11080 11087 12080 12087 13080 13087) ;;
        *) demo_die "Unknown localnet topology: $DEMO_TOPOLOGY" ;;
    esac
    demo_require_tools

    python3 - "${ports[@]}" <<'PY'
import socket
import sys

occupied = []
for value in sys.argv[1:]:
    port = int(value)
    with socket.socket() as probe:
        probe.settimeout(0.2)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            occupied.append(port)

if occupied:
    joined = ", ".join(str(port) for port in occupied)
    raise SystemExit(f"Localnet ports are already in use: {joined}")
PY

    echo "Starting the existing native localnet (${DEMO_TOPOLOGY})."
    python3 - "$DEMO_LOCALNET_SCRIPT" "$DEMO_TOPOLOGY" <<'PY' &
import os
import sys

os.setpgrp()
os.execv(sys.argv[1], sys.argv[1:])
PY
    DEMO_LOCALNET_PID=$!
    trap demo_cleanup EXIT
    trap 'exit 130' INT TERM

    deadline=$((SECONDS + 120))
    while :; do
        if curl --data '{}' --header 'content-type: application/json' \
            -sf "http://127.0.0.1:10087/lyquor.lyquid.v1.LyquidService/GetLyquidInfo" \
            | grep -Eq '"value"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]{40}"'; then
            kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Spawned localnet exited during startup."
            break
        fi
        if ! kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1; then
            wait "$DEMO_LOCALNET_PID" || true
            demo_die "Localnet exited before bartender was ready."
        fi
        ((SECONDS < deadline)) || demo_die "Bartender was not ready after 120 seconds."
        sleep 1
    done
}

demo_deploy() {
    local name="$1"
    local manifest="$2"
    local constructor_input="${3:-}"
    local output
    local args=(deploy --endpoint "$DEMO_PRIMARY_WS" --private-key "$DEMO_SIGNER_KEY" --debug --output json)

    if [[ "$DEMO_TOPOLOGY" == "multi" ]]; then
        args+=(--reference "$DEMO_REGISTRY_REPO:${name}-local")
    fi
    args+=("$manifest")
    if [[ -n "$constructor_input" ]]; then
        args+=(--input "$constructor_input")
    fi

    echo "Building and deploying $name with shaker."
    output="$(shaker "${args[@]}")"
    LYQUID_ID="$(printf '%s\n' "$output" | jq -r '.lyquid_id // empty')"
    LYQUID_CONTRACT="$(printf '%s\n' "$output" | jq -r '.contract // empty')"
    [[ "$LYQUID_ID" == Lyquid-* ]] || demo_die "Shaker did not return a Lyquid ID: $output"
    [[ "$LYQUID_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]] || demo_die "Shaker did not return a contract: $output"
    LYQUID_TARGET="$(shaker to-hex "$LYQUID_ID")"

    echo "  Lyquid:  $LYQUID_ID"
    echo "  Contract: $LYQUID_CONTRACT"
}

demo_node_id_hex() {
    local api_port="$((10087 + 1000 * $1))"
    local node_id
    node_id="$(curl --silent --fail \
        --data '{}' \
        --header 'content-type: application/json' \
        "http://127.0.0.1:${api_port}/lyquor.node.v1.NodeService/GetNodeInfo" \
        | jq -r '.node_id.value // .nodeId.value // empty')"
    [[ -n "$node_id" ]] || demo_die "Could not read the Node ID from port $api_port."

    python3 - "$node_id" <<'PY'
import base64
import sys

value = sys.argv[1]
if value.startswith("Node-"):
    value = value[5:]
value = value.upper()
value += "=" * ((8 - len(value) % 8) % 8)
decoded = base64.b32decode(value, casefold=True)
if len(decoded) != 35:
    raise SystemExit(f"unexpected Node ID length: {len(decoded)}")
print("0x" + decoded[:32].hex())
PY
}

demo_node_ids_array() {
    local values=()
    local index
    for ((index = 0; index < ${#DEMO_NODE_WS[@]}; index++)); do
        values+=("$(demo_node_id_hex "$index")")
    done
    demo_array "${values[@]}"
}

demo_array() {
    local separator=""
    local value
    printf '['
    for value in "$@"; do
        printf '%s%s' "$separator" "$value"
        separator=,
    done
    printf ']'
}

demo_string_array() {
    local separator=""
    local value
    printf '['
    for value in "$@"; do
        printf '%s"%s"' "$separator" "$value"
        separator=,
    done
    printf ']'
}

demo_call_at() {
    local endpoint="$1"
    local signature="$2"
    shift 2

    local call_signature="${signature%% returns *}"
    local output
    output="$(cast call --rpc-timeout 20 --rpc-url "$endpoint" "$LYQUID_CONTRACT" "$call_signature" "$@")"

    if [[ "$call_signature" == "$signature" ]]; then
        printf '%s\n' "$output"
    else
        cast abi-decode "$signature" "$output"
    fi
}

demo_call() {
    demo_call_at "$DEMO_PRIMARY_WS" "$@"
}

demo_send() {
    cast send \
        --private-key "$DEMO_SIGNER_KEY" \
        --quiet \
        --rpc-url "$DEMO_PRIMARY_WS" \
        "$LYQUID_CONTRACT" \
        "$@"
}

demo_initialize_oracle() {
    local topic="$1"
    local threshold="$2"
    demo_send \
        "__lyquor_oracle_initialize(string,address,bool,bytes32[],uint16)" \
        "$topic" \
        "$LYQUID_TARGET" \
        false \
        "$(demo_node_ids_array)" \
        "$threshold"
}

demo_expect_true() {
    local result
    result="$(printf '%s' "$1" | tr -d '[:space:]')"
    [[ "$result" == "true" || "$result" == "1" ]] || demo_die "$2 returned: $1"
}

demo_wait_for_lyquid() {
    local probe_signature="$1"
    local deadline
    local endpoint
    echo "Waiting for the Lyquid to become callable on every node."
    for endpoint in "${DEMO_NODE_WS[@]}"; do
        deadline=$((SECONDS + 60))
        while ! demo_call_at "$endpoint" "$probe_signature" >/dev/null 2>&1; do
            kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while waiting for $endpoint."
            ((SECONDS < deadline)) || demo_die "Lyquid was not callable on $endpoint after 60 seconds."
            sleep 1
        done
    done
}

demo_oracle_epoch() {
    local topic="$1"
    local endpoint="${2:-$DEMO_PRIMARY_WS}"
    demo_call_at "$endpoint" \
        "__lyquor_oracle_dest_epoch_info(string,bool) returns (uint64,bytes32,uint32,bytes)" \
        "$topic" \
        false \
        | sed -n '1p' \
        | tr -d '[:space:]'
}

demo_activate_oracle() {
    local topic="$1"
    local deadline
    local endpoint
    local old_epoch
    local new_epoch
    local peer_epoch
    local result
    old_epoch="$(demo_oracle_epoch "$topic")"

    echo "Activating the $topic oracle committee."
    deadline=$((SECONDS + 60))
    while :; do
        result="$(demo_call \
            "__lyquor_oracle_advance_epoch(string,address,bool) returns (bool)" \
            "$topic" \
            "$LYQUID_TARGET" \
            false)"
        [[ "$(printf '%s' "$result" | tr -d '[:space:]')" == "true" ]] && break
        kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while advancing the oracle epoch."
        ((SECONDS < deadline)) || demo_die "Oracle epoch did not start advancing after 60 seconds."
        sleep 1
    done

    deadline=$((SECONDS + 60))
    while :; do
        new_epoch="$(demo_oracle_epoch "$topic")"
        if [[ "$new_epoch" =~ ^[0-9]+$ ]] && ((new_epoch > old_epoch)); then
            break
        fi
        kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while advancing the oracle epoch."
        ((SECONDS < deadline)) || demo_die "Oracle epoch did not advance after 60 seconds."
        sleep 1
    done

    echo "Waiting for every node to observe oracle epoch $new_epoch."
    for endpoint in "${DEMO_NODE_WS[@]}"; do
        deadline=$((SECONDS + 60))
        while :; do
            peer_epoch="$(demo_oracle_epoch "$topic" "$endpoint" 2>/dev/null || true)"
            if [[ "$peer_epoch" =~ ^[0-9]+$ ]] && ((peer_epoch >= new_epoch)); then
                break
            fi
            kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while synchronizing oracle peers."
            ((SECONDS < deadline)) || demo_die "$endpoint did not observe oracle epoch $new_epoch after 60 seconds."
            sleep 1
        done
    done

    result="$(demo_call \
        "__lyquor_oracle_finalize_epoch(string,address,bool) returns (bool)" \
        "$topic" \
        "$LYQUID_TARGET" \
        false)"
    demo_expect_true "$result" "finalize oracle epoch"
}

demo_wait_for_committee() {
    local expected="$1"
    local committee
    local count
    local deadline
    local endpoint
    echo "Waiting for every node to observe the $expected-member committee."
    for endpoint in "${DEMO_NODE_WS[@]}"; do
        deadline=$((SECONDS + 60))
        while :; do
            committee="$(demo_call_at "$endpoint" "get_node_ids() returns (string[])" 2>/dev/null || true)"
            count="$(printf '%s' "$committee" | grep -o 'Node-' | wc -l | tr -d ' ' || true)"
            [[ "$count" == "$expected" ]] && break
            kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while waiting for $endpoint."
            ((SECONDS < deadline)) || demo_die "$endpoint did not observe the committee after 60 seconds."
            sleep 1
        done
    done
}
