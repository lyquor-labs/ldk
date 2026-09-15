#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOW_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXAMPLES_DIR="$(cd "$FLOW_DIR/.." && pwd)"
LDK_DIR="$(cd "$EXAMPLES_DIR/.." && pwd)"
REPO_DIR="$(cd "$LDK_DIR/.." && pwd)"

command -v cargo >/dev/null 2>&1 || {
    echo "Required tool 'cargo' is not available on PATH." >&2
    exit 1
}

workspace_version="$(awk '
    $0 == "[workspace.package]" { workspace_package = 1; next }
    workspace_package && /^version = "/ {
        value = $0
        sub(/^version = "/, "", value)
        sub(/"$/, "", value)
        print value
        exit
    }
' "$REPO_DIR/Cargo.toml")"
source_revision="$(git -C "$REPO_DIR" rev-parse --short=7 HEAD 2>/dev/null || true)"

tool_is_current() {
    local output
    [[ -x "$1" ]] || return 1
    output="$("$1" --version 2>&1)" || return 1
    [[ "$output" == *"$workspace_version"* ]] || return 1
    [[ -z "$source_revision" || "$output" == *"$source_revision"* ]]
}

if [[ "${REBUILD_TOOLS:-0}" == "1" ]] \
    || ! tool_is_current "$REPO_DIR/target/debug/lyquor" \
    || ! tool_is_current "$REPO_DIR/target/debug/shaker"; then
    echo "Building matching local Lyquor and Shaker binaries."
    cargo build --locked \
        --manifest-path "$REPO_DIR/Cargo.toml" \
        --package shaker --bin shaker \
        --package lyquor-node --bin lyquor
else
    echo "Using matching local Lyquor and Shaker binaries."
fi

PATH="$REPO_DIR/target/debug:$PATH"
export PATH

# shellcheck source=../../scripts/lib/demo.sh
. "$EXAMPLES_DIR/scripts/lib/demo.sh"

PAYMENT_KEY="${PAYMENT_KEY:?Set PAYMENT_KEY to the private key of a Base Sepolia account funded with USDC.}"
USDC_AMOUNT="${USDC_AMOUNT:-0.000001}"
RESOURCE_URL="${RESOURCE_URL:-https://api.example.com/example}"
RECIPIENT_ADDRESS="${RECIPIENT_ADDRESS:-0x70997970C51812dc3A010C7d01b50e0d17dc79C8}"
BASESCAN_TX_URL="${BASESCAN_TX_URL:-https://sepolia.basescan.org/tx}"

amount_base_units="$(python3 - "$USDC_AMOUNT" <<'PY'
from decimal import Decimal, InvalidOperation
import sys

try:
    amount = Decimal(sys.argv[1])
except InvalidOperation as error:
    raise SystemExit(f"invalid USDC_AMOUNT: {error}") from error

base_units = amount * 1_000_000
if not amount.is_finite() or amount <= 0:
    raise SystemExit("USDC_AMOUNT must be a positive finite number")
if base_units != base_units.to_integral_value():
    raise SystemExit("USDC_AMOUNT supports at most 6 decimal places")

print(int(base_units))
PY
)"
buyer="$(cast wallet address --private-key "$PAYMENT_KEY")"

example_dir=""
cleanup() {
    local status=$?
    local watchdog_pid
    trap - EXIT INT TERM
    if [[ -n "$example_dir" ]]; then
        rm -rf -- "$example_dir"
    fi
    if [[ -n "$DEMO_LOCALNET_PID" ]] && kill -0 -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1; then
        echo
        echo "Stopping localnet."
        kill -TERM -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1 || true
        (
            sleep 5
            if kill -0 -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1; then
                echo "Localnet did not stop gracefully; forcing shutdown."
                kill -KILL -- "-$DEMO_LOCALNET_PID" >/dev/null 2>&1 || true
            fi
        ) &
        watchdog_pid=$!
        wait "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || true
        kill -TERM "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" >/dev/null 2>&1 || true
    fi
    return "$status"
}

demo_start_localnet single
trap cleanup EXIT

example_dir="$(mktemp -d "${TMPDIR:-/tmp}/circle-nanopay-flow-example.XXXXXX")"

cat > "$example_dir/Cargo.toml" <<EOF
[workspace]

[package]
name = "circle-nanopay-flow-example"
version = "0.0.0"
edition = "2024"

[dependencies]
circle-nanopay-flow = { path = "$FLOW_DIR" }
lyquid = { path = "$LDK_DIR/lyquid", features = ["ldk"] }
lyquid-flow = { path = "$LDK_DIR/lyquid-flow" }
serde_json = "1.0.150"

[lib]
crate-type = ["cdylib"]
path = "$FLOW_DIR/example/payment-example.rs"
EOF
cp "$LDK_DIR/Cargo.lock" "$example_dir/Cargo.lock"

demo_deploy "circle-nanopay-flow-example" "$example_dir/Cargo.toml"
demo_wait_for_lyquid "is_ready() returns (bool)"

execution_id="$(
    demo_call \
        "start_payment(string,string,string,string,string,string) returns (uint64)" \
        "$RESOURCE_URL" \
        "$amount_base_units" \
        "eip155:84532" \
        "payment-flow-example" \
        "$buyer" \
        "$RECIPIENT_ADDRESS" \
        | tr -d '[:space:]'
)"
echo "Started payment execution $execution_id; waiting for authorization requirements."

deadline=$((SECONDS + 60))
while :; do
    encoded_requirements="$(
        demo_call "get_payment_authorization_request(uint64) returns (string)" "$execution_id" 2>/dev/null || true
    )"
    if [[ -n "$encoded_requirements" ]] \
        && requirements="$(printf '%s' "$encoded_requirements" | jq -er . 2>/dev/null)" \
        && printf '%s' "$requirements" | jq -e '.chain_id and .asset_contract and .pay_to and .nonce' >/dev/null; then
        break
    fi
    encoded_state="$(demo_call "get_payment_state(uint64) returns (string)" "$execution_id" 2>/dev/null || true)"
    if [[ -n "$encoded_state" ]] && state="$(printf '%s' "$encoded_state" | jq -er . 2>/dev/null)"; then
        status="$(printf '%s' "$state" | jq -r 'keys[0]')"
        if [[ "$status" == "Failed" ]]; then
            reason="$(printf '%s' "$state" | jq -r .Failed.reason)"
            demo_die "Payment failed while preparing authorization requirements: $reason"
        fi
    fi
    kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while preparing the payment."
    ((SECONDS < deadline)) || demo_die "Payment requirements were not ready after 60 seconds."
    sleep 1
done

chain_id="$(printf '%s' "$requirements" | jq -r .chain_id)"
asset_contract="$(printf '%s' "$requirements" | jq -r .asset_contract)"
pay_to="$(printf '%s' "$requirements" | jq -r .pay_to)"
value="$(printf '%s' "$requirements" | jq -r .amount_base_units)"
nonce="$(printf '%s' "$requirements" | jq -r .nonce)"
domain_name="$(printf '%s' "$requirements" | jq -r .asset_eip712_name)"
domain_version="$(printf '%s' "$requirements" | jq -r .asset_eip712_version)"
valid_after="$(( $(date +%s) - 600 ))"
valid_before="$(( $(date +%s) + 7 * 24 * 60 * 60 ))"

typed_data="$(
    jq -cn \
        --arg domain_name "$domain_name" \
        --arg domain_version "$domain_version" \
        --argjson chain_id "$chain_id" \
        --arg asset_contract "$asset_contract" \
        --arg from "$buyer" \
        --arg to "$pay_to" \
        --arg value "$value" \
        --arg valid_after "$valid_after" \
        --arg valid_before "$valid_before" \
        --arg nonce "$nonce" \
        '{
          types: {
            EIP712Domain: [
              {name: "name", type: "string"},
              {name: "version", type: "string"},
              {name: "chainId", type: "uint256"},
              {name: "verifyingContract", type: "address"}
            ],
            TransferWithAuthorization: [
              {name: "from", type: "address"},
              {name: "to", type: "address"},
              {name: "value", type: "uint256"},
              {name: "validAfter", type: "uint256"},
              {name: "validBefore", type: "uint256"},
              {name: "nonce", type: "bytes32"}
            ]
          },
          primaryType: "TransferWithAuthorization",
          domain: {
            name: $domain_name,
            version: $domain_version,
            chainId: $chain_id,
            verifyingContract: $asset_contract
          },
          message: {
            from: $from,
            to: $to,
            value: $value,
            validAfter: $valid_after,
            validBefore: $valid_before,
            nonce: $nonce
          }
        }'
)"
signature="$(cast wallet sign --private-key "$PAYMENT_KEY" --data "$typed_data")"
authorization="$(
    jq -cn \
        --arg from "$buyer" \
        --arg to "$pay_to" \
        --arg value "$value" \
        --arg valid_after "$valid_after" \
        --arg valid_before "$valid_before" \
        --arg nonce "$nonce" \
        --arg signature "$signature" \
        '{
          from: $from,
          to: $to,
          value: $value,
          valid_after: $valid_after,
          valid_before: $valid_before,
          nonce: $nonce,
          signature: $signature
        }'
)"

demo_expect_true \
    "$(demo_call "submit_payment_authorization(uint64,string) returns (bool)" "$execution_id" "$authorization")" \
    "submit payment authorization"
echo "Signed the payment requirements; waiting for Base Sepolia settlement."

deadline=$((SECONDS + 90))
while :; do
    encoded_state="$(demo_call "get_payment_state(uint64) returns (string)" "$execution_id" 2>/dev/null || true)"
    if [[ -n "$encoded_state" ]] && state="$(printf '%s' "$encoded_state" | jq -er . 2>/dev/null)"; then
        status="$(printf '%s' "$state" | jq -r 'keys[0]')"
        case "$status" in
            Succeeded)
                transaction="$(printf '%s' "$state" | jq -r .Succeeded.transaction)"
                echo "Settled $USDC_AMOUNT USDC in transaction $transaction"
                echo "BaseScan: $BASESCAN_TX_URL/$transaction"
                exit 0
                ;;
            Failed)
                reason="$(printf '%s' "$state" | jq -r .Failed.reason)"
                demo_die "Payment failed: $reason"
                ;;
        esac
    fi
    kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while settling the payment."
    ((SECONDS < deadline)) || demo_die "Payment did not finish after 90 seconds."
    sleep 1
done
