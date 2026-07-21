#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../scripts/lib/demo.sh
. "$EXAMPLE_DIR/../scripts/lib/demo.sh"

demo_start_localnet multi
demo_deploy "price-feed" "$EXAMPLE_DIR/Cargo.toml"
demo_wait_for_lyquid "get_node_ids() returns (string[])"

echo "Initializing the four-node price-feed oracle."
demo_initialize_oracle "price_feed" 3
demo_activate_oracle "price_feed"
demo_wait_for_committee 4

SOURCES=(binance binance coinbase coinbase)
for index in 0 1 2 3; do
    demo_expect_true \
        "$(demo_call_at "${DEMO_NODE_WS[$index]}" "set_price_source(string) returns (bool)" "${SOURCES[$index]}")" \
        "set_price_source on node $((index + 1))"
done

echo "Requesting one certified market price update."
demo_expect_true "$(demo_call "report_prices() returns (bool)")" "report_prices"

price_deadline=$((SECONDS + 60))
while :; do
    prices="$(demo_call "get_prices(uint64,uint64,bool) returns (string)" 0 1 false)"
    prices="$(printf '%s' "$prices" | jq -r .)"
    if printf '%s' "$prices" | jq -e '.results | length > 0' >/dev/null; then
        printf '%s' "$prices" | jq -e '
            [.results[0].data.BTC.price, .results[0].data.ETH.price,
             .results[0].data.SOL.price, .results[0].data.AVAX.price]
            | all(type == "number" and . > 0)
        ' >/dev/null || demo_die "The first finalized update contained a missing or zero price."
        break
    fi
    kill -0 "$DEMO_LOCALNET_PID" >/dev/null 2>&1 || demo_die "Localnet exited while waiting for the first price update."
    ((SECONDS < price_deadline)) || demo_die "The first price update was not finalized after 60 seconds."
    sleep 1
done

echo
echo "First finalized price update:"
printf '%s\n' "$prices" | jq .
echo
echo "Starting a new update every five seconds. Press Ctrl-C to stop the demo and its localnet."
demo_expect_true "$(demo_call "start_reporting(uint64) returns (bool)" 5000)" "start_reporting"

shaker console "$LYQUID_ID" --endpoint "$DEMO_PRIMARY_WS"
