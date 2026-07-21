# Price Feed Demo

`price-feed` is a four-node oracle Lyquid that fetches BTC, ETH, SOL, and AVAX
prices from Binance and Coinbase and finalizes the median candidates as network
state.

Install the public LDK release so `lyquor` and `shaker` are on `PATH`, or set
`LYQUOR_BIN_DIR` to the directory that contains them. Foundry (`cast` and
`anvil`) must also be available.

From the public LDK repository root, run:

```bash
lyquid-examples/price-feed/scripts/run.sh
```

The script starts the bundled native four-node `scripts/localnet.sh`, builds and
deploys Price Feed with `shaker`, configures two Binance and two Coinbase
reporters, and prints the first finalized market update. It then reports every
five seconds and streams the Lyquid console until Ctrl-C stops the demo and
localnet. The script exits instead of starting recurring reports if a live source
failure leaves any asset in the first finalized update at zero.

The script sources the shared `lyquid-examples/scripts/lib/demo.sh` helper for
localnet lifecycle, deployment, generic contract calls, and cleanup.
