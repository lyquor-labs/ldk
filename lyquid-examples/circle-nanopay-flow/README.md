# Circle Nanopay Flow

`circle-nanopay-flow` is a reusable child Flow that validates, authorizes, and
settles one Circle USDC x402 payment from a local Lyquid instance. It currently
targets Base Sepolia and does not require a payment service or UPC calls.

## Flow design

```text
                    payment_authorization (input)
                               |
                               v
request ------------------> authorize ------------------> settle ------------------> (succeeded)
  |                           |                           |
  +---------------------------+---------------------------+------------------------> (failed)
```

### Steps

1. `request`: validate the application-supplied resource URL, amount, network,
   buyer, and recipient. An accepted request generates the exact EIP-3009
   requirements, including a payment nonce, and continues to `authorize`; a
   rejected request exits through `failed`.
2. `authorize`: request the `payment_authorization` input containing the signed
   EIP-3009 authorization. A valid signature with the expected signer,
   recipient, amount, validity bounds, and nonce continues to `settle`; invalid
   authorization exits through `failed`.
3. `settle`: submit the verified authorization to the x402 facilitator. Direct
   settlement exits through `succeeded` only after the configured chain RPC
   confirms a successful transaction containing the expected USDC
   `AuthorizationUsed` and `Transfer` events. After a facilitator error, the
   same step uses the authorization event to find candidate transactions and
   applies the same receipt validation before recovering through `succeeded`;
   otherwise it exits through `failed`.

The application or wallet owns the private key and provides only the signed
authorization. The Flow never stores or receives the private key. Active
Scopes are intentionally in memory and crash recovery is not supported yet.

## Use the Flow

Build the immutable payment Flow with application-owned settlement
configuration, then mount it at a step in a parent Flow:

```rust
let payment = circle_nanopay_flow::flow(PaymentConfig::base_sepolia())?;
let exits = ExitTransitions::new()
    .transition(circle_nanopay_flow::SUCCEEDED_EXIT, "payment-succeeded")?
    .transition(circle_nanopay_flow::FAILED_EXIT, "payment-failed")?;

Flow::builder("payment-app")
    // ...
    .flow("payment", Arc::new(payment), exits, TraceMode::Expanded)
    // ...
```

The parent Scope must contain `PAYMENT_STATE_FIELD`. Use `initial_state(request)`
when the payment is its only State field, or add an initialized `PaymentState`
alongside the application's other fields:

```rust
State::builder()
    .field(
        circle_nanopay_flow::PAYMENT_STATE_FIELD,
        "Payment state",
        PaymentState::Initialized { request },
    )
    .build()?
```

Advance the Scope from an instance function because settlement performs an HTTP
request. While `advance()` waits at `authorize`, obtain the input contract from
`scope.input_handle()` and offer an `Eip3009Authorization`. After completion,
read the result with `payment_state(&scope)`.

## Run the example

The runner starts a single-node localnet, deploys a temporary Lyquid containing
the regular Cargo example, signs its authorization input locally, and waits for
Base Sepolia settlement. No payment service is deployed. The minimal example
accepts one active payment at a time; applications can run separate Scopes when
they need concurrent payments. The runner reuses local `lyquor` and `shaker`
binaries built from the current revision, or builds them when needed, so it can
be run directly from the repository root:

```bash
PAYMENT_KEY="0xYOUR_PRIVATE_KEY" \
USDC_AMOUNT="0.01" \
RECIPIENT_ADDRESS="0xRECIPIENT_ADDRESS" \
./ldk/lyquid-examples/circle-nanopay-flow/scripts/run.sh
```

`USDC_AMOUNT` accepts up to six decimal places and defaults to `0.000001`.
`PAYMENT_KEY` is required; its Base Sepolia address must hold enough USDC.
`RECIPIENT_ADDRESS` defaults to
`0x70997970C51812dc3A010C7d01b50e0d17dc79C8`. On success the runner prints the
transaction hash and BaseScan URL. Facilitator errors are automatically checked
against Base Sepolia before the Flow reports failure.

Set `REBUILD_TOOLS=1` to force the runner to rebuild `lyquor` and `shaker`.

The runner requires Cargo, `cast`, `curl`, `jq`, Python 3, and Anvil. Run
`./scripts/dev-setup.sh` if they are not installed.
