# Price Feed

`price-feed` is a snapshot demo of the Price Feed oracle Lyquid and its hosted frontend. Four
reporters fetch BTC, ETH, SOL, and AVAX prices from Binance or Coinbase; the
oracle committee finalizes the median candidates as network state.

## Layout

- `ui/`: editable frontend source. Its framework and build process are owned by
  the frontend package.
- `assets/`: generated, ignored static output. This is the only directory
  mounted and deployed with the Lyquid.
- `src/`: Price Feed Lyquid implementation.

## Hosted frontend contract

The frontend explicitly reads these same-origin runtime endpoints:

- `GET /lyquid/info`: Lyquid ID, serving node URL, backend contract, and
  sequence backend.
- `GET /lyquid/statusz`: hosted instance and image status.

Browser routes are handled by the bundled SPA. `GET /feeds/*`, `GET /explorer/*`,
and `GET /setup/*` explicitly return `assets/index.html` so direct navigation
works on hosted nodes that have not yet rolled out static SPA fallback.

`/setup` is an unlisted operator route. It discovers the hosted node cluster
from `/lyquid/info`, derives the committee keys from Node IDs, and provides the
Price Feed lifecycle and per-node reporting controls. It is deliberately not a
general ABI workbench and is not linked from the public navigation. Its
reporting status is instance-local: starting or stopping reporting affects only
the selected node instance.

Application data belongs under `/api/*`:

- `GET /api/prices?start=<u64>&end=<u64>&use_id=<true|false>`: the current
  hosted instance's bounded price-history cache. Its response is the existing
  `{ "results": [...] }` Price Feed shape.
- `GET /api/committee`: the current oracle committee as `{ "nodeIds": [...] }`.
- `GET /api/config`: Lyquid-derived UI metadata: package version, configured
  assets and sources, plus the current committee and certification threshold.
- `GET /api/info`: optional public display metadata. It currently returns
  `{ "name": "Price Feed" }` and permits cross-origin reads with
  `Access-Control-Allow-Origin: *`.

The EVM surface also exposes `get_initializer()`, `get_price_source()`, and
`get_reporting_status()` for operator preflight and node-local state reads.

## Build and deploy

The Price Feed Cargo build script installs the locked UI dependencies and builds
`assets/` before compiling the Lyquid. This applies consistently to direct Cargo
builds and to `shaker build`, `shaker deploy`, and `shaker push`:

```bash
scripts/build.sh
shaker deploy Cargo.toml --endpoint <node-websocket-endpoint>
```

The UI is an independent pnpm project. It installs the immutable
`lyquor-shadcn@0.0.1-cdn.1` and `lyquor-theme@0.0.1-cdn.1` tarballs from public
Supabase Storage URLs recorded in `ui/package.json` and `ui/pnpm-lock.yaml`.
Run `pnpm dev` from `ui/` when iterating on the frontend. `assets/` is generated
and must not be committed.

## Local demo

With the Lyquor checkout available beside this apps repository, run:

```bash
scripts/run.sh
```

Choose the hosted UI, Vite development UI, Shaker console, or complete cleanup
from the menu. For normal shutdown, press `Ctrl-C` in the terminal that runs
the demo. The cleanup option stops recorded processes (forcing only those that
do not exit), then removes `.run/`, its logs, and the generated build artifacts.
The non-interactive equivalents are `scripts/run.sh --hosted`,
`scripts/run.sh --dev`, and `scripts/run.sh --console`. Each mode starts the
four-node demo network, deploys Price Feed, configures the committee, and waits
until continuous price reporting is started before opening its UI or console.

Use `scripts/run.sh status` to inspect the current session and
`scripts/run.sh stop` to stop it from another terminal. Add `--clean` to remove
the Price Feed-only `.run/` data, or `--force` when a recorded process does not
exit after a normal stop. After the demo is stopped,
`scripts/run.sh clean --artifacts` removes its ignored, regenerable
`lyquid_tools_target/` and `assets/` directories. It does not remove the
workspace `target/`, `ui/node_modules/`, or pnpm's shared cache.
