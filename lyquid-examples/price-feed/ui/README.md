# Price Feed UI

This is the editable hosted Price Feed frontend. Its Vite build writes the
final static bundle to the parent `../assets/` directory; that generated
directory is the only frontend directory included in the Lyquid image.

The UI is standalone: its shared UI dependencies resolve from immutable public
CDN tarballs in `package.json`, with their content integrity recorded in
`pnpm-lock.yaml`. No Lyquor Apps checkout, npm account, or CDN credentials are
needed to install and build it.

The browser obtains hosted identity from `GET /lyquid/info`, checks instance
status through `GET /lyquid/statusz`, and reads price data from the same-origin
Price Feed API. It does not require a manually entered RPC endpoint or contract
address. `GET /api/info` optionally exposes public display metadata.

## Local Vite debugging

Run `scripts/run.sh --dev`. It starts `shaker serve` for the deployed Lyquid
and passes its local origin to the Vite process as the temporary
`VITE_PRICE_FEED_HOSTED_ORIGIN` value. Nothing is written to `.env`.

The deployed UI has no environment configuration. It reads same-origin
`/lyquid/info` to discover the current Lyquid and its `node_base_url`, then
uses that node's `/api` RPC endpoint. Vite proxies the hosted Lyquid requests
because the local proxy is a separate browser origin.
