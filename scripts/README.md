# Native Localnet Scripts

Spin up a local Lyquor network on your machine **without Docker or
docker-compose** — just the released binaries. These scripts double as the demo
behind the project's native end-to-end test, so what you run locally is what CI
runs.

For the container-based equivalents, see `docker/single/` and `docker/multi/`.

## Prerequisites

- `lyquor` and `shaker` on your `PATH` (install with `shakenup.sh`), or point
  `LYQUOR_BIN_DIR` at the directory that contains them.
- [Foundry](https://book.getfoundry.sh/) for `cast` and `anvil`. Both topologies
  need `anvil`: the single node spawns its own Anvil devnet, and `multi` shares one.
- `curl`.
- Network access to GHCR to pull the released bartender image.

## Usage

```bash
# Single node (spawns its own Anvil devnet). Default.
./localnet.sh single

# Four-node UPC mesh sharing one Anvil sequencer.
./localnet.sh multi
```

Each command brings the network up, deploys bartender from a released GHCR image,
prints the node endpoints, and stays running until you press Ctrl-C — at which
point every process is stopped and the scratch directory is removed.

### Choosing the bartender image

Bartender is **not built from source**; it is deployed straight from
`ghcr.io/lyquor-labs/lyquids`. By default the `bartender-v0.4.0` tag is used.

```bash
# Pin to the release matching this LDK checkout. `v0.4.0` is replaced with
# the release tag when this README is mirrored to a versioned LDK release.
LYQUOR_IMAGE_TAG=v0.4.0 ./localnet.sh single

# Or specify the full reference.
LYQUOR_BARTENDER_REFERENCE=ghcr.io/lyquor-labs/lyquids:bartender-v0.4.0 ./localnet.sh multi
```

## Endpoints

### `single`

| Service   | URL                              |
| --------- | -------------------------------- |
| API       | `http://127.0.0.1:10087/api`     |
| WebSocket | `ws://127.0.0.1:10087/ws`        |

### `multi`

Node *i* (1..4) exposes its API on host port `1{i-1}0087` → `10087`, `11087`,
`12087`, `13087` (WebSocket on the same port). The shared Anvil
sequencer listens on `127.0.0.1:8545`.

Peers pull deployed lyquid images from node 1's built-in OCI registry
(`http://127.0.0.1:10087/lyquids`), with GHCR as the fallback — no separate
registry container is needed.

## Deploying a lyquid

With the network up, deploy the `hello` example (built from source) in another
terminal:

```bash
# single
shaker deploy --endpoint ws://127.0.0.1:10087/ws lyquid-examples/hello/Cargo.toml

# multi: push to node 1's registry so peers can pull it, then call via any node
shaker deploy --endpoint ws://127.0.0.1:10087/ws \
  --reference http://127.0.0.1:10087/lyquids:hello lyquid-examples/hello/Cargo.toml
```

## Serving a lyquid locally

Localnet does not publish wildcard DNS for per-lyquid virtual hosts. After
deployment, use `shaker serve` to expose one Lyquid through localhost while
preserving the node's virtual-host routing:

```bash
shaker serve <LYQUID_ID> --endpoint ws://127.0.0.1:10087/ws
```

Open the printed `http://127.0.0.1:<port>/` URL to reach the Lyquid's HTTP
exports, static assets, and relative `/lyquid/*` paths.

## Environment variables

| Variable                     | Purpose                                                        |
| ---------------------------- | ------------------------------------------------------------- |
| `LYQUOR_IMAGE_TAG`           | Tag used to build the bartender reference (`v0.4.0`).     |
| `LYQUOR_BARTENDER_REFERENCE` | Full bartender OCI reference; overrides `LYQUOR_IMAGE_TAG`.    |
| `LYQUOR_BIN_DIR`             | Directory containing `lyquor`/`shaker` if not already on PATH. |
| `LYQUOR_LOG`                 | Node log level (`info`, `debug`, ...).                         |
| `LOCALNET_WORK_DIR`          | Reuse a specific scratch dir instead of a fresh temp dir.      |
