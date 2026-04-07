# Multi-Node Docker Deployment (4 Nodes)

This directory contains a 4-node Lyquor Docker Compose setup with:
- 1 shared `anvil` sequencer
- 4 interconnected Lyquor nodes (`node1`..`node4`)
- 1 OCI registry (`registry`)
- 1 bootstrap helper service (`setup-devnet`) that runs `shaker deploy --is-bartender`

For the single-node topology, see `docker/single/`.

## What This Stack Does

- Starts a full-mesh UPC peer network across 4 nodes.
- Uses deterministic node seeds in `node1.toml`..`node4.toml` so peer IDs are stable.
- Sets `LYQUOR_ETH_SUBMITTER_KEY` on all nodes (Anvil key0) so oracle epoch advance/finalize internal submits can be sequenced.
- Exposes each node API port on the host.
- Persists Anvil chain state in a Docker volume.
- Starts/uses a local OCI registry on host port `8000`.
- Bootstraps bartender once (idempotent check in the `setup-devnet` service command).

## Prerequisites

- Docker Engine
- Docker Compose v2
- Network access to pull images from GHCR (for `lyquor-node`, `lyquor-tools`, and bartender reference)

## Start The Stack

From the repository root:

```bash
docker compose -f docker/multi/docker-compose.yaml up -d
```

Watch bootstrap logs:

```bash
docker compose -f docker/multi/docker-compose.yaml logs -f setup-devnet
```

Check service status:

```bash
docker compose -f docker/multi/docker-compose.yaml ps
```

## Endpoints

Host-exposed endpoints:

- Registry (OCI): `http://localhost:8000`
- Node 1 API: `http://localhost:10087/api` (`ws://localhost:10087/ws`)
- Node 2 API: `http://localhost:11087/api` (`ws://localhost:11087/ws`)
- Node 3 API: `http://localhost:12087/api` (`ws://localhost:12087/ws`)
- Node 4 API: `http://localhost:13087/api` (`ws://localhost:13087/ws`)

Inside the Docker network:

- Anvil JSON-RPC: `http://anvil:8545`
- Registry is available as `http://registry:8000`
- Nodes reach each other on `nodeX:10080` for UPC

## Quick Health Checks

Check node info via node1 API:

```bash
curl --data '{}' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/lyquor.node.v1.NodeService/GetNodeInfo
```

Check that a Lyquid is deployed (after bootstrap):

```bash
curl --data '{}' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/lyquor.lyquid.v1.LyquidService/GetLyquidInfo
```

## Persistence

Anvil state is persisted via the named volume `anvil-state`, mounted at `/home/foundry`, with state file:

- `/home/foundry/anvil-state.json`

Node data is persisted in:

- `node1-data`, `node2-data`, `node3-data`, `node4-data`

Registry data is persisted in:

- `registry-data`

## Registry And Fallback Repos

Each node config includes fallback repos:

- `http://registry:8000/lyquids`
- `ghcr.io/lyquor-labs/lyquids`

Note: current `setup-devnet` service bootstraps bartender by running `shaker deploy --is-bartender --reference ghcr.io/lyquor-labs/lyquids:bartender-main-latest --endpoint ws://node1:10087/ws`, with an idempotency check to skip redeploy when already present.

## Stop / Reset

Stop containers, keep volumes:

```bash
docker compose -f docker/multi/docker-compose.yaml down
```

Stop and remove all persisted state:

```bash
docker compose -f docker/multi/docker-compose.yaml down -v
```

## Common Operations

Re-run bootstrap job only:

```bash
docker compose -f docker/multi/docker-compose.yaml up setup-devnet
```

Follow node logs:

```bash
docker compose -f docker/multi/docker-compose.yaml logs -f node1 node2 node3 node4
```

## Deploying With Shaker

When deploying with `shaker` against this multi-node setup, pass both:

- `-r`/`--reference` for the OCI registry reference
- `-e`/`--endpoint` (or `--endpoint`) for the target node WebSocket API endpoint

Example:

```bash
shaker deploy -r 'http://127.0.0.1:8000/lyquids' --endpoint 'ws://127.0.0.1:10087/ws' lyquid-examples/erc20/Cargo.toml
```
