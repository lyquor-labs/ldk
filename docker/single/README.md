# Single-Node Docker Deployment

This directory contains the single-node Lyquor Docker Compose setup with:
- 1 Lyquor node (`node`)
- 1 bootstrap helper service (`setup-devnet`) that deploys bartender once (idempotent)

For the 4-node topology, see `docker/multi/`.

## Prerequisites

- Docker Engine
- Docker Compose v2
- Network access to pull images from GHCR

## Start The Stack

From the repository root:

```bash
docker compose -f docker/single/docker-compose.yaml up -d
```

Watch bootstrap logs:

```bash
docker compose -f docker/single/docker-compose.yaml logs -f setup-devnet
```

Check service status:

```bash
docker compose -f docker/single/docker-compose.yaml ps
```

## Endpoints

- Node API: `http://localhost:10087/api`
- Node WebSocket: `ws://localhost:10087/ws`

## Quick Health Checks

Check node info:

```bash
curl --data '{}' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/lyquor.node.v1.NodeService/GetNodeInfo
```

Check deployed Lyquid info:

```bash
curl --data '{}' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/lyquor.lyquid.v1.LyquidService/GetLyquidInfo
```

## Opt In To Availability Admission

The single-node kit stays at epoch 0 by default. To exercise the full admission path with a 1-of-1 committee, set the bootstrap flag when starting the stack:

```bash
LYQUOR_ACTIVATE_AVAILABILITY=true docker compose -f docker/single/docker-compose.yaml up -d
```

Then inspect the gate with:

```bash
docker compose -f docker/single/docker-compose.yaml run --rm setup-devnet \
  /usr/local/bin/shaker availability status --endpoint ws://node:10087/ws
```

## Stop / Reset

Stop containers, keep volume:

```bash
docker compose -f docker/single/docker-compose.yaml down
```

Stop and remove persisted node state:

```bash
docker compose -f docker/single/docker-compose.yaml down -v
```

## Common Operations

Re-run bootstrap job only:

```bash
docker compose -f docker/single/docker-compose.yaml up setup-devnet
```

Follow node logs:

```bash
docker compose -f docker/single/docker-compose.yaml logs -f node
```
