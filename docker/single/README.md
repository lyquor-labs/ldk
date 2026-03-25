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

Check chain ID:

```bash
curl --data '{"id":1,"jsonrpc":"2.0","params":[],"method":"eth_chainId"}' \
  --header 'accept: application/json' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/api
```

Check deployed Lyquid info:

```bash
curl --data '{"lyquidId":""}' \
  --header 'accept: application/json' \
  --header 'content-type: application/json' \
  -s http://localhost:10087/lyquor.lyquid.v1.LyquidService/GetLyquidInfo
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
