# Lyquid Development Kit (LDK)

This repository contains the core components and tools needed to build and deploy Lyquids on the Lyquor network.

## Prerequisites

- Docker and Docker Compose
- Git
- GitHub CLI (for private testing setup)

### Setting up GitHub CLI

1. Install GitHub CLI:
   - macOS: `brew install gh`
   - Linux: Follow [GitHub CLI installation guide](https://github.com/cli/cli#installation)
   - Windows: `winget install GitHub.cli`

2. Authenticate with GitHub (make sure to select the `read:packages` scope for ghcr.io access):
```bash
gh auth login --scopes read:packages
```

3. Configure Git and Docker to use GitHub CLI for authentication:
```bash
gh auth setup-git
gh auth token | docker login ghcr.io -u USERNAME --password-stdin 
```

## Getting Started

Start the development environment:
```bash
docker-compose up -d
```

This will start:
- A Lyquid node
- Development tools container
- Devnet setup service

## Development

Now you can follow our [tutorial](https://docs.lyquor.dev/docs/tutorial/build-and-deploy/):
```bash
docker compose exec -e USER -it tools cargo generate --path ./lyquid-template --name hello
```

Development tools are also available in `tools` container, so you can run shaker like:
```bash
docker compose exec -it tools shaker deploy ./hello/Cargo.toml --input 0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d48656c6c6f2c20576f726c642100000000000000000000000000000000000000
```


