# OIDC Conformance Suite Testing

Run the [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) against the dev server to validate OIDC spec compliance.

## Prerequisites

- Docker and Docker Compose
- Java 17+ and Clojure CLI

## Quick Start

### 1. Set up and start the conformance suite

```bash
./conformance/setup.sh
```

This clones the conformance suite (pinned to `release-v5.1.39`), builds the JAR via Maven in Docker (~5 minutes on first run), and starts the services with health checks. The suite will be available at https://localhost.emobix.co.uk:8443/ once the script completes.

### 2. Start the dev server

```bash
BASE_URL=http://host.docker.internal:9090 clojure -M:dev
```

The OIDC provider runs at http://localhost:9090 with two pre-registered test clients:
- `test-client` / `test-secret`
- `test-client-2` / `test-secret-2`

### 3. Run conformance tests

```bash
clojure -M:conformance
```

This creates a Basic OP test plan via the conformance suite REST API, runs all test modules, and reports results.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | Dev server port |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Conformance suite base URL |

### Test Plan Config

The test plan configuration is in `conformance/basic-op-config.json`. It uses `host.docker.internal` to reach the dev server from inside Docker. On macOS/Windows this works out of the box; on Linux, the `docker-compose.yml` includes `extra_hosts` to map it.

## Manual Testing

You can also create and run test plans via the web UI at https://localhost.emobix.co.uk:8443/:

1. Click "Create a new test plan"
2. Select "OpenID Connect Core: Basic Certification Profile Authorization server test"
3. Set Server metadata to "discovery" and Client registration to "static_client"
4. Paste the contents of `conformance/basic-op-config.json` as the configuration
5. Click "Create Test Plan" and then run individual tests

## Cleanup

```bash
docker compose down -v
```
