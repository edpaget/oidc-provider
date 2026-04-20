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
# Basic OP certification plan (~30 modules)
clojure -M:conformance

# Comprehensive OIDCC plan (~50 modules, includes PKCE, dynamic registration,
# refresh tokens, request objects, redirect URI validation)
clojure -M:conformance-comprehensive
```

The basic plan runs the `oidcc-basic-certification-test-plan` with static client registration. The comprehensive plan runs `oidcc-test-plan` with dynamic client registration, exercising OAuth 2.1-relevant tests beyond the basic certification profile.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | Dev server port |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Conformance suite base URL |

### Test Plan Config

Test plan configurations are in the `conformance/` directory:

- `basic-op-config.json` — Basic OP certification plan
- `comprehensive-op-config.json` — Comprehensive OIDCC plan

Both use `host.docker.internal` to reach the dev server from inside Docker. On macOS/Windows this works out of the box; on Linux, the `docker-compose.yml` includes `extra_hosts` to map it.

Each plan has its own expected-skips and expected-failures JSON files for tracking known gaps.

## Manual Testing

You can also create and run test plans via the web UI at https://localhost.emobix.co.uk:8443/:

1. Click "Create a new test plan"
2. Select a test plan:
   - "OpenID Connect Core: Basic Certification Profile Authorization server test" for basic
   - "OpenID Connect Core: Comprehensive Authorization server test" for comprehensive
3. Set variants (Server metadata: "discovery", Client registration: "static_client" or "dynamic_client")
4. Paste the contents of the corresponding config JSON as the configuration
5. Click "Create Test Plan" and then run individual tests

## Cleanup

```bash
docker compose down -v
```
