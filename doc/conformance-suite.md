# Conformance Suite Testing

Validate your OIDC provider against the [OpenID Foundation Conformance Suite](https://www.certification.openid.net/) using a local Docker-based setup and automated test runner.

## Overview

The conformance suite integration provides:

- A **dev server** (`oidc-provider.dev-server`) that composes all library handlers into a running OIDC provider with auto-approved authorization (no login UI)
- A **test runner** (`oidc-provider.conformance`) that drives the conformance suite's REST API and uses Playwright for headless browser automation
- **Docker Compose** configuration to run the conformance suite locally
- **Skip and expected-failure lists** to track known gaps without blocking CI

## Prerequisites

- Docker and Docker Compose
- Java 17+
- Clojure CLI (`clojure`)

## Quick Start

### 1. Set up the conformance suite

```bash
./conformance/setup.sh
```

This clones the OpenID Foundation Conformance Suite (pinned to `release-v5.1.39`), builds the JAR via Maven in Docker (~5 minutes on first run), and starts the services. The suite UI will be available at `https://localhost.emobix.co.uk:8443/` once the script completes.

### 2. Start the dev server

```bash
BASE_URL=http://host.docker.internal:9090 clojure -M:dev
```

The `BASE_URL` variable tells the provider to advertise `host.docker.internal` in its discovery metadata so the conformance suite (running in Docker) can reach it. The server listens on `http://localhost:9090`.

Two test clients are pre-registered on startup:

| Client ID | Client Secret | Auth Method |
|-----------|---------------|-------------|
| `test-client` | `test-secret` | `client_secret_basic` |
| `test-client-2` | `test-secret-2` | `client_secret_basic` |

### 3. Run conformance tests

```bash
clojure -M:conformance
```

The runner creates a Basic OP test plan, executes each module (automating browser redirects via Playwright), and prints a summary:

```
=== Conformance Test Results ===
Total: 20  Passed: 12  Warning: 1  Review: 0  Failed: 2  Skipped: 5

  PASSED   oidcc-server
  PASSED   oidcc-id-token-typ
  SKIPPED  oidcc-prompt-login
  FAILED   oidcc-codereuse (expected)
  ...
```

The exit code is 0 when all failures are expected, non-zero otherwise.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | Dev server listen port |
| `BASE_URL` | `http://localhost:<PORT>` | Issuer URL advertised in discovery metadata |
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443` | Conformance suite base URL |

### Test Plan Configuration

The test plan configuration lives at `conformance/basic-op-config.json`. It uses `host.docker.internal` to reach the dev server from inside Docker. On macOS and Windows this works out of the box; on Linux, the `docker-compose.yml` includes `extra_hosts` to map it.

### Skip and Expected-Failure Lists

Two JSON files in `conformance/` control which tests are skipped or allowed to fail:

- **`expected-skips.json`** — Tests that are not run (e.g., they time out waiting for unimplemented protocol features). Each entry maps a test name to the roadmap phase or task that would fix it.
- **`expected-failures.json`** — Tests that run but whose failures don't count against the pass/fail result. Same mapping format.

To promote a test from "expected failure" to "must pass", remove its entry from the JSON file.

## Manual Testing via Web UI

You can also run tests interactively through the conformance suite's web UI at `https://localhost.emobix.co.uk:8443/`:

1. Click "Create a new test plan"
2. Select "OpenID Connect Core: Basic Certification Profile Authorization server test"
3. Set Server metadata to "discovery" and Client registration to "static_client"
4. Paste the contents of `conformance/basic-op-config.json` as the configuration
5. Click "Create Test Plan" and run individual tests

## How It Works

### Dev Server

The dev server (`dev/oidc_provider/dev_server.clj`) wires together all library endpoints into a single Ring application:

- `GET /.well-known/openid-configuration` — OIDC discovery metadata
- `GET /jwks` — JSON Web Key Set
- `GET /authorize` — Authorization endpoint (auto-approves for a hardcoded `test-user`)
- `POST /token` — Token endpoint (authorization code and refresh token grants)
- `GET|POST /userinfo` — UserInfo endpoint (returns claims filtered by access token scope)
- `POST /register`, `GET /register/:client-id` — Dynamic client registration
- `POST /revoke` — Token revocation

Authorization requests are automatically approved without user interaction — the endpoint validates the request, then immediately issues an authorization code for the test user and redirects back.

The `TestClaimsProvider` returns claims filtered by scope:
- `openid` — `sub` only
- `profile` — `name`, `given_name`, `family_name`, `preferred_username`
- `email` — `email`, `email_verified`

### Test Runner

The test runner (`dev/oidc_provider/conformance.clj`) automates the conformance suite's REST API:

1. Creates a Basic OP test plan with the provider's discovery URL and client credentials
2. For each test module: creates the test, starts it, and polls for status
3. When a test enters `WAITING` state (expecting browser interaction), the runner extracts the authorization redirect URL from the test logs and navigates a headless Chromium browser (via Playwright) to complete the flow
4. Collects results and prints a summary, distinguishing expected failures from unexpected ones

## Cleanup

```bash
docker compose down -v
```

This stops all conformance suite containers and removes the MongoDB volume.

## Limitations

The following conformance tests are currently skipped or expected to fail due to unimplemented features:

**Skipped** (would time out):
- `oidcc-response-type-missing` — Missing authorization error code standardization
- `oidcc-prompt-login` — `prompt=login` not yet enforced
- `oidcc-max-age-1` — `max_age` parameter not yet enforced
- `oidcc-ensure-registered-redirect-uri` — Missing authorization error code standardization
- `oidcc-ensure-request-object-with-redirect-uri` — Request objects not yet rejected

**Expected failures** (run but allowed to fail):
- `oidcc-prompt-none-not-logged-in` — `prompt=none` not yet enforced
- `oidcc-max-age-10000` — `max_age` parameter not yet enforced
- `oidcc-server-client-secret-post` — `client_secret_post` configuration issues
- `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` — Request object handling
