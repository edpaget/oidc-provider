# Roadmap 05: Test Coverage

Fills gaps in the existing test suite and ensures new features from other roadmaps are well-tested. Each phase is independently committable.

## Phase 1: token.clj unit tests

Create `oidc-provider.token-test` covering:

- `generate-rsa-key` — returns valid RSA key with key ID, both arities (default and custom size)
- `generate-id-token` — produces valid signed JWT, contains expected claims (iss, sub, aud, exp, iat), respects nonce and auth_time, honors TTL, includes extra claims
- `validate-id-token` — round-trip with `generate-id-token`, rejects wrong issuer, rejects wrong audience, rejects expired tokens, rejects tampered signatures
- `generate-access-token` — returns non-empty string
- `generate-refresh-token` — returns valid UUID string
- `generate-authorization-code` — returns valid UUID string
- `jwks` — returns map with `:keys` vector, key has expected RSA fields (kty, n, e, kid)

## Phase 2: store.clj unit tests

Create `oidc-provider.store-test` covering each in-memory store:

- `InMemoryClientStore` — register and retrieve, unknown client returns nil
- `InMemoryAuthorizationCodeStore` — save/get/delete cycle, delete makes subsequent get return nil
- `InMemoryTokenStore` — save/get access tokens, save/get refresh tokens, revoke removes from both maps

## Phase 3: Token endpoint — error paths and client auth

Extend `token-endpoint-test` with:

- `authenticate-client` via Basic auth header (valid and invalid)
- `authenticate-client` via POST body params
- Wrong `client_secret` returns error
- Unknown `client_id` returns error
- Unknown `grant_type` returns error
- `handle-token-request` top-level dispatcher (not just individual handlers)
- `token-error-response` produces correct Ring response shape

## Phase 4: Authorization — edge cases

Extend `authorization-test` with:

- Missing required params (no `client_id`, no `redirect_uri`)
- Invalid `response_type` rejected
- Scope validation (requested scope not in client's registered scopes)
- Query string edge cases (URL-encoded keys, repeated params)

## Phase 5: Core facade tests

Extend `core-test` with:

- `authorize` and `deny-authorization` through the public API
- `token-request` through the public API (full flow: register client, authorize, exchange code)
- `create-provider` with custom stores
- `create-provider` with invalid config (schema rejection)

## Phase 6: Integration test — full OIDC flow

Create `oidc-provider.integration-test` that exercises the complete authorization code flow end-to-end through the public API:

1. Create provider
2. Register client
3. Parse authorization request
4. Approve authorization
5. Exchange code for tokens
6. Validate ID token
7. Refresh access token

This serves as a smoke test that all components work together correctly.
