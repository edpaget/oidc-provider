# Roadmap 05: Test Coverage (Remaining)

Phases 3-4 are covered by existing tests. Three phases remain.

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

Expand `oidc-provider.store-test` to cover:

- `InMemoryAuthorizationCodeStore` — save/get/delete cycle, delete makes subsequent get return nil
- `InMemoryTokenStore` — save/get access tokens, save/get refresh tokens, revoke removes from both maps

(Client store register/retrieve already tested.)

## Phase 6: Integration test — full OIDC flow

Create `oidc-provider.integration-test` that exercises the complete authorization code flow end-to-end through the public API:

1. Create provider
2. Register client
3. Parse authorization request
4. Approve authorization
5. Exchange code for tokens
6. Validate ID token
7. Refresh access token
