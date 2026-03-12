# Plan 06: Secret Generation & Handling Hardening

## Motivation

Security review identified five deficiencies in secret generation and token lifecycle management. This plan addresses them in priority order, with each step independently shippable.

## Step 1: Replace UUID-based secrets with SecureRandom + base64url

**Problem:** Client secrets, refresh tokens, and authorization codes use `UUID/randomUUID` (122 bits, predictable structure with version/variant bits). Secrets should use high-entropy random bytes.

**Changes:**
- `src/oidc_provider/util.clj` — add `generate-secure-token` function: 32 bytes from `SecureRandom`, base64url-encoded (256 bits entropy, no padding)
- `src/oidc_provider/token.clj` — change `generate-refresh-token` and `generate-authorization-code` to call `util/generate-secure-token` instead of `UUID/randomUUID`
- `src/oidc_provider/registration.clj` — change `request->client-config` to use `util/generate-secure-token` for `:client-secret` generation
- `test/oidc_provider/util_test.clj` — add tests for `generate-secure-token` (length, uniqueness, url-safe characters)
- Update existing tests if they assert on UUID format

**Notes:**
- Client IDs and key IDs remain UUIDs — they are identifiers, not secrets
- `registration-access-token` already uses `BearerAccessToken` (Nimbus), which is fine

## Step 2: Add configurable refresh token TTL

**Problem:** Refresh tokens persist indefinitely until explicitly revoked. A compromised token grants unlimited access.

**Changes:**
- `src/oidc_provider/token.clj` — add `:refresh-token-ttl-seconds` to `ProviderConfig` schema (optional, default `nil` = no expiry for backward compat)
- `src/oidc_provider/protocol.clj` — extend `save-refresh-token` signature to accept an `expiry` parameter (milliseconds epoch, or `nil`)
- `src/oidc_provider/store.clj` — update `InMemoryTokenStore` to store and check refresh token expiry
- `src/oidc_provider/token_endpoint.clj`:
  - `handle-authorization-code-grant` — compute refresh token expiry from config and pass to `save-refresh-token`
  - `handle-refresh-token-grant` — check expiry on retrieved refresh token, reject if expired
- Add/update tests for expired refresh token rejection

**Breaking change:** `save-refresh-token` protocol method gains a new `expiry` parameter. Existing `TokenStore` implementations will need updating. Document in CHANGELOG.

## Step 3: Implement refresh token rotation

**Problem:** Reusing the same refresh token on every refresh request means a leaked token is valid forever (within TTL). OAuth 2.1 recommends rotation.

**Changes:**
- `src/oidc_provider/token_endpoint.clj` — in `handle-refresh-token-grant`:
  - Generate a new refresh token
  - Revoke the old refresh token
  - Save the new refresh token with the same scope/resource
  - Include the new refresh token in the response
- `src/oidc_provider/token.clj` — add `:rotate-refresh-tokens` to `ProviderConfig` (optional, default `true`)
- Add tests: verify old token is revoked, new token is returned and usable

## Step 4: Auto-hash client secrets during registration

**Problem:** `register-client` stores plaintext secrets. The hashing infrastructure exists but isn't applied automatically. Implementors must remember to hash.

**Changes:**
- `src/oidc_provider/registration.clj` — in `request->client-config`:
  - After generating the client secret, store `{:client-secret-hash (util/hash-client-secret secret)}` instead of `{:client-secret secret}`
  - Keep the plaintext secret available only for the registration response (returned to the client once, never stored)
- `src/oidc_provider/registration.clj` — in `client-config->response`:
  - Thread the original plaintext secret through to the response separately (not from stored config)
- Adjust `handle-registration-request` to pass plaintext secret from generation to response without it touching storage
- `src/oidc_provider/protocol.clj` — remove `:client-secret` from `ClientConfig` schema? Or keep for backward compat with externally-managed stores. Keep it, but document that auto-registration now uses `:client-secret-hash`.
- Update registration tests to verify stored client has hash, not plaintext
- Update token endpoint tests that rely on plaintext stored secrets

## Step 5: Support multiple signing keys in JWKS (key rotation)

**Problem:** Single signing key means no graceful rotation — old JWTs can't be verified during transition.

**Changes:**
- `src/oidc_provider/token.clj`:
  - Change `:signing-key` in `ProviderConfig` to accept either a single `RSAKey` or a vector of `RSAKey`s
  - Add `:active-signing-key-id` config option (defaults to first key)
  - `generate-id-token` uses the active key for signing
  - `validate-id-token` tries all keys matching the `kid` header
  - `jwks` returns all public keys
- Add tests for multi-key JWKS, signing with active key, validating with any key

## Sequencing

Steps 1-4 can be done in order, each building minimally on the prior. Step 5 is independent and can be done in parallel with steps 2-4.

| Step | Depends on | Breaking? |
|------|-----------|-----------|
| 1    | none      | No        |
| 2    | none      | Yes — protocol change |
| 3    | 2         | No        |
| 4    | 1         | No (additive) |
| 5    | none      | No (backward compat) |
