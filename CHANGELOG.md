# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-03-17

### Changed
- Client authentication now requires hashed secrets via `:client-secret-hash`; plaintext `:client-secret` field removed from `ClientConfig` schema
- **Breaking** — `handle-registration-request` and `handle-client-read` now expect and return keyword keys (e.g., `:redirect_uris`, `:client_id`) instead of string keys. Callers passing parsed JSON must use `(json/parse-string body true)` or equivalent to produce keyword maps.
- **Breaking** — `parse-authorization-request` now accepts a pre-parsed keyword params map instead of a raw query string. Callers should use Ring's `wrap-params`/`wrap-keyword-params` middleware or equivalent to parse query parameters before passing them in. The `:resource` parameter accepts a string or vector and is normalized to a vector.

### Removed
- `initial-access-token` option from `registration-handler`; use application-level middleware to gate registration access

### Security
- Eliminated plaintext client secret storage and comparison path

## [0.2.0] - 2026-03-16

### Security
- SSRF protection: `fetch-metadata-document` blocks requests to private, loopback, and link-local addresses
- `fetch-metadata-document` now enforces body size limits during streaming read, preventing memory exhaustion from oversized responses

### Added
- RFC 7009 token revocation endpoint
- Revocation endpoint uses `token_type_hint` to optimize token lookup per RFC 7009 §2.1
- Client ID Metadata Document resolution for URL-based client identifiers (draft-ietf-oauth-client-id-metadata-document)
- `client_id_metadata_document_supported` discovery metadata field

### Fixed
- Authorization responses no longer include an empty `iss` parameter when provider config lacks an issuer
- Registration error responses surface specific descriptions for semantic validation errors while keeping schema internals hidden

### Changed
- Revocation error responses include `Cache-Control: no-store` and `Pragma: no-cache` headers per RFC 6749 §5.1

### Security
- Revocation endpoint validates `Content-Type: application/x-www-form-urlencoded` to mitigate cross-origin request forgery
- URL-decode Basic auth credentials per RFC 6749 §2.3.1 to correctly handle special characters in client_id/client_secret
- Add `iss` (issuer) parameter to authorization responses per RFC 9207 to prevent mix-up attacks
- Use constant-time comparison for PKCE code challenge verification to prevent timing attacks
- Atomically consume authorization codes to prevent replay via concurrent requests (RFC 6749 §10.5)
- Only issue refresh tokens to clients whose `grant-types` include `"refresh_token"`
- Registration access tokens hashed at rest using PBKDF2
- `validate-id-token` uses injected clock instead of `Date.` for testable time handling
- Token responses include `Cache-Control: no-store` and `Pragma: no-cache` headers per RFC 6749 §5.1
- `parse-basic-auth` returns `nil` instead of throwing NPE on malformed Base64 credentials without a colon separator
- `client-config->response` no longer includes hashed `registration_access_token` in its output
- Token revocation verifies token ownership before revoking, preventing cross-client revocation (RFC 7009)

## [0.1.2] - 2026-03-13

## [0.1.1] - 2026-03-13

## [0.1.0] - 2026-03-13

### Added
- Multiple signing key support via `:signing-keys` configuration for graceful JWKS key rotation
- Refresh token rotation on every refresh grant (configurable via `:rotate-refresh-tokens`, defaults to `true`)
- Explicit `:client-type` field (`"confidential"` / `"public"`) on client model, derived from `token_endpoint_auth_method` during registration
- Configurable refresh token TTL via `:refresh-token-ttl-seconds` provider config option
- Injectable `java.time.Clock` via `:clock` provider config option for testable time handling
- PKCE support (RFC 7636): code challenge parsing, verifier verification, discovery metadata, and public client enforcement
- Resource indicator support (RFC 8707): authorization parameter handling, token binding, and discovery metadata
- Dynamic client registration (RFC 7591/7592): metadata validation, client read endpoint, client update, Ring handler, and discovery advertisement
- Protected resource metadata endpoint (RFC 9728)
- PBKDF2 client secret hashing

### Security
- Client secrets generated during dynamic registration are now stored as PBKDF2 hashes; plaintext is returned only in the registration response

### Changed
- Token endpoint no longer accepts a raw POST body string; `resource` parameters (RFC 8707) should be passed in the params map as a string or vector, as produced by Ring's `wrap-params` middleware
- PKCE enforcement now checks `:client-type` instead of probing for `:client-secret`, fixing false-positive public detection when secrets are hashed
- Token endpoint rejects confidential clients with no stored credentials

### Fixed
- Only issue `id_token` when `openid` scope is present
- Validate grant types against client registration
- Enforce `redirect_uri` matching per RFC 6749 §4.1.3
- Use timing-safe comparison for client secrets

### Changed
- **Breaking** — `TokenStore/save-refresh-token` protocol method now takes an `expiry` parameter (milliseconds epoch or `nil`)
- **Breaking** — `ProviderConfig` now requires a `:clock` key (`java.time.Clock` instance)
- Remove authn dependency from protocol layer
