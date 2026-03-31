# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `userinfo-response` for the UserInfo endpoint (OIDC Core §5.3) with Bearer token authentication
- `token-response` for the token endpoint with RFC 6749 §5.1 compliant `Cache-Control: no-store` and `Pragma: no-cache` headers on all success and error responses
- `registration-response` for dynamic client registration (RFC 7591) and client read (RFC 7592)
- `revocation-response` for token revocation (RFC 7009)
- `oidc-provider.error` namespace with keyword hierarchy for structured error dispatch via `isa?`
- `RingRequest` and `RingResponse` malli schemas in `oidc-provider.core`
- Client config validation against `ClientRegistration` schema in `register-client` before delegating to the store
- Issuer URL validation per RFC 8414 §2 — HTTPS required, no query or fragment components
- `:allow-http-issuer` option for development use with HTTP issuers
- Server-level `grant-types-supported` enforcement in token endpoint — grant types not in the provider's allowed list are rejected with `unsupported_grant_type` error per RFC 6749 §5.2
- `unsupported_grant_type` error code in ex-data for unknown or disabled grant types

### Changed
- Default `token_endpoint_auth_method` for dynamic registration is now `client_secret_basic` per RFC 7591 §2 (was incorrectly `none`)
- `handle-registration-request` accepts an optional `opts` map with `:clock` and `:registration-endpoint`
- **Breaking:** `oidc-provider.ring` namespace deleted — all Ring response functions now live in `oidc-provider.core` (`token-response`, `registration-response`, `revocation-response`, `userinfo-response`)
- **Breaking:** Ring response `:body` values are now plain Clojure maps (keyword keys), not JSON strings — integrators must add `wrap-json-response` middleware for JSON serialization
- **Breaking:** `registration-response` expects `:body` to be a pre-parsed map (via `wrap-json-body` middleware), not a raw input stream
- **Breaking:** `dynamic-read-client` and `handle-client-read` now return the client config map directly on success and throw `ex-info` on failure, instead of returning Ring-style `{:status :body}` maps
- **Breaking:** Handler-creating functions (`registration-handler`, `revocation-handler`, `userinfo-handler`) replaced by direct response functions that take `[provider request]` and return a Ring response map
- `handle-revocation-request` now returns `:ok` on success and throws `ex-info` on failure, instead of returning Ring response maps
- Response-formatting functions (`token-error-response`, `token-success-response`, `registration-error-response`) removed from domain namespaces
- Error `ex-info` throws now include a `:type` keyword from the `oidc-provider.error` hierarchy, enabling structured dispatch via `isa?`
- Malli `m/=>` schemas added to all public functions in `oidc-provider.core`

### Fixed
- Registration response now includes `client_secret_expires_at` (value `0` for non-expiring) when a `client_secret` is issued, per RFC 7591 §3.2.1
- Registration response now includes `client_id_issued_at` with epoch seconds timestamp per RFC 7591 §3.2.1
- Registration response now includes `registration_client_uri` when registration endpoint is configured, per RFC 7592
- Discovery `grant_types_supported` now includes `client_credentials` in the default set
- Discovery response now explicitly includes `request_uri_parameter_supported`, `request_parameter_supported`, and `claims_parameter_supported` boolean flags per OIDC Discovery §3
- Revocation 401 responses now include `WWW-Authenticate: Bearer` header per RFC 6750 §3
- Redirectable authorization errors now include `:state` and `:redirect_uri` in `ex-data` per RFC 6749 §4.1.2.1

## [0.6.2] - 2026-03-24

### Added
- Signing key and `jwks-uri` are now optional — the provider can be used as a plain OAuth2 server without OpenID Connect

## [0.6.1] - 2026-03-24

## [0.6.0] - 2026-03-24

### Security
- Access tokens, refresh tokens, and authorization codes are now SHA-256 hashed before storage, preventing plaintext token exposure if the store is compromised

## [0.5.0] - 2026-03-20

### Added
- `application_type` field in client registration (`web` or `native`, defaults to `web`) per OpenID Connect Dynamic Client Registration 1.0
- Custom URI schemes (e.g., `cursor://`, `com.example.app://`) accepted as redirect URIs for `native` clients per RFC 8252 Section 7.1

### Changed
- **Breaking:** Web clients (default `application_type`) no longer accept HTTP loopback redirect URIs. Set `application_type` to `native` for loopback redirects.

## [0.4.0] - 2026-03-19

### Fixed
- Public clients can no longer use `client_credentials` grant (RFC 6749 §4.4)
- Metadata-backed clients now enforce strict HTTPS-only redirect URI validation (HTTP loopback no longer allowed)
- Malformed Basic auth no longer crashes token/revocation endpoints
- `token_endpoint_auth_method` is now enforced during client authentication, including clients without the field (defaults to `client_secret_basic` for confidential, `none` for public)
- `client_secret_post` clients now reject requests missing `client_secret` in POST body
- `client_secret_basic` clients now ignore redundant `client_secret` in POST params instead of rejecting
- `verify-client-secret` returns `false` on any exception from malformed hash input
- Redirect URI error messages truncate URIs to 200 characters in all endpoints
- Redirect URI validation now accepts IPv6 loopback (`[::1]`) for HTTP
- Unsupported `token_endpoint_auth_method` values now fail with `invalid_client` instead of silently bypassing authentication
- Metadata document clients can no longer declare `client_credentials` grant type

## [0.3.1] - 2026-03-18

### Changed
- README now references the Clojars artifact with a version badge and proper `deps.edn`/Leiningen coordinates

### Fixed
- Corrected GitHub repository URL in published JAR SCM metadata (`edpaget` instead of `edwardpaget`)

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
