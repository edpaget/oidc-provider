# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Explicit `:client-type` field (`"confidential"` / `"public"`) on client model, derived from `token_endpoint_auth_method` during registration
- Configurable refresh token TTL via `:refresh-token-ttl-seconds` provider config option
- Injectable `java.time.Clock` via `:clock` provider config option for testable time handling
- PKCE support (RFC 7636): code challenge parsing, verifier verification, discovery metadata, and public client enforcement
- Resource indicator support (RFC 8707): authorization parameter handling, token binding, and discovery metadata
- Dynamic client registration (RFC 7591/7592): metadata validation, client read endpoint, client update, Ring handler, and discovery advertisement
- Protected resource metadata endpoint (RFC 9728)
- PBKDF2 client secret hashing

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
