# Roadmap 03: Dynamic Client Registration (RFC 7591)

Enables tools like Claude Code, Cursor, and LibreChat to register themselves as OAuth clients at runtime. Nimbus provides `com.nimbusds.oauth2.sdk.client.ClientMetadata` and related classes but we only need to handle the server-side endpoint logic.

## Phase 1: Registration endpoint — core handler ✅

Create `oidc-provider.registration` namespace with a `handle-registration-request` function.

Accepts a parsed request body (map) with standard RFC 7591 fields:
- `redirect_uris` (required)
- `grant_types` (optional, defaults to `["authorization_code"]`)
- `response_types` (optional, defaults to `["code"]`)
- `client_name` (optional)
- `token_endpoint_auth_method` (optional, defaults to `"none"` for public clients)
- `scope` (optional)

Processing:
- Validate the metadata against a Malli schema
- Generate a `client_id` (UUID)
- Generate a `client_secret` only if `token_endpoint_auth_method` is not `"none"`
- Generate a `registration_access_token` for later management
- Store via `ClientStore/register-client`
- Return the full client information response per RFC 7591 Section 3.2

## Phase 2: Registration metadata validation

Add validation rules beyond schema conformance:
- `redirect_uris` must be valid absolute URIs
- `redirect_uris` must use HTTPS (or `http://localhost` for development)
- `grant_types` and `response_types` must be consistent (e.g., `authorization_code` requires `code`)
- `token_endpoint_auth_method: "none"` should require PKCE (after Roadmap 02)
- Return `invalid_client_metadata` error responses per RFC 7591 Section 3.2.2

## Phase 3: Client read endpoint (RFC 7592)

Add `handle-client-read` to the registration namespace.

- Accept `client_id` and `registration_access_token`
- Validate the token matches what was issued at registration
- Return current client configuration

This requires extending `ClientStore` protocol with `get-client-with-registration-token` or storing the registration token alongside the client.

## Phase 4: Extend ClientStore protocol

Update `protocol.clj`:
- Add `registration_access_token` and `registration_client_uri` to `ClientConfig` schema
- Add `client_name`, `client_uri`, `logo_uri`, `contacts` optional metadata fields
- Consider whether `ClientStore` needs an `update-client` method for RFC 7592 PUT

## Phase 5: Discovery document updates

Add registration endpoint to discovery metadata:
- `registration_endpoint` — the URL for dynamic registration
- Ensure `token_endpoint_auth_methods_supported` includes `"none"` for public clients

## Phase 6: Ring handler

Create a Ring handler (or handler factory) in `oidc-provider.ring` that wires the registration endpoint as a proper HTTP endpoint:
- POST to `/register` — calls `handle-registration-request`
- GET to `/register/:client_id` — calls `handle-client-read`
- Content-type negotiation, error formatting as JSON
- Optional: initial access token requirement for gated registration
