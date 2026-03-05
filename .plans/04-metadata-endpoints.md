# Roadmap 04: Protected Resource Metadata & Client ID Metadata

Two lightweight JSON endpoint specs that improve interoperability with modern OAuth clients.

## Phase 1: Protected Resource Metadata (RFC 9728)

A simple JSON document served at `/.well-known/oauth-protected-resource` that describes a resource server's authorization requirements. This is the resource server's counterpart to the provider's discovery document.

Create `oidc-provider.resource-metadata` namespace with:

- `ResourceServerConfig` Malli schema accepting:
  - `resource` (required URI — the resource server identifier)
  - `authorization_servers` (required — list of issuer URIs this resource trusts)
  - `scopes_supported` (optional)
  - `bearer_methods_supported` (optional, defaults to `["header"]`)
  - `resource_documentation` (optional URI)
- `resource-metadata` function that takes a config map and returns the JSON-ready document
- This is intentionally simple — it's a static document the resource server serves

## Phase 2: Client ID Metadata Documents

Newer spec where a client's `client_id` is a URL that resolves to a JSON document containing the client's metadata (redirect URIs, name, etc.). This enables verification without pre-registration.

Create `oidc-provider.client-metadata` namespace with:

- `resolve-client-metadata` function that fetches and validates a client ID URL
- Malli schema for the expected document structure (subset of RFC 7591 metadata)
- Cache layer (atom-based, TTL) to avoid repeated fetches
- Integration point: when `parse-authorization-request` encounters an unknown `client_id` that is a URL, attempt to resolve it as a metadata document
- Validate that `redirect_uris` in the metadata document match the request's `redirect_uri`

## Phase 3: Discovery document updates

- Add `protected_resource_metadata_supported: true` or relevant field to the OIDC discovery document if the provider also acts as a resource server
- Document how resource servers using this library should serve their metadata endpoint
