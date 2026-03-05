# Roadmap 02: PKCE & Resource Indicators

Adds PKCE (RFC 7636) and Resource Indicators (RFC 8707) to the provider. Nimbus SDK already ships `com.nimbusds.oauth2.sdk.pkce` with `CodeVerifier`, `CodeChallenge`, and `CodeChallengeMethod` classes, so the crypto is handled for us.

## Phase 1: PKCE — Authorization request parsing

Extend `AuthorizationRequest` schema in `authorization.clj` to accept optional `code_challenge` and `code_challenge_method` parameters.

- Add `:code_challenge` and `:code_challenge_method` (optional, defaults to `"S256"`) to the schema
- Validate that `code_challenge_method` is `"S256"` (only supported method); reject `"plain"` with `invalid_request`
- Pass both values through to `handle-authorization-approval` for storage

## Phase 2: PKCE — Store and verify

Store `code_challenge` and `code_challenge_method` alongside the authorization code in `save-authorization-code`.

In `handle-authorization-code-grant` in `token_endpoint.clj`:
- Accept `code_verifier` from the token request
- If the stored code has a `code_challenge`, require `code_verifier` and verify using Nimbus:

```clojure
(import '[com.nimbusds.oauth2.sdk.pkce CodeVerifier CodeChallenge CodeChallengeMethod])

(let [verifier (CodeVerifier. code_verifier)
      computed (CodeChallenge/compute CodeChallengeMethod/S256 verifier)]
  (when (not= (str computed) code_challenge)
    (throw (ex-info "PKCE verification failed" {:error "invalid_grant"}))))
```

- If the stored code has a `code_challenge` but no `code_verifier` is provided, reject with `invalid_grant`

## Phase 3: PKCE — Discovery and public client support

- Add `"S256"` to `code_challenge_methods_supported` in the discovery document
- Allow clients with no `client_secret` (public clients) when PKCE is used
- Update `authenticate-client` to skip secret validation for public clients using PKCE

## Phase 4: Resource Indicators — Authorization request

Add optional `resource` parameter (a URI or list of URIs) to the authorization request per RFC 8707.

- Extend `AuthorizationRequest` schema with optional `:resource` (string or vector of strings)
- Validate that resource values are absolute URIs
- Store resource indicators alongside the authorization code

## Phase 5: Resource Indicators — Token binding

Bind issued tokens to the requested resource.

- Include `aud` claim in access tokens (JWT or structured) set to the resource URI(s)
- Include `aud` in ID tokens when resource indicators are present
- On refresh, the `resource` parameter may narrow but not expand the original set
- Add `resource` to `TokenResponse` when present

## Phase 6: Resource Indicators — Discovery

Add `resource_indicators_supported: true` (or the appropriate metadata field) to the discovery document.
