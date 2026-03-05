# Roadmap 01: Security Hardening

Fixes known security issues in oidc-provider before adding new features. Each phase is a single committable unit.

## Phase 1: Timing-safe client secret comparison ✅

Replace `not=` string comparison in `token_endpoint.clj` with `MessageDigest/isEqual` on byte arrays. This closes a timing side-channel that could leak client secrets.

```clojure
(import '[java.security MessageDigest])

(defn- constant-time-eq [a b]
  (MessageDigest/isEqual (.getBytes a "UTF-8") (.getBytes b "UTF-8")))
```

Update `authenticate-client` to use this instead of `not=`.

## Phase 2: Enforce redirect_uri matching per RFC 6749 Section 4.1.3 ✅

In `handle-authorization-code-grant`, the `redirect_uri` parameter is currently optional. Per spec, if `redirect_uri` was included in the authorization request, it MUST be present and identical in the token request.

- Store the `redirect_uri` used in the authorization request alongside the authorization code (already done)
- Require `redirect_uri` in the token request when the stored code has one
- Reject with `invalid_grant` if missing or mismatched

## Phase 3: Validate grant types against client registration ✅

`handle-authorization-code-grant` does not check that the client is registered for the `authorization_code` grant type. A client registered only for `client_credentials` can currently exchange authorization codes.

- Add grant type validation at the top of each grant handler
- Return `unauthorized_client` error when the grant type is not in the client's `grant-types`

## Phase 4: Enforce openid scope for ID tokens

ID tokens are currently issued regardless of whether `openid` is in the requested scope. Per OIDC Core Section 3.1.2.1, the `openid` scope is required.

- Only generate and return `id_token` when the scope includes `"openid"`
- Authorization code flow without `openid` should return access/refresh tokens but no ID token

## Phase 5: Remove unused dependencies

`buddy/buddy-sign`, `buddy/buddy-core`, and `ring/ring-core` are declared in `deps.edn` but never imported. Remove them to reduce the dependency surface.

## Phase 6: Client secret hashing guidance

Add a `hash-client-secret` utility function using `buddy-hashers` or `MessageDigest` for production use, and update `authenticate-client` to support hashed secrets via a `:client-secret-hash` field as an alternative to plaintext `:client-secret`. Document that the in-memory store with plaintext secrets is for development only.
