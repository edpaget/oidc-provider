# OIDC Provider

[![CI](https://github.com/edpaget/oidc-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/edpaget/oidc-provider/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/edpaget/25d1d04ed600f8ba8b2191866be2cc63/raw/coverage-badge.json)
[![Clojars](https://img.shields.io/clojars/v/net.carcdr/oidc-provider.svg)](https://clojars.org/net.carcdr/oidc-provider)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![cljdoc](https://cljdoc.org/badge/net.carcdr/oidc-provider)](https://cljdoc.org/d/net.carcdr/oidc-provider)

A flexible, protocol-based OpenID Connect Provider implementation for the JVM using Clojure.

## Features

- **Protocol-based architecture** — extend claims and storage via protocols
- **Nimbus OAuth SDK foundation** — built on the battle-tested OAuth2/OIDC library
- **OAuth2 and OIDC** — can run as a plain OAuth2 server (no signing key / `jwks-uri`) or as a full OpenID Connect provider
- **Grant types** — authorization code, refresh token, and client credentials
- **PKCE** (RFC 7636), **resource indicators** (RFC 8707), and **prompt / max_age** handling (OIDC Core §3.1.2)
- **Dynamic client registration** (RFC 7591) and **client configuration management** (RFC 7592): create, read, update, delete
- **UserInfo endpoint** (OIDC Core §5.3) with Bearer token authentication
- **Token revocation** (RFC 7009) with `token_type_hint` lookup
- **Discovery** (OIDC Discovery 1.0), **JWKS**, and **protected resource metadata** (RFC 9728)
- **Key rotation** — multiple signing keys with a selectable active key
- **Hashed storage at rest** — SHA-256 for tokens / codes, PBKDF2 for client secrets and registration access tokens
- **Client ID metadata documents** (draft-ietf-oauth-client-id-metadata-document) with SSRF protection
- **In-memory stores** — development-ready stores for clients, codes, and tokens
- **Ring response helpers** — `token-response`, `registration-response`, `revocation-response`, `userinfo-response`

## Installation

Add to your `deps.edn`:

```clojure
{:deps {net.carcdr/oidc-provider {:mvn/version "0.7.1"}}}
```

Or for Leiningen:

```clojure
[net.carcdr/oidc-provider "0.7.1"]
```

## Serialization boundary

This library does **not** perform JSON serialization. Public functions accept and return plain Clojure data, and Ring response helpers (`token-response`, `registration-response`, `revocation-response`, `userinfo-response`) return Ring maps whose `:body` values are Clojure maps, not JSON strings.

Integrators are responsible for wiring middleware at the edges:

- **Responses**: `ring.middleware.json/wrap-json-response` (or equivalent) to serialize `:body` maps to JSON
- **JSON request bodies**: `ring.middleware.json/wrap-json-body` so `registration-response` receives a pre-parsed keyword map
- **Form params**: `ring.middleware.params/wrap-params` + `ring.middleware.keyword-params/wrap-keyword-params` for the token and revocation endpoints

## Quick Start

```clojure
(require '[oidc-provider.core :as provider]
         '[oidc-provider.protocol :as proto]
         '[oidc-provider.util :as util])

;; Implement a claims provider. `scope` is a vector of scope strings.
(defrecord SimpleClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    (cond-> {:sub user-id}
      (some #{"profile"} scope) (assoc :name "Test User")
      (some #{"email"} scope)   (assoc :email "user@example.com"
                                       :email_verified true))))

;; Create a provider
(def my-provider
  (provider/create-provider
   {:issuer                 "https://idp.example.com"
    :authorization-endpoint "https://idp.example.com/authorize"
    :token-endpoint         "https://idp.example.com/token"
    :jwks-uri               "https://idp.example.com/jwks"
    :userinfo-endpoint      "https://idp.example.com/userinfo"
    :claims-provider        (->SimpleClaimsProvider)}))

;; Register a client. Secrets are stored hashed — use `util/hash-client-secret`.
(provider/register-client
 my-provider
 {:client-id                  "my-app"
  :client-type                "confidential"
  :client-secret-hash         (util/hash-client-secret "secret123")
  :redirect-uris              ["https://app.example.com/callback"]
  :grant-types                ["authorization_code" "refresh_token"]
  :response-types             ["code"]
  :scopes                     ["openid" "profile" "email" "offline_access"]
  :token-endpoint-auth-method "client_secret_basic"})

;; Discovery + JWKS
(provider/discovery-metadata my-provider)
(provider/jwks my-provider)
```

## Authorization Flow

Authentication is the responsibility of your host application. The provider handles everything after the user has been authenticated.

```clojure
;; 1. Parse and validate the authorization request. `params` is the keyword map
;;    produced by Ring's wrap-params + wrap-keyword-params middleware.
(def auth-req
  (provider/parse-authorization-request
   my-provider
   {:response_type "code"
    :client_id     "my-app"
    :redirect_uri  "https://app.example.com/callback"
    :scope         "openid profile"
    :state         "xyz"}))

;; 2. Authenticate the user (your application logic). This library does not
;;    handle authentication — use whatever fits (session, SSO, form login, …).
(def user-id   "user-123")
(def auth-time (quot (System/currentTimeMillis) 1000))  ;; epoch seconds

;; 3. After consent, build the redirect URL back to the client.
;;    `auth-time` flows through to the `auth_time` claim in the ID token.
(provider/authorize my-provider auth-req user-id auth-time)
;; => "https://app.example.com/callback?code=..."

;; 4. Exchange the code for tokens.
(provider/token-request
 my-provider
 {:grant_type   "authorization_code"
  :code         "authorization-code-from-callback"
  :client_id    "my-app"
  :client_secret "secret123"
  :redirect_uri "https://app.example.com/callback"}
 nil) ;; or the raw "Authorization: Basic …" header value
;; => {:access_token "…" :id_token "…" :refresh_token "…" …}
```

A refresh token is only issued when the client has `refresh_token` in `:grant-types` **and** the request included the `offline_access` scope (OIDC Core §11).

### `prompt` and `max_age`

`parse-authorization-request` validates and parses `prompt` and `max_age` per OIDC Core §3.1.2.1. The validated request exposes `:prompt-values` (a keyword set, e.g. `#{:login}`) and `:max-age` (an integer). Helpers in `oidc-provider.authorization` let host applications enforce the semantics:

- `validate-prompt-none` — returns a `login_required` error redirect when `prompt=none` is requested but the user is unauthenticated
- `validate-max-age` — returns true when the user's `auth_time` is within the requested window

## Ring Integration

Each endpoint has a Ring response helper that returns a Ring map with a Clojure data `:body`. Wire your router and JSON middleware around them.

```clojure
(require '[ring.middleware.json :as rj]
         '[ring.middleware.params :refer [wrap-params]]
         '[ring.middleware.keyword-params :refer [wrap-keyword-params]])

(defn handler [provider]
  (fn [{:keys [uri request-method] :as request}]
    (cond
      (and (= uri "/token")    (= request-method :post))
      (provider/token-response provider request)

      (= uri "/userinfo")
      (provider/userinfo-response provider request)

      (or (= uri "/register") (clojure.string/starts-with? uri "/register/"))
      (provider/registration-response provider request)

      (and (= uri "/revoke")   (= request-method :post))
      (provider/revocation-response provider request)

      (and (= uri "/.well-known/openid-configuration") (= request-method :get))
      {:status 200 :body (provider/discovery-metadata provider)}

      (and (= uri "/jwks") (= request-method :get))
      {:status 200 :body (provider/jwks provider)}

      :else {:status 404 :body {:error "not_found"}})))

(def app
  (-> (handler my-provider)
      rj/wrap-json-response
      rj/wrap-json-body
      wrap-keyword-params
      wrap-params))
```

Authorization-endpoint errors can be rendered with `authorization-error-response`: it dispatches on the `oidc-provider.error` hierarchy, returning a 400 page for non-redirectable failures (unknown `client_id`, invalid `redirect_uri`) and a 302 error redirect otherwise.

## Protocols

### ClaimsProvider

Provides user claims for ID tokens and the UserInfo endpoint based on the authenticated user and requested scopes:

```clojure
(defprotocol ClaimsProvider
  (get-claims [this user-id scope]))
```

Registered JWT claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `azp`, `at_hash`) are protected — returning them from `get-claims` does not overwrite provider-generated values.

### Storage Protocols

Storage is pluggable. In-memory defaults are provided for development.

```clojure
(defprotocol ClientStore
  (get-client        [this client-id])
  (register-client   [this client-config])
  (update-client     [this client-id updated-config])
  (delete-client     [this client-id]))

(defprotocol AuthorizationCodeStore
  (save-authorization-code    [this code user-id client-id redirect-uri scope
                               nonce expiry code-challenge code-challenge-method
                               resource auth-time])
  (get-authorization-code     [this code])
  (delete-authorization-code  [this code])
  (consume-authorization-code [this code])               ;; atomic get+delete
  (mark-code-exchanged        [this code access-token refresh-token])
  (get-code-tokens            [this code]))              ;; for replay detection

(defprotocol TokenStore
  (save-access-token  [this token user-id client-id scope expiry resource])
  (get-access-token   [this token])
  (save-refresh-token [this token user-id client-id scope expiry resource])
  (get-refresh-token  [this token])
  (revoke-token       [this token]))
```

The provider wraps whatever code and token stores you supply with `HashingAuthorizationCodeStore` / `HashingTokenStore`, so tokens and codes reach your implementation as SHA-256 hashes. Client secrets and registration access tokens are PBKDF2-hashed via `oidc-provider.util/hash-client-secret`.

Replaying a previously consumed authorization code revokes the access and refresh tokens that were issued for it, per RFC 6749 §10.5.

## Configuration

Provider configuration options for `create-provider`:

```clojure
{:issuer                          "https://idp.example.com"   ;; Required
 :authorization-endpoint          "…/authorize"               ;; Required
 :token-endpoint                  "…/token"                   ;; Required

 ;; OIDC — omit all three to run as a plain OAuth2 server
 :jwks-uri                        "…/jwks"
 :signing-key                     rsa-key                     ;; single RSAKey
 :signing-keys                    [rsa-key-1 rsa-key-2]       ;; for rotation
 :active-signing-key-id           "key-id-for-new-tokens"

 ;; Optional endpoint advertisements (also surfaced in discovery)
 :userinfo-endpoint               "…/userinfo"
 :registration-endpoint           "…/register"
 :revocation-endpoint             "…/revoke"

 ;; TTLs (seconds)
 :access-token-ttl-seconds        3600       ;; default 3600
 :id-token-ttl-seconds            3600       ;; default 3600
 :authorization-code-ttl-seconds  600        ;; default 600
 :refresh-token-ttl-seconds       nil        ;; no expiry unless set
 :rotate-refresh-tokens           true       ;; default true

 ;; Server policy
 :grant-types-supported           ["authorization_code" "refresh_token"]
 :allow-http-issuer               false      ;; true for local dev
 :clock                           (java.time.Clock/systemUTC)

 ;; Pluggable implementations
 :claims-provider                 claims-provider
 :client-store                    client-store
 :code-store                      code-store
 :token-store                     token-store}
```

The issuer URL is validated per RFC 8414 §2: HTTPS with no query or fragment. Set `:allow-http-issuer true` to permit HTTP issuers during local development. If no signing keys or `:jwks-uri` are provided, the provider runs as a plain OAuth2 server and omits OIDC features.

## Grant Types

### Authorization Code

```clojure
(provider/token-request
 my-provider
 {:grant_type    "authorization_code"
  :code          "..."
  :client_id     "my-app"
  :client_secret "secret123"
  :redirect_uri  "https://app.example.com/callback"}
 nil)
```

PKCE is enforced for public clients: include `code_challenge` / `code_challenge_method` on the authorization request and `code_verifier` on the exchange.

### Refresh Token

```clojure
(provider/token-request
 my-provider
 {:grant_type    "refresh_token"
  :refresh_token "..."
  :client_id     "my-app"
  :client_secret "secret123"}
 nil)
```

By default the refresh token is rotated on each grant (`:rotate-refresh-tokens true`).

### Client Credentials

```clojure
(provider/token-request
 my-provider
 {:grant_type    "client_credentials"
  :client_id     "my-app"
  :client_secret "secret123"
  :scope         "api:read api:write"}
 nil)
```

Only confidential clients may use `client_credentials` (RFC 6749 §4.4).

## Dynamic Client Registration (RFC 7591 / 7592)

`dynamic-register-client` accepts a registration request map in snake_case wire format, validates it, generates credentials, and returns the registration response:

```clojure
(provider/dynamic-register-client
 my-provider
 {:redirect_uris              ["https://app.example.com/callback"]
  :grant_types                ["authorization_code"]
  :response_types             ["code"]
  :client_name                "My App"
  :token_endpoint_auth_method "client_secret_basic"})
;; => {:client_id "…" :client_secret "…" :client_id_issued_at …
;;     :client_secret_expires_at 0 :registration_client_uri "…" …}
```

When a `:registration-endpoint` is configured, responses include `registration_client_uri` and a `registration_access_token` the client can use with `dynamic-read-client`, `dynamic-update-client`, and `dynamic-delete-client` for subsequent management. `registration-response` dispatches POST / GET / PUT / DELETE on those resources.

## Token Revocation (RFC 7009)

```clojure
(provider/revocation-response my-provider request)
```

The request must be `POST application/x-www-form-urlencoded` with a `token` parameter and client authentication. `token_type_hint` (`access_token` or `refresh_token`) optimizes lookup. Token ownership is verified before revocation.

## UserInfo (OIDC Core §5.3)

```clojure
(provider/userinfo-response my-provider request)
```

Accepts `GET` or `POST` with `Authorization: Bearer <access_token>`. The provider validates the token, filters claims by the token's scope, and returns the claims map. On failure the response includes `WWW-Authenticate: Bearer` per RFC 6750 §3.

## Testing

```bash
clojure -X:test
```

OIDC conformance suite harness:

```bash
clojure -M:conformance                  # Basic OP profile
clojure -M:conformance-comprehensive    # PKCE, dynamic registration, refresh, request objects, strict redirect URIs
```

## License

[Apache License, Version 2.0](LICENSE)
