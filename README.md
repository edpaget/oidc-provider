# OIDC Provider

[![CI](https://github.com/edpaget/oidc-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/edpaget/oidc-provider/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/edpaget/25d1d04ed600f8ba8b2191866be2cc63/raw/coverage-badge.json)
[![Clojars](https://img.shields.io/clojars/v/net.carcdr/oidc-provider.svg)](https://clojars.org/net.carcdr/oidc-provider)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![cljdoc](https://cljdoc.org/badge/net.carcdr/oidc-provider)](https://cljdoc.org/d/net.carcdr/oidc-provider)

A flexible, protocol-based OpenID Connect Provider implementation for the JVM using Clojure.

## Features

- **Protocol-based architecture** - Extend claims and storage via protocols
- **Nimbus OAuth SDK foundation** - Built on battle-tested OAuth2/OIDC library
- **Complete OIDC flows** - Authorization code, refresh token, and client credentials grants
- **Dynamic client registration** - RFC 7591 compliant registration endpoint
- **Discovery support** - OpenID Connect Discovery and JWKS endpoints
- **In-memory stores** - Development-ready stores for clients, codes, and tokens

## Installation

Add to your `deps.edn`:

```clojure
{:deps {net.carcdr/oidc-provider {:mvn/version "0.5.0"}}}
```

Or for Leiningen:

```clojure
[net.carcdr/oidc-provider "0.5.0"]
```

## Quick Start

```clojure
(require '[oidc-provider.core :as provider]
         '[oidc-provider.protocol :as proto])

;; Implement claims provider
(defrecord SimpleClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    {:sub user-id
     :email "user@example.com"
     :name "Test User"}))

;; Create provider
(def my-provider
  (provider/create-provider
   {:issuer "https://idp.example.com"
    :authorization-endpoint "https://idp.example.com/authorize"
    :token-endpoint "https://idp.example.com/token"
    :jwks-uri "https://idp.example.com/jwks"
    :claims-provider (->SimpleClaimsProvider)}))

;; Register a client
(provider/register-client
 my-provider
 {:client-id "my-app"
  :client-secret "secret123"
  :redirect-uris ["https://app.example.com/callback"]
  :grant-types ["authorization_code" "refresh_token"]
  :response-types ["code"]
  :scopes ["openid" "profile" "email"]})

;; Get discovery metadata
(provider/discovery-metadata my-provider)

;; Get JWKS
(provider/jwks my-provider)
```

## Authorization Flow

Authentication is the responsibility of your host application. The provider handles everything after the user has been authenticated.

```clojure
;; 1. Parse authorization request
(def auth-req
  (provider/parse-authorization-request
   my-provider
   "response_type=code&client_id=my-app&redirect_uri=https://app.example.com/callback&scope=openid+profile"))

;; 2. Authenticate user (your application logic)
;; This library does not handle authentication — use whatever mechanism
;; fits your application (session, form login, SSO, etc.) to identify the user.
(def user-id "user-123")

;; 3. Get user consent and authorize
(def redirect-url
  (provider/authorize my-provider auth-req user-id))
;; => "https://app.example.com/callback?code=..."

;; 4. Exchange code for tokens
(def token-response
  (provider/token-request
   my-provider
   {:grant_type "authorization_code"
    :code "authorization-code-from-callback"
    :client_id "my-app"
    :client_secret "secret123"
    :redirect_uri "https://app.example.com/callback"}
   nil))
;; => {:access_token "..." :id_token "..." :refresh_token "..." ...}
```

## Protocols

### ClaimsProvider

Provides user claims for ID tokens based on the authenticated user and requested scopes:

```clojure
(defprotocol ClaimsProvider
  (get-claims [this user-id scope]))

;; Example: Database-backed claims
(defrecord DbClaimsProvider [db]
  proto/ClaimsProvider
  (get-claims [_ user-id scope]
    (let [user (db/get-user @db user-id)]
      (cond-> {:sub user-id}
        (some #{"profile"} scope)
        (assoc :name (:name user)
               :given_name (:given-name user)
               :family_name (:family-name user))

        (some #{"email"} scope)
        (assoc :email (:email user)
               :email_verified (:email-verified user))))))
```

### Storage Protocols

Implement custom storage:

```clojure
;; ClientStore - manage client registrations
(defprotocol ClientStore
  (get-client [this client-id])
  (register-client [this client-config]))

;; AuthorizationCodeStore - manage authorization codes
(defprotocol AuthorizationCodeStore
  (save-authorization-code [this code user-id client-id redirect-uri scope nonce expiry])
  (get-authorization-code [this code])
  (delete-authorization-code [this code]))

;; TokenStore - manage access and refresh tokens
(defprotocol TokenStore
  (save-access-token [this token user-id client-id scope expiry])
  (get-access-token [this token])
  (save-refresh-token [this token user-id client-id scope])
  (get-refresh-token [this token])
  (revoke-token [this token]))
```

## Configuration

Provider configuration options:

```clojure
{:issuer "https://idp.example.com"                        ;; Required
 :authorization-endpoint "https://idp.example.com/authorize" ;; Required
 :token-endpoint "https://idp.example.com/token"         ;; Required
 :jwks-uri "https://idp.example.com/jwks"                ;; Required

 ;; Optional
 :signing-key rsa-key                    ;; RSAKey (generated if not provided)
 :access-token-ttl-seconds 3600          ;; Default: 3600
 :id-token-ttl-seconds 3600              ;; Default: 3600
 :authorization-code-ttl-seconds 600     ;; Default: 600

 ;; Custom implementations
 :claims-provider claims-provider         ;; ClaimsProvider instance
 :client-store client-store               ;; ClientStore instance (in-memory default)
 :code-store code-store                   ;; AuthorizationCodeStore instance (in-memory default)
 :token-store token-store}                ;; TokenStore instance (in-memory default)
```

## Grant Types

### Authorization Code Grant

```clojure
(provider/token-request
 my-provider
 {:grant_type "authorization_code"
  :code "..."
  :client_id "my-app"
  :client_secret "secret123"
  :redirect_uri "https://app.example.com/callback"}
 nil)
```

### Refresh Token Grant

```clojure
(provider/token-request
 my-provider
 {:grant_type "refresh_token"
  :refresh_token "..."
  :client_id "my-app"
  :client_secret "secret123"}
 nil)
```

### Client Credentials Grant

```clojure
(provider/token-request
 my-provider
 {:grant_type "client_credentials"
  :client_id "my-app"
  :client_secret "secret123"
  :scope "api:read api:write"}
 nil)
```

## Dynamic Client Registration

RFC 7591 compliant dynamic registration:

```clojure
(provider/dynamic-register-client
 my-provider
 {:redirect_uris ["https://app.example.com/callback"]
  :grant_types ["authorization_code"]
  :response_types ["code"]
  :client_name "My App"
  :token_endpoint_auth_method "client_secret_basic"})
;; => {:client_id "..." :client_secret "..." :redirect_uris [...] ...}
```

The registration endpoint validates metadata per RFC 7591, generates client credentials, and returns the full client configuration in wire format.

## Testing

Run tests:

```bash
clojure -X:test
```

## License

[Apache License, Version 2.0](LICENSE)
