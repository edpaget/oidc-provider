(ns oidc-provider.core
  "Core OIDC provider setup and configuration."
  (:require
   [malli.core :as m]
   [oidc-provider.authorization :as authz]
   [oidc-provider.discovery :as disco]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep]))

(set! *warn-on-reflection* true)

(def ProviderSetup
  "Malli schema for provider setup configuration."
  [:map
   [:issuer :string]
   [:authorization-endpoint :string]
   [:token-endpoint :string]
   [:jwks-uri :string]
   [:signing-key {:optional true} [:fn (fn [k] (instance? com.nimbusds.jose.jwk.RSAKey k))]]
   [:access-token-ttl-seconds {:optional true} pos-int?]
   [:id-token-ttl-seconds {:optional true} pos-int?]
   [:authorization-code-ttl-seconds {:optional true} pos-int?]
   [:client-store {:optional true} [:fn #(satisfies? proto/ClientStore %)]]
   [:code-store {:optional true} [:fn #(satisfies? proto/AuthorizationCodeStore %)]]
   [:token-store {:optional true} [:fn #(satisfies? proto/TokenStore %)]]
   [:credential-validator {:optional true} [:fn #(satisfies? proto/CredentialValidator %)]]
   [:claims-provider {:optional true} [:fn #(satisfies? proto/ClaimsProvider %)]]])

(defrecord Provider [config
                     provider-config
                     client-store
                     code-store
                     token-store
                     credential-validator
                     claims-provider])

(defn create-provider
  "Creates an OIDC provider instance.

   Takes a configuration map containing required keys `:issuer` (provider issuer URL),
   `:authorization-endpoint`, `:token-endpoint`, and `:jwks-uri`. Optional keys include
   `:signing-key` (RSAKey for signing tokens, generated if not provided),
   `:access-token-ttl-seconds` (defaults to 3600), `:id-token-ttl-seconds` (defaults to
   3600), `:authorization-code-ttl-seconds` (defaults to 600), `:client-store`,
   `:code-store`, `:token-store` (all three store implementations created in-memory if
   not provided), `:credential-validator` (required for authentication), and
   `:claims-provider` (required for ID token claims).

   Validates the configuration and returns a Provider instance with all stores and
   settings initialized."
  [{:keys [issuer
           signing-key
           access-token-ttl-seconds
           id-token-ttl-seconds
           authorization-code-ttl-seconds
           client-store
           code-store
           token-store
           credential-validator
           claims-provider] :as config}]
  {:pre [(m/validate ProviderSetup config)]}
  (let [key             (or signing-key (token/generate-rsa-key))
        provider-config {:issuer issuer
                         :signing-key key
                         :access-token-ttl-seconds (or access-token-ttl-seconds 3600)
                         :id-token-ttl-seconds (or id-token-ttl-seconds 3600)
                         :authorization-code-ttl-seconds (or authorization-code-ttl-seconds 600)}]
    (->Provider config
                provider-config
                (or client-store (store/create-client-store))
                (or code-store (store/create-authorization-code-store))
                (or token-store (store/create-token-store))
                credential-validator
                claims-provider)))

(defn discovery-metadata
  "Returns OpenID Connect Discovery metadata for the provider.

   Takes a Provider instance and extracts the relevant configuration keys to build
   the OpenID Connect Discovery metadata document. Returns the discovery metadata map
   containing issuer, endpoints, supported features, and other OIDC configuration."
  [provider]
  (disco/openid-configuration
   (select-keys (:config provider)
                [:issuer
                 :authorization-endpoint
                 :token-endpoint
                 :jwks-uri
                 :userinfo-endpoint
                 :scopes-supported
                 :response-types-supported
                 :grant-types-supported
                 :subject-types-supported
                 :id-token-signing-alg-values-supported
                 :token-endpoint-auth-methods-supported
                 :claims-supported])))

(defn jwks
  "Returns JWKS for the provider.

   Takes a Provider instance and generates the JSON Web Key Set containing the
   provider's public signing keys. Returns the JWKS map suitable for serving at
   the JWKS endpoint."
  [provider]
  (disco/jwks-endpoint (:provider-config provider)))

(defn parse-authorization-request
  "Parses and validates an authorization request.

   Takes a Provider instance and the query string from the authorization endpoint
   request. Validates the request parameters against the registered client
   configuration. Returns the validated authorization request map. Throws ex-info
   on validation errors."
  [provider query-string]
  (authz/parse-authorization-request query-string (:client-store provider)))

(defn authorize
  "Handles authorization approval after user authentication.

   Takes a Provider instance, a parsed authorization request, and the user ID of
   the user who approved the request. Generates an authorization code, stores it,
   and builds the redirect URL to send the user back to the client. Returns the
   redirect URL string."
  [provider request user-id]
  (let [response (authz/handle-authorization-approval
                  request
                  user-id
                  (:provider-config provider)
                  (:code-store provider))]
    (authz/build-redirect-url response)))

(defn deny-authorization
  "Handles authorization denial.

   Takes a Provider instance, a parsed authorization request, an OAuth2 error code,
   and an error description. Builds an error response and constructs the redirect URL
   to send the user back to the client with the error information. Returns the redirect
   URL string."
  [_provider request error-code error-description]
  (let [response (authz/handle-authorization-denial request error-code error-description)]
    (authz/build-redirect-url response)))

(defn token-request
  "Handles token endpoint request.

   Takes a Provider instance, token request parameters from the form body, and an
   optional Authorization header value for client authentication. Validates the
   request, exchanges the authorization code for tokens, and generates access tokens
   and ID tokens. Returns the token response map containing tokens and metadata.
   Throws ex-info on validation or processing errors."
  [provider params authorization-header]
  (token-ep/handle-token-request
   params
   authorization-header
   (:provider-config provider)
   (:client-store provider)
   (:code-store provider)
   (:token-store provider)
   (:claims-provider provider)))

(defn register-client
  "Registers a new OAuth2/OIDC client.

   Takes a Provider instance and a client configuration map. Stores the client
   configuration in the client store and returns the registered client configuration
   including the generated client-id."
  [provider client-config]
  (proto/register-client (:client-store provider) client-config))

(defn get-client
  "Retrieves a client configuration.

   Takes a Provider instance and a client identifier. Looks up the client
   configuration in the client store. Returns the client configuration map if found,
   or nil if the client doesn't exist."
  [provider client-id]
  (proto/get-client (:client-store provider) client-id))
