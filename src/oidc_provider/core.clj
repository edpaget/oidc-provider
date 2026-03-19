(ns oidc-provider.core
  "Core OIDC provider setup and configuration."
  (:require
   [malli.core :as m]
   [oidc-provider.authorization :as authz]
   [oidc-provider.discovery :as disco]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.ring :as ring-handlers]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep])
  (:import
   [com.nimbusds.jose.jwk RSAKey]
   [java.time Clock]))

(set! *warn-on-reflection* true)

(def ProviderSetup
  "Malli schema for provider setup configuration."
  [:map
   [:issuer :string]
   [:authorization-endpoint :string]
   [:token-endpoint :string]
   [:jwks-uri :string]
   [:signing-key {:optional true} [:fn (fn [k] (instance? com.nimbusds.jose.jwk.RSAKey k))]]
   [:signing-keys {:optional true} [:vector [:fn (fn [k] (instance? com.nimbusds.jose.jwk.RSAKey k))]]]
   [:active-signing-key-id {:optional true} :string]
   [:access-token-ttl-seconds {:optional true} pos-int?]
   [:id-token-ttl-seconds {:optional true} pos-int?]
   [:authorization-code-ttl-seconds {:optional true} pos-int?]
   [:client-store {:optional true} [:fn #(satisfies? proto/ClientStore %)]]
   [:code-store {:optional true} [:fn #(satisfies? proto/AuthorizationCodeStore %)]]
   [:token-store {:optional true} [:fn #(satisfies? proto/TokenStore %)]]
   [:claims-provider {:optional true} [:fn #(satisfies? proto/ClaimsProvider %)]]
   [:registration-endpoint {:optional true} :string]
   [:revocation-endpoint {:optional true} :string]
   [:refresh-token-ttl-seconds {:optional true} [:or pos-int? [:= :none]]]
   [:rotate-refresh-tokens {:optional true} :boolean]
   [:clock {:optional true} [:fn (fn [c] (instance? java.time.Clock c))]]])

(def ^:private default-ttl-seconds (* 30 24 60 60))

(defrecord Provider [config
                     provider-config
                     client-store
                     code-store
                     token-store
                     claims-provider])

(defn create-provider
  "Creates an OIDC provider instance.

   Takes a configuration map containing required keys `:issuer` (provider issuer URL),
   `:authorization-endpoint`, `:token-endpoint`, and `:jwks-uri`. Optional keys include
   `:signing-key` (RSAKey for signing tokens, generated if not provided),
   `:access-token-ttl-seconds` (defaults to 3600), `:id-token-ttl-seconds` (defaults to
   3600), `:authorization-code-ttl-seconds` (defaults to 600), `:client-store`,
   `:code-store`, `:token-store` (all three store implementations created in-memory if
   not provided), and `:claims-provider` (required for ID token claims).

   Validates the configuration and returns a Provider instance with all stores and
   settings initialized."
  [{:keys [issuer
           signing-key
           signing-keys
           active-signing-key-id
           access-token-ttl-seconds
           id-token-ttl-seconds
           authorization-code-ttl-seconds
           refresh-token-ttl-seconds
           rotate-refresh-tokens
           clock
           client-store
           code-store
           token-store
           claims-provider]               :as config}]
  {:pre [(m/validate ProviderSetup config)]}
  (let [key-set         (cond
                          signing-keys (token/normalize-to-jwk-set
                                        (com.nimbusds.jose.jwk.JWKSet.
                                         ^java.util.List (java.util.ArrayList. ^java.util.Collection signing-keys)))
                          signing-key  (token/normalize-to-jwk-set signing-key)
                          :else        (token/normalize-to-jwk-set (token/generate-rsa-key)))
        active-kid      (or active-signing-key-id
                            (.getKeyID ^RSAKey (first (.getKeys ^com.nimbusds.jose.jwk.JWKSet key-set))))
        provider-config (cond-> {:issuer                         issuer
                                 :key-set                        key-set
                                 :active-signing-key-id          active-kid
                                 :access-token-ttl-seconds       (or access-token-ttl-seconds 3600)
                                 :id-token-ttl-seconds           (or id-token-ttl-seconds 3600)
                                 :authorization-code-ttl-seconds (or authorization-code-ttl-seconds 600)
                                 :rotate-refresh-tokens          (if (some? rotate-refresh-tokens) rotate-refresh-tokens true)
                                 :clock                          (or clock (Clock/systemUTC))}
                          :always (assoc :refresh-token-ttl-seconds
                                         (case refresh-token-ttl-seconds
                                           nil  default-ttl-seconds
                                           :none nil
                                           refresh-token-ttl-seconds)))]
    (->Provider config
                provider-config
                (or client-store (store/create-client-store))
                (or code-store (store/create-authorization-code-store))
                (or token-store (store/create-token-store))
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
                 :claims-supported
                 :registration-endpoint
                 :revocation-endpoint
                 :client-id-metadata-document-supported])))

(defn jwks
  "Returns JWKS for the provider.

   Takes a Provider instance and generates the JSON Web Key Set containing the
   provider's public signing keys. Returns the JWKS map suitable for serving at
   the JWKS endpoint."
  [provider]
  (disco/jwks-endpoint (:provider-config provider)))

(defn parse-authorization-request
  "Validates an authorization request.

   Takes a Provider instance and a `params` map with keyword keys (as produced by
   Ring's `wrap-params` and `wrap-keyword-params` middleware). Validates the request
   parameters against the registered client configuration. Returns the validated
   authorization request map. Throws `ex-info` on validation errors."
  [provider params]
  (authz/parse-authorization-request params (:client-store provider)))

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
  [{:keys [provider-config] :as _provider} request error-code error-description]
  (let [response (authz/handle-authorization-denial request error-code error-description provider-config)]
    (authz/build-redirect-url response)))

(defn token-request
  "Handles token endpoint request.

   Takes a Provider instance, token request parameters from the form body (as
   produced by Ring's `wrap-params` / `wrap-keyword-params` middleware), and an
   optional Authorization header value for client authentication. Multi-value
   `resource` parameters (RFC 8707) should already be present in `params` —
   Ring's `wrap-params` automatically yields a vector for repeated form fields.
   Validates the request, exchanges the authorization code for tokens, and
   generates access tokens and ID tokens. Returns the token response map
   containing tokens and metadata. Throws ex-info on validation or processing
   errors."
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

(defn dynamic-register-client
  "Dynamically registers a new OAuth2/OIDC client per RFC 7591.

   Takes a Provider instance and a registration request map in snake_case wire
   format. Validates the request, generates credentials, stores the client, and
   returns the registration response in snake_case wire format. Throws `ex-info`
   with `\"invalid_client_metadata\"` on validation errors."
  [provider request]
  (reg/handle-registration-request request (:client-store provider)))

(defn dynamic-read-client
  "Reads a dynamically registered client's configuration per RFC 7592.

   Takes a Provider instance, a `client-id`, and the bearer `access-token`
   presented by the caller. Returns the client configuration if the token is
   valid, or a 401 error response otherwise."
  [provider client-id access-token]
  (reg/handle-client-read (:client-store provider) client-id access-token))

(defn registration-handler
  "Creates a Ring handler for dynamic client registration.

   Takes a Provider instance. To gate registration access, use
   application-level middleware."
  [provider]
  (ring-handlers/registration-handler (:client-store provider)))

(defn revocation-handler
  "Creates a Ring handler for RFC 7009 token revocation.

   Takes a Provider instance and returns a Ring handler that accepts POST
   requests to revoke access or refresh tokens."
  [provider]
  (ring-handlers/revocation-handler
   (:client-store provider)
   (:token-store provider)))
