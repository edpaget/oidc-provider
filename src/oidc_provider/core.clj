(ns oidc-provider.core
  "Core OIDC provider setup and configuration.

  Provides [[create-provider]] for initialization, domain functions like
  [[token-request]] and [[dynamic-register-client]] that return pure data,
  and Ring response functions like [[token-response]], [[registration-response]],
  [[revocation-response]], and [[userinfo-response]] that return Ring response
  maps with plain Clojure data as bodies. Use Ring middleware such as
  `wrap-json-response` to handle JSON serialization."
  (:require
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.authorization :as authz]
   [oidc-provider.discovery :as disco]
   [oidc-provider.error :as error]
   [oidc-provider.protocol :as proto]
   [oidc-provider.registration :as reg]
   [oidc-provider.revocation :as revocation]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep]
   [oidc-provider.util :as util])
  (:import
   [com.nimbusds.jose.jwk RSAKey]
   [java.time Clock]))

(set! *warn-on-reflection* true)

;; ---------------------------------------------------------------------------
;; Ring response helpers
;; ---------------------------------------------------------------------------

(defn- extract-bearer-token
  "Extracts the Bearer token from the Authorization header, or returns nil."
  [request]
  (when-let [auth (get-in request [:headers "authorization"])]
    (when (str/starts-with? auth "Bearer ")
      (subs auth 7))))

(def ^:private no-cache-headers
  {"Cache-Control" "no-store"
   "Pragma"        "no-cache"})

(def ^:private auth-failure-headers
  (assoc no-cache-headers "WWW-Authenticate" "Bearer"))

(defn- extract-client-id
  "Extracts the last non-empty path segment from the URI."
  [uri]
  (->> (str/split uri #"/")
       (remove str/blank?)
       last))

(defn- bearer-unauthorized
  "Returns a 401 response with `WWW-Authenticate: Bearer` header and optional
  error code. Per RFC 6750 §3.1 the error is omitted when no token was
  presented."
  ([]
   {:status  401
    :headers {"WWW-Authenticate" "Bearer"}})
  ([error-code]
   {:status  401
    :headers {"WWW-Authenticate" (str "Bearer error=\"" error-code "\"")}
    :body    {:error error-code}}))

(defn- method-not-allowed
  "Returns a 405 response with the allowed methods."
  [allowed]
  {:status  405
   :headers {"Allow" allowed}
   :body    {:error :method_not_allowed}})

(defn- unsupported-media-type
  "Returns a 415 response requiring `application/x-www-form-urlencoded`."
  []
  {:status  415
   :headers {"Accept" "application/x-www-form-urlencoded"}
   :body    {:error             :invalid_request
             :error_description "Content-Type must be application/x-www-form-urlencoded"}})

(defn- form-urlencoded?
  "Returns true when the request content-type starts with
  `application/x-www-form-urlencoded`."
  [request]
  (some-> (get-in request [:headers "content-type"])
          (str/starts-with? "application/x-www-form-urlencoded")))

;; ---------------------------------------------------------------------------
;; Provider setup
;; ---------------------------------------------------------------------------

(def ProviderSetup
  "Malli schema for provider setup configuration."
  [:map
   [:issuer :string]
   [:authorization-endpoint :string]
   [:token-endpoint :string]
   [:jwks-uri {:optional true} :string]
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
   [:userinfo-endpoint {:optional true} :string]
   [:registration-endpoint {:optional true} :string]
   [:revocation-endpoint {:optional true} :string]
   [:refresh-token-ttl-seconds {:optional true} pos-int?]
   [:rotate-refresh-tokens {:optional true} :boolean]
   [:allow-http-issuer {:optional true} :boolean]
   [:grant-types-supported {:optional true} [:vector :string]]
   [:clock {:optional true} [:fn (fn [c] (instance? java.time.Clock c))]]])

(defrecord Provider [config
                     provider-config
                     client-store
                     code-store
                     token-store
                     claims-provider])

(def RingRequest
  "Malli schema for an incoming Ring request map."
  [:map
   [:request-method keyword?]
   [:headers {:optional true} [:map-of :string :string]]
   [:uri {:optional true} :string]
   [:params {:optional true} :map]
   [:body {:optional true} :any]])

(def RingResponse
  "Malli schema for an outgoing Ring response map."
  [:map
   [:status pos-int?]
   [:headers {:optional true} [:map-of :string :string]]
   [:body {:optional true} :any]])

(defn create-provider
  "Creates an OIDC provider instance.

   Takes a configuration map containing required keys `:issuer` (provider issuer URL),
   `:authorization-endpoint`, and `:token-endpoint`. Optional keys include
   `:jwks-uri` (required for OIDC; omit for plain OAuth2),
   `:signing-key` (RSAKey for signing tokens, generated if `:jwks-uri` is provided),
   `:access-token-ttl-seconds` (defaults to 3600), `:id-token-ttl-seconds` (defaults to
   3600), `:authorization-code-ttl-seconds` (defaults to 600 per the RFC 6749 §4.1.2
   maximum recommendation; shorter values are recommended for production), `:client-store`,
   `:code-store`, `:token-store` (all three store implementations created in-memory if
   not provided), and `:claims-provider` (required for ID token claims).

   The issuer URL is validated per RFC 8414 §2: it must use HTTPS with no query or
   fragment component. Set `:allow-http-issuer` to `true` to permit HTTP issuers
   during local development.

   Without RFC 8707 resource indicators or a client-level `:default-resource` setting,
   access tokens have no audience binding. Configure `:default-resource` on client
   registrations to scope tokens to specific resource servers by default.

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
           grant-types-supported
           clock
           client-store
           code-store
           token-store
           claims-provider
           allow-http-issuer]             :as config}]
  {:pre [(m/validate ProviderSetup config)]}
  (util/validate-issuer issuer (boolean allow-http-issuer))
  (let [oidc?           (or signing-key signing-keys (:jwks-uri config))
        key-set         (when oidc?
                          (cond
                            signing-keys (token/normalize-to-jwk-set
                                          (com.nimbusds.jose.jwk.JWKSet.
                                           ^java.util.List (java.util.ArrayList. ^java.util.Collection signing-keys)))
                            signing-key  (token/normalize-to-jwk-set signing-key)
                            :else        (token/normalize-to-jwk-set (token/generate-rsa-key))))
        active-kid      (when key-set
                          (or active-signing-key-id
                              (.getKeyID ^RSAKey (first (.getKeys ^com.nimbusds.jose.jwk.JWKSet key-set)))))
        provider-config (cond-> {:issuer                         issuer
                                 :access-token-ttl-seconds       (or access-token-ttl-seconds 3600)
                                 :id-token-ttl-seconds           (or id-token-ttl-seconds 3600)
                                 :authorization-code-ttl-seconds (or authorization-code-ttl-seconds 600)
                                 :rotate-refresh-tokens          (if (some? rotate-refresh-tokens) rotate-refresh-tokens true)
                                 :clock                          (or clock (Clock/systemUTC))}
                          key-set                   (assoc :key-set key-set)
                          active-kid                (assoc :active-signing-key-id active-kid)
                          refresh-token-ttl-seconds (assoc :refresh-token-ttl-seconds refresh-token-ttl-seconds)
                          grant-types-supported     (assoc :grant-types-supported grant-types-supported))]
    (->Provider config
                provider-config
                (or client-store (store/create-client-store))
                (store/->HashingAuthorizationCodeStore (or code-store (store/create-authorization-code-store)))
                (store/->HashingTokenStore (or token-store (store/create-token-store)))
                claims-provider)))

(m/=> create-provider [:=> [:cat ProviderSetup] :any])

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

(m/=> discovery-metadata [:=> [:cat :any] :map])

(defn jwks
  "Returns JWKS for the provider.

   Takes a Provider instance and generates the JSON Web Key Set containing the
   provider's public signing keys. Returns the JWKS map suitable for serving at
   the JWKS endpoint."
  [provider]
  (disco/jwks-endpoint (:provider-config provider)))

(m/=> jwks [:=> [:cat :any] :map])

(defn parse-authorization-request
  "Validates an authorization request.

   Takes a Provider instance and a `params` map with keyword keys (as produced by
   Ring's `wrap-params` and `wrap-keyword-params` middleware). Validates the request
   parameters against the registered client configuration. Returns the validated
   authorization request map. Throws `ex-info` on validation errors."
  [provider params]
  (authz/parse-authorization-request params (:client-store provider)))

(m/=> parse-authorization-request [:=> [:cat :any :map] :map])

(defn authorize
  "Handles authorization approval after user authentication.

   Takes a Provider instance, a parsed authorization request, and the user ID of
   the user who approved the request. Generates an authorization code, stores it,
   and builds the redirect URL to send the user back to the client. Optionally
   accepts `auth-time` (epoch seconds) so the `auth_time` claim appears in the
   resulting ID token per OIDC Core §3.1.2.1. Returns the redirect URL string."
  ([provider request user-id]
   (authorize provider request user-id nil))
  ([provider request user-id auth-time]
   (let [response (authz/handle-authorization-approval
                   request
                   user-id
                   (:provider-config provider)
                   (:code-store provider)
                   auth-time)]
     (authz/build-redirect-url response))))

(m/=> authorize [:=> [:cat :any :map :string [:maybe :int]] :string])

(defn deny-authorization
  "Handles authorization denial.

   Takes a Provider instance, a parsed authorization request, an OAuth2 error code,
   and an error description. Builds an error response and constructs the redirect URL
   to send the user back to the client with the error information. Returns the redirect
   URL string."
  [{:keys [provider-config] :as _provider} request error-code error-description]
  (let [response (authz/handle-authorization-denial request error-code error-description provider-config)]
    (authz/build-redirect-url response)))

(m/=> deny-authorization [:=> [:cat :any :map :string :string] :string])

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

(m/=> token-request [:=> [:cat :any :map [:maybe :string]] :map])

(defn register-client
  "Registers a new OAuth2/OIDC client.

   Takes a Provider instance and a client configuration map that must conform to
   the [[oidc-provider.protocol/ClientRegistration]] schema. Throws `AssertionError`
   if the config is invalid. Stores the client in the client store and returns the
   registered client configuration including the generated client-id."
  [provider client-config]
  {:pre [(m/validate proto/ClientRegistration client-config)]}
  (proto/register-client (:client-store provider) client-config))

(m/=> register-client [:=> [:cat :any proto/ClientRegistration] :map])

(defn get-client
  "Retrieves a client configuration.

   Takes a Provider instance and a client identifier. Looks up the client
   configuration in the client store. Returns the client configuration map if found,
   or nil if the client doesn't exist."
  [provider client-id]
  (proto/get-client (:client-store provider) client-id))

(m/=> get-client [:=> [:cat :any :string] [:maybe :map]])

(defn dynamic-register-client
  "Dynamically registers a new OAuth2/OIDC client per RFC 7591.

   Takes a Provider instance and a registration request map in snake_case wire
   format. Validates the request, generates credentials, stores the client, and
   returns the registration response in snake_case wire format. Throws `ex-info`
   with `\"invalid_client_metadata\"` on validation errors."
  [provider request]
  (let [{:keys [provider-config client-store]} provider]
    (reg/handle-registration-request
     request client-store
     {:clock                 (:clock provider-config)
      :registration-endpoint (:registration-endpoint (:config provider))
      :scopes-supported      (:scopes-supported (:config provider))})))

(m/=> dynamic-register-client [:=> [:cat :any :map] :map])

(defn dynamic-read-client
  "Reads a dynamically registered client's configuration per RFC 7592.

   Takes a Provider instance, a `client-id`, and the bearer `access-token`
   presented by the caller. Returns the client configuration map if the token
   is valid. Throws `ex-info` with `\"invalid_token\"` when the client is
   unknown or the token does not match."
  [provider client-id access-token]
  (reg/handle-client-read (:client-store provider) client-id access-token))

(m/=> dynamic-read-client [:=> [:cat :any :string :string] :map])

(defn dynamic-update-client
  "Updates a dynamically registered client's metadata per RFC 7592 §2.2.

  Takes a Provider instance, a `client-id`, the bearer `access-token`, and the
  updated metadata `body` map. Returns the updated client configuration.
  Throws `ex-info` with `\"invalid_token\"` on auth failure or
  `\"invalid_client_metadata\"` on validation errors."
  [provider client-id access-token body]
  (reg/handle-client-update (:client-store provider) client-id access-token body))

(m/=> dynamic-update-client [:=> [:cat :any :string :string :map] :map])

(defn dynamic-delete-client
  "Deregisters a dynamically registered client per RFC 7592 §2.3.

  Takes a Provider instance, a `client-id`, and the bearer `access-token`.
  Returns nil on success. Throws `ex-info` with `\"invalid_token\"` on auth
  failure."
  [provider client-id access-token]
  (reg/handle-client-delete (:client-store provider) client-id access-token))

(m/=> dynamic-delete-client [:=> [:cat :any :string :string] :nil])

;; ---------------------------------------------------------------------------
;; Ring response functions
;; ---------------------------------------------------------------------------

(defn- registration-error-response
  "Converts a caught `ExceptionInfo` from the registration domain into a Ring
  response. Auth errors (per `oidc-provider.error` hierarchy) become 401,
  validation errors become 400."
  [e]
  (if (error/auth-error? (:type (ex-data e)))
    {:status 401
     :body   {:error :invalid_token}}
    {:status 400
     :body   {:error             :invalid_client_metadata
              :error_description (or (:error_description (ex-data e))
                                     "invalid_client_metadata")}}))

(defn- with-bearer-auth
  "Extracts the Bearer token from `request` and calls `(f token)`. Returns 401
  if no token is present."
  [request f]
  (if-let [token (extract-bearer-token request)]
    (f token)
    {:status 401
     :body   {:error :invalid_token}}))

(defn registration-response
  "Returns a Ring response for dynamic client registration (RFC 7591) and client
  configuration management (RFC 7592).

  Dispatches on HTTP method: POST for registration, GET for client read, PUT for
  client metadata update, and DELETE for deregistration. Takes a Provider
  instance and a Ring `request` whose `:body` has already been parsed to a
  keyword map (e.g. via `wrap-json-body` or `wrap-keyword-params`).
  To gate registration access, use application-level middleware."
  [provider request]
  (case (:request-method request)
    :post   (if-not (map? (:body request))
              {:status 400
               :body   {:error             :invalid_client_metadata
                        :error_description "Missing or malformed JSON body"}}
              (try
                {:status 201
                 :body   (dynamic-register-client provider (:body request))}
                (catch clojure.lang.ExceptionInfo e
                  (registration-error-response e))))
    :get    (with-bearer-auth request
              (fn [token]
                (try
                  (let [client-id (extract-client-id (:uri request))]
                    {:status 200
                     :body   (dynamic-read-client provider client-id token)})
                  (catch clojure.lang.ExceptionInfo e
                    (registration-error-response e)))))
    :put    (with-bearer-auth request
              (fn [token]
                (if-not (map? (:body request))
                  {:status 400
                   :body   {:error             :invalid_client_metadata
                            :error_description "Missing or malformed JSON body"}}
                  (try
                    (let [client-id (extract-client-id (:uri request))]
                      {:status 200
                       :body   (dynamic-update-client provider client-id token (:body request))})
                    (catch clojure.lang.ExceptionInfo e
                      (registration-error-response e))))))
    :delete (with-bearer-auth request
              (fn [token]
                (try
                  (let [client-id (extract-client-id (:uri request))]
                    (dynamic-delete-client provider client-id token)
                    {:status 204})
                  (catch clojure.lang.ExceptionInfo e
                    (registration-error-response e)))))
    (method-not-allowed "DELETE, GET, POST, PUT")))

(m/=> registration-response [:=> [:cat :any RingRequest] RingResponse])

(defn revocation-response
  "Returns a Ring response for RFC 7009 token revocation.

  Only accepts POST requests with `application/x-www-form-urlencoded` content
  type. Returns 200 on success, 400 for missing token, or 401 on auth failure."
  [provider request]
  (if (not= :post (:request-method request))
    (method-not-allowed "POST")
    (if-not (form-urlencoded? request)
      (unsupported-media-type)
      (try
        (let [auth-header (get-in request [:headers "authorization"])]
          (revocation/handle-revocation-request
           (:params request) auth-header
           (:client-store provider) (:token-store provider))
          {:status 200})
        (catch clojure.lang.ExceptionInfo e
          (if (error/request-error? (:type (ex-data e)))
            {:status  400
             :headers no-cache-headers
             :body    {:error             (keyword (ex-message e))
                       :error_description (:error_description (ex-data e))}}
            {:status  401
             :headers auth-failure-headers
             :body    {:error :invalid_client}}))))))

(m/=> revocation-response [:=> [:cat :any RingRequest] RingResponse])

(defn authorization-error-response
  "Returns a Ring response for an authorization endpoint error.

  Dispatches on the `:type` key in `ex-data` via [[oidc-provider.error/request-error?]].
  Non-redirectable errors (`:redirect false` — invalid `redirect_uri` or unknown
  `client_id`) return a 400 response with the error in the body. Redirectable errors
  build a 302 error redirect using the `:redirect_uri` and `:state` from ex-data."
  [provider e]
  (let [data            (ex-data e)
        provider-config (:provider-config provider)]
    (if (and (error/request-error? (:type data))
             (false? (:redirect data)))
      {:status 400
       :body   {:error             (:error data)
                :error_description (ex-message e)}}
      {:status  302
       :headers {"Location" (authz/build-redirect-url
                             (authz/handle-authorization-denial
                              {:redirect_uri (:redirect_uri data)
                               :state        (:state data)}
                              (:error data)
                              (ex-message e)
                              provider-config))}})))

(m/=> authorization-error-response [:=> [:cat :any [:fn #(instance? clojure.lang.ExceptionInfo %)]] RingResponse])

(defn token-response
  "Returns a Ring response for the OAuth2 token endpoint (RFC 6749 §3.2).

  Only accepts POST requests with `application/x-www-form-urlencoded` content
  type. Success responses include `Cache-Control: no-store` and `Pragma: no-cache`
  headers per RFC 6749 §5.1."
  [provider request]
  (if (not= :post (:request-method request))
    (method-not-allowed "POST")
    (if-not (form-urlencoded? request)
      (unsupported-media-type)
      (try
        (let [auth-header (get-in request [:headers "authorization"])
              result      (token-request provider (:params request) auth-header)]
          {:status  200
           :headers no-cache-headers
           :body    result})
        (catch clojure.lang.ExceptionInfo e
          {:status  400
           :headers no-cache-headers
           :body    (cond-> {:error (or (:error (ex-data e)) "invalid_request")}
                      (ex-message e) (assoc :error_description (ex-message e)))})))))

(m/=> token-response [:=> [:cat :any RingRequest] RingResponse])

(defn userinfo-response
  "Returns a Ring response for the OIDC UserInfo endpoint (OIDC Core §5.3).

  Accepts GET and POST requests with a Bearer token in the Authorization header.
  Looks up the access token, validates expiry, retrieves user claims filtered by
  the token's scope, and returns them as a Clojure map."
  [provider request]
  (if-not (#{:get :post} (:request-method request))
    (method-not-allowed "GET, POST")
    (let [clock      ^Clock (get-in provider [:provider-config :clock])
          token      (extract-bearer-token request)
          token-data (when token (proto/get-access-token (:token-store provider) token))
          expired?   (when token-data (> (.millis clock) (:expiry token-data)))]
      (cond
        (not token)
        (bearer-unauthorized)

        (or (not token-data) expired?)
        (bearer-unauthorized "invalid_token")

        :else
        {:status 200
         :body   (proto/get-claims (:claims-provider provider)
                                   (:user-id token-data)
                                   (:scope token-data))}))))

(m/=> userinfo-response [:=> [:cat :any RingRequest] RingResponse])
