(ns oidc-provider.token-endpoint
  "Token endpoint implementation for OAuth2/OIDC."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token]
   [oidc-provider.util :as util])
  (:import
   [com.nimbusds.oauth2.sdk.pkce CodeChallenge CodeChallengeMethod CodeVerifier]
   [java.net URLDecoder]
   [java.util Base64]))

(set! *warn-on-reflection* true)

(def default-grant-types-supported
  "Default grant types when `:grant-types-supported` is not configured."
  ["authorization_code" "refresh_token" "client_credentials"])

(def TokenRequest
  "Malli schema for token request parameters."
  [:map
   [:grant_type :string]
   [:code {:optional true} :string]
   [:redirect_uri {:optional true} :string]
   [:refresh_token {:optional true} :string]
   [:client_id {:optional true} :string]
   [:client_secret {:optional true} :string]
   [:scope {:optional true} :string]
   [:code_verifier {:optional true} :string]
   [:resource {:optional true} [:or :string [:vector :string]]]])

(def TokenResponse
  "Malli schema for token response."
  [:map
   [:access_token :string]
   [:token_type [:enum "Bearer"]]
   [:expires_in pos-int?]
   [:id_token {:optional true} :string]
   [:refresh_token {:optional true} :string]
   [:scope {:optional true} :string]
   [:resource {:optional true} [:vector :string]]])

(defn- normalize-resource
  "Normalizes the `resource` parameter to a vector of strings.

  Ring's `wrap-params` middleware yields a single string for one value and a
  vector for repeated values. This function coerces either form into a
  consistent vector, returning `nil` when no resource is present."
  [resource]
  (cond
    (vector? resource) (not-empty resource)
    (string? resource) [resource]
    :else              nil))

(defn- has-basic-scheme?
  "Returns true when `authorization-header` begins with the Basic scheme,
  regardless of whether the remainder is valid Base64 or well-formed
  `client_id:client_secret` content."
  [authorization-header]
  (when authorization-header
    (let [[scheme] (str/split authorization-header #" " 2)]
      (boolean (and scheme (= (str/lower-case scheme) "basic"))))))

(defn parse-basic-auth
  "Parses an HTTP Basic Authorization header into client credentials.

  Decodes the Base64-encoded `client_id:client_secret` pair from the header
  value. Returns a map with `:client-id` and `:client-secret` keys, or `nil`
  when the header is absent, not a Basic scheme, or malformed."
  [authorization-header]
  (try
    (when authorization-header
      (let [[scheme encoded] (str/split authorization-header #" " 2)]
        (when (and encoded (= (str/lower-case scheme) "basic"))
          (let [decoded (String. (.decode (Base64/getDecoder) encoded))]
            (when (str/includes? decoded ":")
              (let [[client-id client-secret] (str/split decoded #":" 2)]
                {:client-id     (URLDecoder/decode ^String client-id "UTF-8")
                 :client-secret (URLDecoder/decode ^String client-secret "UTF-8")}))))))
    (catch Exception _ nil)))

(defn- resolve-auth-method
  "Determines the effective `token_endpoint_auth_method` for a client.
  Uses the explicit setting if present, otherwise defaults to `client_secret_basic`
  for confidential clients (or those with a stored secret) and `none` for public clients."
  [client]
  (or (:token-endpoint-auth-method client)
      (if (or (= (:client-type client) "confidential")
              (and (nil? (:client-type client))
                   (:client-secret-hash client)))
        "client_secret_basic"
        "none")))

(defn- validate-auth-method
  "Validates that the resolved `auth-method` is consistent with the client
  configuration and the credentials provided in `basic-auth` and `params`.
  Throws `ex-info` on any mismatch."
  [auth-method client basic-auth params client-secret has-basic-header]
  (let [client-id (:client-id client)]
    (when-not (#{"none" "client_secret_basic" "client_secret_post"} auth-method)
      (throw (ex-info "Unsupported token_endpoint_auth_method"
                      {:client-id client-id :auth-method auth-method})))
    (when (and (= auth-method "none")
               (or (= (:client-type client) "confidential")
                   (:client-secret-hash client)))
      (throw (ex-info "Confidential client must not use auth method 'none'"
                      {:client-id client-id})))
    (when (= auth-method "client_secret_basic")
      (when-not basic-auth
        (throw (ex-info "Client requires Basic authentication"
                        {:client-id client-id}))))
    (when (= auth-method "client_secret_post")
      (when has-basic-header
        (throw (ex-info "Client requires POST body authentication"
                        {:client-id client-id})))
      (when-not (:client_secret params)
        (throw (ex-info "Client requires POST body authentication with client_secret"
                        {:client-id client-id}))))
    (when (and (= auth-method "none") (or client-secret has-basic-header))
      (throw (ex-info "Public client must not provide a client_secret"
                      {:client-id client-id})))
    (when (and (#{"client_secret_basic" "client_secret_post"} auth-method)
               (not (:client-secret-hash client)))
      (throw (ex-info "Client configured for secret-based auth has no stored credentials"
                      {:client-id client-id})))
    (when (and (#{"client_secret_basic" "client_secret_post"} auth-method)
               (:client-secret-hash client))
      (when-not (util/verify-client-secret (or client-secret "") (:client-secret-hash client))
        (throw (ex-info "Invalid client credentials" {:client-id client-id}))))))

(defn authenticate-client
  "Authenticates an OAuth2 client from request parameters or Basic auth header.

  Resolves the client identity from `params` (`:client_id` / `:client_secret`)
  or the `authorization-header` (HTTP Basic), looks the client up in
  `client-store`, and verifies credentials. Returns the client config map on
  success. Throws `ex-info` on missing, unknown, or mismatched credentials."
  [params authorization-header client-store]
  (let [has-basic  (has-basic-scheme? authorization-header)
        basic-auth (parse-basic-auth authorization-header)
        client-id  (or (:client-id basic-auth) (:client_id params))]
    (when-not client-id
      (throw (ex-info "Missing client_id" {})))
    (let [client        (proto/get-client client-store client-id)
          _             (when-not client
                          (throw (ex-info "Unknown client" {:client-id client-id})))
          auth-method   (resolve-auth-method client)
          client-secret (case auth-method
                          "client_secret_basic" (:client-secret basic-auth)
                          "client_secret_post"  (:client_secret params)
                          "none"                (or (:client-secret basic-auth) (:client_secret params))
                          nil)]
      (validate-auth-method auth-method client basic-auth params client-secret has-basic)
      client)))

(defn- verify-pkce
  "Verifies the PKCE `code_verifier` against the stored `code_challenge` per RFC 7636 §4.6.

  Throws `ex-info` with `{:error \"invalid_grant\"}` when the verifier is missing,
  unexpected, or does not match the stored challenge."
  [code-data code-verifier]
  (let [stored-challenge (:code-challenge code-data)]
    (cond
      (and stored-challenge (not code-verifier))
      (throw (ex-info "Missing code_verifier for PKCE" {:error "invalid_grant"}))

      (and code-verifier (not stored-challenge))
      (throw (ex-info "Unexpected code_verifier" {:error "invalid_grant"}))

      (and stored-challenge code-verifier)
      (let [verifier (CodeVerifier. ^String code-verifier)
            method   (CodeChallengeMethod/parse (or (:code-challenge-method code-data) "S256"))
            computed (.getValue (CodeChallenge/compute method verifier))]
        (when-not (util/constant-time-eq? computed stored-challenge)
          (throw (ex-info "PKCE verification failed" {:error "invalid_grant"})))))))

(defn handle-authorization-code-grant
  "Exchanges an authorization code for tokens per RFC 6749 §4.1.3.

  Validates the client is authorized for the `authorization_code` grant, verifies
  the code against `code-store`, checks redirect URI and PKCE, then issues access,
  refresh, and (when `openid` scope is present) ID tokens via `token-store` and
  `claims-provider`. Returns a token response map."
  [{:keys [code redirect_uri code_verifier]} client provider-config code-store token-store claims-provider]
  (when-not (some #{"authorization_code"} (:grant-types client))
    (throw (ex-info "Client not authorized for authorization_code grant"
                    {:client-id (:client-id client)})))
  (when-not code
    (throw (ex-info "Missing code parameter" {})))
  (let [code-data (proto/consume-authorization-code code-store code)]
    (when-not code-data
      (throw (ex-info "Invalid or expired authorization code" {:code code})))
    (when (> (.millis ^java.time.Clock (:clock provider-config)) (:expiry code-data))
      (throw (ex-info "Authorization code expired" {:code code})))
    (when (not= (:client-id code-data) (:client-id client))
      (throw (ex-info "Client mismatch" {:expected (:client-id code-data)
                                         :actual   (:client-id client)})))
    (when (and (:redirect-uri code-data) (not redirect_uri))
      (throw (ex-info "Missing redirect_uri parameter" {:code code})))
    (when (and redirect_uri (not= (:redirect-uri code-data) redirect_uri))
      (throw (ex-info "Redirect URI mismatch" {:expected (:redirect-uri code-data)
                                               :actual   redirect_uri})))
    (verify-pkce code-data code_verifier)
    (let [user-id        (:user-id code-data)
          scope          (:scope code-data)
          resource       (:resource code-data)
          openid?        (some #{"openid"} scope)
          refresh?       (some #{"refresh_token"} (:grant-types client))
          access-token   (token/generate-access-token)
          refresh-token  (when refresh? (token/generate-refresh-token))
          ttl            (or (:access-token-ttl-seconds provider-config) 3600)
          now            (.millis ^java.time.Clock (:clock provider-config))
          expiry         (+ now (* 1000 ttl))
          refresh-ttl    (:refresh-token-ttl-seconds provider-config)
          refresh-expiry (when refresh-ttl (+ now (* 1000 refresh-ttl)))
          id-token       (when openid?
                           (let [user-claims (proto/get-claims claims-provider user-id scope)]
                             (token/generate-id-token
                              provider-config user-id (:client-id client)
                              user-claims {:nonce (:nonce code-data)})))]
      (proto/save-access-token token-store access-token user-id (:client-id client) scope expiry resource)
      (when refresh-token
        (proto/save-refresh-token token-store refresh-token user-id (:client-id client) scope refresh-expiry resource))
      (cond-> {:access_token access-token
               :token_type   "Bearer"
               :expires_in   ttl
               :scope        (str/join " " scope)}
        refresh-token (assoc :refresh_token refresh-token)
        id-token      (assoc :id_token id-token)
        resource      (assoc :resource resource)))))

(defn handle-refresh-token-grant
  "Issues a new access token from a refresh token per RFC 6749 §6.

  Validates the client is authorized for the `refresh_token` grant, verifies the
  token against `token-store`, enforces scope down-scoping and resource constraints,
  and optionally rotates the refresh token. Returns a token response map."
  [{:keys [refresh_token scope resource]} client provider-config token-store]
  (when-not (some #{"refresh_token"} (:grant-types client))
    (throw (ex-info "Client not authorized for refresh_token grant"
                    {:client-id (:client-id client)})))
  (when-not refresh_token
    (throw (ex-info "Missing refresh_token parameter" {})))
  (let [token-data (proto/get-refresh-token token-store refresh_token)]
    (when-not token-data
      (throw (ex-info "Invalid refresh token" {:refresh-token refresh_token})))
    (when-let [expiry (:expiry token-data)]
      (when (> (.millis ^java.time.Clock (:clock provider-config)) expiry)
        (throw (ex-info "Refresh token expired" {:error "invalid_grant"}))))
    (when (not= (:client-id token-data) (:client-id client))
      (throw (ex-info "Client mismatch" {:expected (:client-id token-data)
                                         :actual   (:client-id client)})))
    (let [requested-scope   (when scope (vec (str/split scope #" ")))
          token-scope       (:scope token-data)
          final-scope       (or requested-scope token-scope)
          original-resource (:resource token-data)
          final-resource    (or resource original-resource)]
      (when (and requested-scope
                 (not (every? (set token-scope) requested-scope)))
        (throw (ex-info "Requested scope exceeds original scope"
                        {:original  token-scope
                         :requested requested-scope})))
      (when (and resource original-resource
                 (not (every? (set original-resource) resource)))
        (throw (ex-info "Requested resource exceeds original grant"
                        {:error     "invalid_target"
                         :original  original-resource
                         :requested resource})))
      (let [access-token   (token/generate-access-token)
            ttl            (or (:access-token-ttl-seconds provider-config) 3600)
            now            (.millis ^java.time.Clock (:clock provider-config))
            expiry         (+ now (* 1000 ttl))
            rotate?        (:rotate-refresh-tokens provider-config)
            new-refresh    (when rotate? (token/generate-refresh-token))
            refresh-ttl    (:refresh-token-ttl-seconds provider-config)
            refresh-expiry (when refresh-ttl (+ now (* 1000 refresh-ttl)))]
        (proto/save-access-token token-store access-token (:user-id token-data)
                                 (:client-id client) final-scope expiry final-resource)
        (when rotate?
          (proto/revoke-token token-store refresh_token)
          (proto/save-refresh-token token-store new-refresh (:user-id token-data)
                                    (:client-id client) final-scope refresh-expiry final-resource))
        (cond-> {:access_token access-token
                 :token_type   "Bearer"
                 :expires_in   ttl
                 :scope        (str/join " " final-scope)}
          new-refresh    (assoc :refresh_token new-refresh)
          final-resource (assoc :resource final-resource))))))

(defn handle-client-credentials-grant
  "Issues an access token for the client itself per RFC 6749 §4.4.

  Validates the client is authorized for the `client_credentials` grant and is
  confidential, resolves the requested scope against the client's allowed scopes,
  and stores the token via `token-store`. Returns a token response map."
  [{:keys [scope resource]} client provider-config token-store]
  (when-not (some #{"client_credentials"} (:grant-types client))
    (throw (ex-info "Client not authorized for client_credentials grant"
                    {:client-id (:client-id client)})))
  (when-not (or (= (:client-type client) "confidential")
                (and (nil? (:client-type client))
                     (:client-secret-hash client)))
    (throw (ex-info "client_credentials grant requires a confidential client"
                    {:client-id (:client-id client)})))
  (let [requested-scope (if scope (vec (str/split scope #" ")) [])
        client-scope    (:scopes client)
        final-scope     (if (empty? requested-scope)
                          client-scope
                          requested-scope)]
    (when-not (every? (set client-scope) final-scope)
      (throw (ex-info "Invalid scope for client"
                      {:requested final-scope
                       :allowed   client-scope})))
    (let [access-token (token/generate-access-token)
          ttl          (or (:access-token-ttl-seconds provider-config) 3600)
          expiry       (+ (.millis ^java.time.Clock (:clock provider-config)) (* 1000 ttl))]
      (proto/save-access-token token-store access-token (:client-id client)
                               (:client-id client) final-scope expiry resource)
      (cond-> {:access_token access-token
               :token_type   "Bearer"
               :expires_in   ttl
               :scope        (str/join " " final-scope)}
        resource (assoc :resource resource)))))

(defn handle-token-request
  "Handles token endpoint requests.

  Takes the parsed `params` map (as produced by Ring's `wrap-params` and
  `wrap-keyword-params` middleware), the `authorization-header` for client
  authentication, and the usual provider stores. Multi-value `resource`
  parameters (RFC 8707) should already be present in `params` as a string or
  vector — Ring's `wrap-params` handles this automatically for repeated form
  fields. Validates the request, authenticates the client, and dispatches to
  the appropriate grant handler. Returns a token response map. Throws `ex-info`
  on validation or processing errors."
  [params authorization-header provider-config client-store code-store token-store claims-provider]
  (when-not (m/validate TokenRequest params)
    (throw (ex-info "Invalid token request"
                    {:errors (m/explain TokenRequest params)})))
  (let [resources             (normalize-resource (:resource params))
        _                     (when resources (proto/validate-resource-indicators resources))
        params                (cond-> params resources (assoc :resource resources))
        grant-types-supported (or (:grant-types-supported provider-config)
                                  default-grant-types-supported)
        _                     (when-not (some #{(:grant_type params)} grant-types-supported)
                                (throw (ex-info "Unsupported grant type"
                                                {:error "unsupported_grant_type"})))
        client                (authenticate-client params authorization-header client-store)
        response              (case (:grant_type params)
                                "authorization_code"
                                (handle-authorization-code-grant params client provider-config
                                                                 code-store token-store claims-provider)

                                "refresh_token"
                                (handle-refresh-token-grant params client provider-config token-store)

                                "client_credentials"
                                (handle-client-credentials-grant params client provider-config token-store)

                                (throw (ex-info "Unimplemented grant type"
                                                {:error      "unsupported_grant_type"
                                                 :grant-type (:grant_type params)})))]
    (when-not (m/validate TokenResponse response)
      (throw (ex-info "Invalid token response generated"
                      {:errors (m/explain TokenResponse response)})))
    response))

(def ^:private no-cache-headers
  {"Content-Type"  "application/json"
   "Cache-Control" "no-store"
   "Pragma"        "no-cache"})

(defn token-error-response
  "Creates an OAuth2 error response with cache-control headers per RFC 6749 §5.1.

  Takes an `error` code string, an `error-description` string, and an optional
  `:status` (defaults to 400). Returns a Ring response map with JSON body and
  `Cache-Control: no-store` / `Pragma: no-cache` headers."
  [error error-description & {:keys [status] :or {status 400}}]
  {:status  status
   :headers no-cache-headers
   :body    (json/generate-string
             (cond-> {:error error}
               error-description (assoc :error_description error-description)))})

(defn token-success-response
  "Wraps a token response map as a Ring response with cache-control headers per RFC 6749 §5.1.

  Takes a `token-map` (e.g. the result of [[handle-token-request]]) and returns
  a Ring response with status 200, JSON body, and `Cache-Control: no-store` /
  `Pragma: no-cache` headers."
  [token-map]
  {:status  200
   :headers no-cache-headers
   :body    (json/generate-string token-map)})
