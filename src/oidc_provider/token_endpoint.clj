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

(defn parse-basic-auth
  "Parses an HTTP Basic Authorization header into client credentials.

  Decodes the Base64-encoded `client_id:client_secret` pair from the header
  value. Returns a map with `:client-id` and `:client-secret` keys, or `nil`
  when the header is absent or not a Basic scheme."
  [authorization-header]
  (when (and authorization-header (str/starts-with? authorization-header "Basic "))
    (let [encoded (subs authorization-header 6)
          decoded (String. (.decode (Base64/getDecoder) encoded))]
      (when (str/includes? decoded ":")
        (let [[client-id client-secret] (str/split decoded #":" 2)]
          {:client-id     (URLDecoder/decode ^String client-id "UTF-8")
           :client-secret (URLDecoder/decode ^String client-secret "UTF-8")})))))

(defn authenticate-client
  "Authenticates an OAuth2 client from request parameters or Basic auth header.

  Resolves the client identity from `params` (`:client_id` / `:client_secret`)
  or the `authorization-header` (HTTP Basic), looks the client up in
  `client-store`, and verifies credentials. Returns the client config map on
  success. Throws `ex-info` on missing, unknown, or mismatched credentials."
  [params authorization-header client-store]
  (let [basic-auth    (parse-basic-auth authorization-header)
        client-id     (or (:client-id basic-auth) (:client_id params))
        client-secret (or (:client-secret basic-auth) (:client_secret params))]
    (when-not client-id
      (throw (ex-info "Missing client_id" {})))
    (let [client (proto/get-client client-store client-id)]
      (when-not client
        (throw (ex-info "Unknown client" {:client-id client-id})))
      (when (and (= (:client-type client) "confidential")
                 (not (:client-secret-hash client))
                 (not (:client-secret client)))
        (throw (ex-info "Confidential client has no stored credentials" {:client-id client-id})))
      (cond
        (:client-secret-hash client)
        (when-not (util/verify-client-secret (or client-secret "") (:client-secret-hash client))
          (throw (ex-info "Invalid client credentials" {:client-id client-id})))

        (:client-secret client)
        (when-not (util/constant-time-eq? (:client-secret client) (or client-secret ""))
          (throw (ex-info "Invalid client credentials" {:client-id client-id}))))
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
  "Handles authorization_code grant type.

  Args:
    params: Token request parameters
    client: Authenticated client configuration
    provider-config: Provider configuration map
    code-store: AuthorizationCodeStore implementation
    token-store: TokenStore implementation
    claims-provider: ClaimsProvider implementation

  Returns:
    Token response map"
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
  "Handles refresh_token grant type.

  Args:
    params: Token request parameters
    client: Authenticated client configuration
    provider-config: Provider configuration map
    token-store: TokenStore implementation

  Returns:
    Token response map"
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
  "Handles client_credentials grant type.

  Args:
    params: Token request parameters
    client: Authenticated client configuration
    provider-config: Provider configuration map
    token-store: TokenStore implementation

  Returns:
    Token response map"
  [{:keys [scope resource]} client provider-config token-store]
  (when-not (some #{"client_credentials"} (:grant-types client))
    (throw (ex-info "Client not authorized for client_credentials grant"
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
  (let [resources (normalize-resource (:resource params))
        _         (when resources (proto/validate-resource-indicators resources))
        params    (cond-> params resources (assoc :resource resources))
        client    (authenticate-client params authorization-header client-store)
        response  (case (:grant_type params)
                    "authorization_code"
                    (handle-authorization-code-grant params client provider-config
                                                     code-store token-store claims-provider)

                    "refresh_token"
                    (handle-refresh-token-grant params client provider-config token-store)

                    "client_credentials"
                    (handle-client-credentials-grant params client provider-config token-store)

                    (throw (ex-info "Unsupported grant_type"
                                    {:grant-type (:grant_type params)})))]
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
