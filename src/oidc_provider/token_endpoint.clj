(ns oidc-provider.token-endpoint
  "Token endpoint implementation for OAuth2/OIDC."
  (:require
   [cheshire.core :as json]
   [clojure.string :as str]
   [malli.core :as m]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token :as token])
  (:import
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
   [:scope {:optional true} :string]])

(def TokenResponse
  "Malli schema for token response."
  [:map
   [:access_token :string]
   [:token_type [:enum "Bearer"]]
   [:expires_in pos-int?]
   [:id_token {:optional true} :string]
   [:refresh_token {:optional true} :string]
   [:scope {:optional true} :string]])

(defn- parse-basic-auth
  [authorization-header]
  (when (and authorization-header (str/starts-with? authorization-header "Basic "))
    (let [encoded                   (subs authorization-header 6)
          decoded                   (String. (.decode (Base64/getDecoder) encoded))
          [client-id client-secret] (str/split decoded #":" 2)]
      {:client-id client-id
       :client-secret client-secret})))

(defn- authenticate-client
  [params authorization-header client-store]
  (let [basic-auth    (parse-basic-auth authorization-header)
        client-id     (or (:client-id basic-auth) (:client_id params))
        client-secret (or (:client-secret basic-auth) (:client_secret params))]
    (when-not client-id
      (throw (ex-info "Missing client_id" {})))
    (let [client (proto/get-client client-store client-id)]
      (when-not client
        (throw (ex-info "Unknown client" {:client-id client-id})))
      (when (and (:client-secret client)
                 (not= (:client-secret client) client-secret))
        (throw (ex-info "Invalid client credentials" {:client-id client-id})))
      client)))

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
  [{:keys [code redirect_uri]} client provider-config code-store token-store claims-provider]
  (when-not code
    (throw (ex-info "Missing code parameter" {})))
  (let [code-data (proto/get-authorization-code code-store code)]
    (when-not code-data
      (throw (ex-info "Invalid or expired authorization code" {:code code})))
    (proto/delete-authorization-code code-store code)
    (when (> (System/currentTimeMillis) (:expiry code-data))
      (throw (ex-info "Authorization code expired" {:code code})))
    (when (not= (:client-id code-data) (:client-id client))
      (throw (ex-info "Client mismatch" {:expected (:client-id code-data)
                                         :actual (:client-id client)})))
    (when (and redirect_uri (not= (:redirect-uri code-data) redirect_uri))
      (throw (ex-info "Redirect URI mismatch" {:expected (:redirect-uri code-data)
                                               :actual redirect_uri})))
    (let [user-id       (:user-id code-data)
          scope         (:scope code-data)
          access-token  (token/generate-access-token)
          refresh-token (token/generate-refresh-token)
          ttl           (or (:access-token-ttl-seconds provider-config) 3600)
          expiry        (+ (System/currentTimeMillis) (* 1000 ttl))
          user-claims   (proto/get-claims claims-provider user-id scope)
          id-token      (token/generate-id-token
                         provider-config
                         user-id
                         (:client-id client)
                         user-claims
                         {:nonce (:nonce code-data)})]
      (proto/save-access-token token-store access-token user-id (:client-id client) scope expiry)
      (proto/save-refresh-token token-store refresh-token user-id (:client-id client) scope)
      {:access_token access-token
       :token_type "Bearer"
       :expires_in ttl
       :id_token id-token
       :refresh_token refresh-token
       :scope (str/join " " scope)})))

(defn handle-refresh-token-grant
  "Handles refresh_token grant type.

  Args:
    params: Token request parameters
    client: Authenticated client configuration
    provider-config: Provider configuration map
    token-store: TokenStore implementation

  Returns:
    Token response map"
  [{:keys [refresh_token scope]} client provider-config token-store]
  (when-not refresh_token
    (throw (ex-info "Missing refresh_token parameter" {})))
  (let [token-data (proto/get-refresh-token token-store refresh_token)]
    (when-not token-data
      (throw (ex-info "Invalid refresh token" {:refresh-token refresh_token})))
    (when (not= (:client-id token-data) (:client-id client))
      (throw (ex-info "Client mismatch" {:expected (:client-id token-data)
                                         :actual (:client-id client)})))
    (let [requested-scope (when scope (vec (str/split scope #" ")))
          token-scope     (:scope token-data)
          final-scope     (or requested-scope token-scope)]
      (when (and requested-scope
                 (not (every? (set token-scope) requested-scope)))
        (throw (ex-info "Requested scope exceeds original scope"
                        {:original token-scope
                         :requested requested-scope})))
      (let [access-token (token/generate-access-token)
            ttl          (or (:access-token-ttl-seconds provider-config) 3600)
            expiry       (+ (System/currentTimeMillis) (* 1000 ttl))]
        (proto/save-access-token token-store access-token (:user-id token-data)
                                 (:client-id client) final-scope expiry)
        {:access_token access-token
         :token_type "Bearer"
         :expires_in ttl
         :scope (str/join " " final-scope)}))))

(defn handle-client-credentials-grant
  "Handles client_credentials grant type.

  Args:
    params: Token request parameters
    client: Authenticated client configuration
    provider-config: Provider configuration map
    token-store: TokenStore implementation

  Returns:
    Token response map"
  [{:keys [scope]} client provider-config token-store]
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
                       :allowed client-scope})))
    (let [access-token (token/generate-access-token)
          ttl          (or (:access-token-ttl-seconds provider-config) 3600)
          expiry       (+ (System/currentTimeMillis) (* 1000 ttl))]
      (proto/save-access-token token-store access-token (:client-id client)
                               (:client-id client) final-scope expiry)
      {:access_token access-token
       :token_type "Bearer"
       :expires_in ttl
       :scope (str/join " " final-scope)})))

(defn handle-token-request
  "Handles token endpoint requests.

  Args:
    params: Token request parameters (from form body)
    authorization-header: Authorization header value (for client authentication)
    provider-config: Provider configuration map
    client-store: ClientStore implementation
    code-store: AuthorizationCodeStore implementation
    token-store: TokenStore implementation
    claims-provider: ClaimsProvider implementation

  Returns:
    Token response map

  Throws:
    ex-info on validation or processing errors"
  [params authorization-header provider-config client-store code-store token-store claims-provider]
  (when-not (m/validate TokenRequest params)
    (throw (ex-info "Invalid token request"
                    {:errors (m/explain TokenRequest params)})))
  (let [client   (authenticate-client params authorization-header client-store)
        response (case (:grant_type params)
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

(defn token-error-response
  "Creates an OAuth2 error response.

  Args:
    error: Error code (e.g., \"invalid_request\", \"invalid_client\")
    error-description: Human-readable error description
    status: HTTP status code (default 400)

  Returns:
    Map with :status, :headers, and :body"
  [error error-description & {:keys [status] :or {status 400}}]
  {:status status
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string
          (cond-> {:error error}
            error-description (assoc :error_description error-description)))})
