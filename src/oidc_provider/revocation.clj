(ns oidc-provider.revocation
  "RFC 7009 token revocation endpoint.

  Provides [[handle-revocation-request]] for revoking access and refresh tokens.
  The endpoint always returns 200 on successful authentication, even for unknown
  tokens, to prevent token-scanning attacks per RFC 7009 §2.2."
  (:require
   [oidc-provider.protocol :as proto]
   [oidc-provider.token-endpoint :as token-ep]))

(def ^:private no-cache-headers
  {"Content-Type"  "application/json"
   "Cache-Control" "no-store"
   "Pragma"        "no-cache"})

(def ^:private auth-failure-headers
  (assoc no-cache-headers "WWW-Authenticate" "Bearer"))

(set! *warn-on-reflection* true)

(def RevocationRequest
  "Malli schema for an RFC 7009 token revocation request."
  [:map
   [:token :string]
   [:token_type_hint {:optional true} [:enum "access_token" "refresh_token"]]])

(defn- lookup-token
  "Looks up a token in the store, using `hint` to optimize lookup order per
  RFC 7009 §2.1. When hint is `\"refresh_token\"`, checks refresh tokens first;
  otherwise checks access tokens first. Always falls back to the other store."
  [token-store token hint]
  (if (= hint "refresh_token")
    (or (proto/get-refresh-token token-store token)
        (proto/get-access-token token-store token))
    (or (proto/get-access-token token-store token)
        (proto/get-refresh-token token-store token))))

(defn handle-revocation-request
  "Processes an RFC 7009 token revocation request.

  Authenticates the client via [[oidc-provider.token-endpoint/authenticate-client]],
  validates the `token` parameter is present, and revokes the token from
  `token-store`. Returns `{:status 200}` on success (including for unknown
  tokens per RFC 7009 §2.2), `{:status 400}` when the `token` parameter is
  missing, or `{:status 401}` on authentication failure."
  [params authorization-header client-store token-store]
  (try
    (let [client (token-ep/authenticate-client params authorization-header client-store)]
      (if-not (:token params)
        {:status  400
         :headers no-cache-headers
         :body    {:error "invalid_request" :error_description "Missing token parameter"}}
        (let [token      (:token params)
              token-data (lookup-token token-store token (:token_type_hint params))]
          (when (and token-data (= (:client-id token-data) (:client-id client)))
            (proto/revoke-token token-store token))
          {:status 200})))
    (catch clojure.lang.ExceptionInfo _
      {:status  401
       :headers auth-failure-headers
       :body    {:error "invalid_client"}})))
