(ns oidc-provider.revocation
  "RFC 7009 token revocation endpoint.

  Provides [[handle-revocation-request]] for revoking access and refresh tokens.
  The endpoint always returns 200 on successful authentication, even for unknown
  tokens, to prevent token-scanning attacks per RFC 7009 §2.2."
  (:require
   [oidc-provider.error :as error]
   [oidc-provider.protocol :as proto]
   [oidc-provider.token-endpoint :as token-ep]))

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
  `token-store`. Returns `:ok` on success (including for unknown tokens per
  RFC 7009 §2.2). Throws `ex-info` with `\"invalid_request\"` when the `token`
  parameter is missing, or lets authentication exceptions propagate on
  credential failure."
  [params authorization-header client-store token-store]
  (let [client (token-ep/authenticate-client params authorization-header client-store)]
    (when-not (:token params)
      (throw (ex-info "invalid_request" {:type              ::error/invalid-request
                                         :error_description "Missing token parameter"})))
    (let [token      (:token params)
          token-data (lookup-token token-store token (:token_type_hint params))]
      (when (and token-data (= (:client-id token-data) (:client-id client)))
        (proto/revoke-token token-store token))
      :ok)))
