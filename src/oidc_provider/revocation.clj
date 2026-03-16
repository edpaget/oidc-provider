(ns oidc-provider.revocation
  "RFC 7009 token revocation endpoint.

  Provides [[handle-revocation-request]] for revoking access and refresh tokens.
  The endpoint always returns 200 on successful authentication, even for unknown
  tokens, to prevent token-scanning attacks per RFC 7009 §2.2."
  (:require
   [oidc-provider.protocol :as proto]
   [oidc-provider.token-endpoint :as token-ep]))

(set! *warn-on-reflection* true)

(def RevocationRequest
  "Malli schema for an RFC 7009 token revocation request."
  [:map
   [:token :string]
   [:token_type_hint {:optional true} [:enum "access_token" "refresh_token"]]])

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
        (token-ep/token-error-response "invalid_request" "Missing token parameter")
        (let [token      (:token params)
              token-data (or (proto/get-access-token token-store token)
                             (proto/get-refresh-token token-store token))]
          (when (and token-data (= (:client-id token-data) (:client-id client)))
            (proto/revoke-token token-store token))
          {:status 200})))
    (catch clojure.lang.ExceptionInfo _
      (token-ep/token-error-response "invalid_client" nil :status 401))))
