(ns oidc-provider.token-endpoint-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep]))

(defrecord TestClaimsProvider []
  proto/ClaimsProvider
  (get-claims [_ user-id _scope]
    {:sub user-id
     :email "test@example.com"
     :name "Test User"}))

(deftest handle-authorization-code-grant-test
  (testing "exchanges authorization code for tokens"
    (let [client-store    (store/create-client-store
                           [{:client-id "test-client"
                             :client-secret "secret123"
                             :redirect-uris ["https://app.example.com/callback"]
                             :grant-types ["authorization_code"]
                             :response-types ["code"]
                             :scopes ["openid" "profile" "email"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer "https://test.example.com"
                           :signing-key (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600
                           :id-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry)
      (let [response (token-ep/handle-authorization-code-grant
                      {:code code
                       :redirect_uri "https://app.example.com/callback"}
                      (proto/get-client client-store "test-client")
                      provider-config
                      code-store
                      token-store
                      claims-provider)]
        (is (some? (:access_token response)))
        (is (= "Bearer" (:token_type response)))
        (is (= 3600 (:expires_in response)))
        (is (some? (:id_token response)))
        (is (some? (:refresh_token response)))
        (is (= "openid profile" (:scope response))))))

  (testing "throws on expired authorization code"
    (let [client-store    (store/create-client-store
                           [{:client-id "test-client"
                             :client-secret "secret123"
                             :redirect-uris ["https://app.example.com/callback"]
                             :grant-types ["authorization_code"]
                             :response-types ["code"]
                             :scopes ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer "https://test.example.com"
                           :signing-key (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (- (System/currentTimeMillis) 1000)]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry)
      (is (thrown-with-msg? Exception #"expired"
                            (token-ep/handle-authorization-code-grant
                             {:code code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest handle-refresh-token-grant-test
  (testing "refreshes access token"
    (let [client-store    (store/create-client-store
                           [{:client-id "test-client"
                             :client-secret "secret123"
                             :redirect-uris ["https://app.example.com/callback"]
                             :grant-types ["refresh_token"]
                             :response-types ["code"]
                             :scopes ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config {:issuer "https://test.example.com"
                           :signing-key (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client" ["openid" "profile"])
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token refresh-token}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)]
        (is (some? (:access_token response)))
        (is (= "Bearer" (:token_type response)))
        (is (= 3600 (:expires_in response)))
        (is (= "openid profile" (:scope response)))))))

(deftest handle-client-credentials-grant-test
  (testing "issues token for client credentials"
    (let [client-store    (store/create-client-store
                           [{:client-id "test-client"
                             :client-secret "secret123"
                             :redirect-uris []
                             :grant-types ["client_credentials"]
                             :response-types []
                             :scopes ["api:read" "api:write"]}])
          token-store     (store/create-token-store)
          provider-config {:issuer "https://test.example.com"
                           :signing-key (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          response        (token-ep/handle-client-credentials-grant
                           {:scope "api:read"}
                           (proto/get-client client-store "test-client")
                           provider-config
                           token-store)]
      (is (some? (:access_token response)))
      (is (= "Bearer" (:token_type response)))
      (is (= 3600 (:expires_in response)))
      (is (= "api:read" (:scope response))))))
