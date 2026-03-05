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
    {:sub   user-id
     :email "test@example.com"
     :name  "Test User"}))

(deftest authenticate-client-wrong-secret-test
  (testing "rejects wrong client secret"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}]
      (is (thrown-with-msg? Exception #"Invalid client credentials"
                            (token-ep/handle-token-request
                             {:grant_type    "authorization_code"
                              :client_id     "test-client"
                              :client_secret "wrong-secret"
                              :code          "some-code"}
                             nil
                             provider-config
                             client-store
                             code-store
                             token-store
                             claims-provider))))))

(deftest authenticate-client-missing-secret-test
  (testing "rejects missing client secret when required"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}]
      (is (thrown-with-msg? Exception #"Invalid client credentials"
                            (token-ep/handle-token-request
                             {:grant_type "authorization_code"
                              :client_id  "test-client"
                              :code       "some-code"}
                             nil
                             provider-config
                             client-store
                             code-store
                             token-store
                             claims-provider))))))

(deftest handle-authorization-code-grant-test
  (testing "exchanges authorization code for tokens stored with correct metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile" "email"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600
                           :id-token-ttl-seconds     3600}
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code         code
                         :redirect_uri "https://app.example.com/callback"}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))
            id-claims  (token/validate-id-token provider-config (:id_token response) "test-client")]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (= "user-123" (:user-id token-data)))
        (is (= "test-client" (:client-id token-data)))
        (is (= "user-123" (:sub id-claims)))
        (is (= "nonce123" (:nonce id-claims)))))))

(deftest handle-authorization-code-grant-expired-test
  (testing "throws on expired authorization code"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (- (System/currentTimeMillis) 1000)]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry)
      (is (thrown-with-msg? Exception #"expired"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest redirect-uri-missing-enforcement-test
  (testing "throws when redirect_uri is missing but was in authorization request"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry)
      (is (thrown-with-msg? Exception #"Missing redirect_uri"
                            (token-ep/handle-authorization-code-grant
                             {:code code}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest redirect-uri-mismatch-enforcement-test
  (testing "throws when redirect_uri does not match"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry)
      (is (thrown-with-msg? Exception #"Redirect URI mismatch"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://evil.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest handle-refresh-token-grant-test
  (testing "refreshes access token with correct stored metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client" ["openid" "profile"])
      (let [response   (token-ep/handle-refresh-token-grant
                        {:refresh_token refresh-token}
                        (proto/get-client client-store "test-client")
                        provider-config
                        token-store)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (= "user-123" (:user-id token-data)))
        (is (= "test-client" (:client-id token-data)))))))

(deftest grant-type-authorization-code-rejected-test
  (testing "authorization_code rejected for client without grant type"
    (let [client-store    (store/create-client-store
                           [{:client-id      "cc-only-client"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "cc-only-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry)
      (is (thrown-with-msg? Exception #"Client not authorized for authorization_code"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "cc-only-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest grant-type-refresh-token-rejected-test
  (testing "refresh_token rejected for client without grant type"
    (let [client-store    (store/create-client-store
                           [{:client-id      "authcode-only-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "authcode-only-client" ["openid"])
      (is (thrown-with-msg? Exception #"Client not authorized for refresh_token"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token}
                             (proto/get-client client-store "authcode-only-client")
                             provider-config
                             token-store))))))

(deftest handle-client-credentials-grant-test
  (testing "issues token with correct stored metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["api:read" "api:write"]}])
          token-store     (store/create-token-store)
          provider-config {:issuer                   "https://test.example.com"
                           :signing-key              (token/generate-rsa-key)
                           :access-token-ttl-seconds 3600}
          response        (token-ep/handle-client-credentials-grant
                           {:scope "api:read"}
                           (proto/get-client client-store "test-client")
                           provider-config
                           token-store)
          token-data      (proto/get-access-token token-store (:access_token response))]
      (is (= {:token_type "Bearer" :expires_in 3600 :scope "api:read"}
             (select-keys response [:token_type :expires_in :scope])))
      (is (= "test-client" (:client-id token-data)))
      (is (= ["api:read"] (:scope token-data))))))
