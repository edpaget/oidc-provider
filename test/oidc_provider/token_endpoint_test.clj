(ns oidc-provider.token-endpoint-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [oidc-provider.protocol :as proto]
   [oidc-provider.store :as store]
   [oidc-provider.token :as token]
   [oidc-provider.token-endpoint :as token-ep]
   [oidc-provider.util :as util])
  (:import
   [com.nimbusds.jose.jwk RSAKey]
   [com.nimbusds.oauth2.sdk.pkce CodeChallenge CodeChallengeMethod CodeVerifier]
   [java.time Clock Instant ZoneOffset]))

(defn- make-provider-config [overrides]
  (let [key (token/generate-rsa-key)]
    (merge {:issuer                   "https://test.example.com"
            :key-set                  (token/normalize-to-jwk-set key)
            :active-signing-key-id    (.getKeyID ^RSAKey key)
            :access-token-ttl-seconds 3600
            :clock                    (Clock/systemUTC)}
           overrides)))

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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})]
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})]
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile" "email"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil nil)
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

(deftest authorization-code-grant-no-openid-scope-test
  (testing "omits id_token when openid is not in scope"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["profile" "email"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["profile"] nil expiry nil nil nil)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code         code
                         :redirect_uri "https://app.example.com/callback"}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= nil (:id_token response)))
        (is (= "user-123" (:user-id token-data)))
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "profile"}
               (select-keys response [:token_type :expires_in :scope])))))))

(deftest handle-authorization-code-grant-expired-test
  (testing "throws on expired authorization code"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (- (System/currentTimeMillis) 1000)]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
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
  (testing "refreshes access token with correct stored metadata and rotates refresh token"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client" ["openid" "profile"] nil nil)
      (let [response   (token-ep/handle-refresh-token-grant
                        {:refresh_token refresh-token}
                        (proto/get-client client-store "test-client")
                        provider-config
                        token-store)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (string? (:refresh_token response)))
        (is (= "user-123" (:user-id token-data)))
        (is (= "test-client" (:client-id token-data)))))))

(deftest grant-type-authorization-code-rejected-test
  (testing "authorization_code rejected for client without grant type"
    (let [client-store    (store/create-client-store
                           [{:client-id      "cc-only-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "cc-only-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "authcode-only-client" ["openid"] nil nil)
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
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["api:read" "api:write"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {})
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

(deftest authorization-code-grant-pkce-success-test
  (testing "exchanges code with valid PKCE verifier"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          verifier-str    (.getValue verifier)
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry challenge "S256" nil)
      (let [response   (token-ep/handle-authorization-code-grant
                        {:code          code
                         :redirect_uri  "https://app.example.com/callback"
                         :code_verifier verifier-str}
                        (proto/get-client client-store "test-client")
                        provider-config
                        code-store
                        token-store
                        claims-provider)
            token-data (proto/get-access-token token-store (:access_token response))]
        (is (= {:token_type "Bearer" :expires_in 3600 :scope "openid profile"}
               (select-keys response [:token_type :expires_in :scope])))
        (is (= "user-123" (:user-id token-data)))))))

(deftest authorization-code-grant-pkce-wrong-verifier-test
  (testing "rejects wrong PKCE verifier"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          wrong-verifier  (.getValue (CodeVerifier.))
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry challenge "S256" nil)
      (is (thrown-with-msg? Exception #"PKCE verification failed"
                            (token-ep/handle-authorization-code-grant
                             {:code          code
                              :redirect_uri  "https://app.example.com/callback"
                              :code_verifier wrong-verifier}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-pkce-missing-verifier-test
  (testing "rejects missing verifier when challenge was stored"
    (let [verifier        (CodeVerifier.)
          challenge       (.getValue (CodeChallenge/compute CodeChallengeMethod/S256 verifier))
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry challenge "S256" nil)
      (is (thrown-with-msg? Exception #"Missing code_verifier"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://app.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-pkce-unexpected-verifier-test
  (testing "rejects verifier when no challenge was stored"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Unexpected code_verifier"
                            (token-ep/handle-authorization-code-grant
                             {:code          code
                              :redirect_uri  "https://app.example.com/callback"
                              :code_verifier "some-verifier"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider))))))

(deftest authorization-code-grant-passes-resource-to-tokens-test
  (testing "resource from auth code round-trips to tokens and response"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))
          resources       ["https://api.example.com" "https://data.example.com"]]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil resources)
      (let [response    (token-ep/handle-authorization-code-grant
                         {:code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (proto/get-client client-store "test-client")
                         provider-config
                         code-store
                         token-store
                         claims-provider)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= resources (:resource response)))
        (is (= resources (:resource access-data)))
        (is (nil? (:refresh_token response)))))))

(deftest authorization-code-grant-no-resource-test
  (testing "no resource in auth code means no resource in tokens or response"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["profile"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["profile"] nil expiry nil nil nil)
      (let [response    (token-ep/handle-authorization-code-grant
                         {:code         code
                          :redirect_uri "https://app.example.com/callback"}
                         (proto/get-client client-store "test-client")
                         provider-config
                         code-store
                         token-store
                         claims-provider)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (nil? (:resource response)))
        (is (nil? (:resource access-data)))))))

(deftest refresh-token-grant-narrows-resource-test
  (testing "requesting a subset of original resources succeeds"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid" "profile"] nil
                                ["https://api.example.com" "https://data.example.com"])
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token refresh-token
                          :resource      ["https://api.example.com"]}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= ["https://api.example.com"] (:resource response)))
        (is (= ["https://api.example.com"] (:resource access-data)))
        (is (string? (:refresh_token response)))))))

(deftest refresh-token-grant-rejects-expanded-resource-test
  (testing "requesting a resource not in original set throws invalid_target"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil
                                ["https://api.example.com"])
      (is (thrown-with-msg? Exception #"Requested resource exceeds original grant"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token
                              :resource      ["https://evil.example.com"]}
                             (proto/get-client client-store "test-client")
                             provider-config
                             token-store))))))

(deftest refresh-token-grant-preserves-resource-test
  (testing "no resource param on refresh preserves original resources"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil
                                ["https://api.example.com"])
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token refresh-token}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            access-data (proto/get-access-token token-store (:access_token response))]
        (is (= ["https://api.example.com"] (:resource response)))
        (is (= ["https://api.example.com"] (:resource access-data)))
        (is (string? (:refresh_token response)))))))

(deftest client-credentials-grant-with-resource-test
  (testing "resource is stored and returned in response"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["api:read"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {})
          response        (token-ep/handle-client-credentials-grant
                           {:scope    "api:read"
                            :resource ["https://api.example.com"]}
                           (proto/get-client client-store "test-client")
                           provider-config
                           token-store)
          access-data     (proto/get-access-token token-store (:access_token response))]
      (is (= ["https://api.example.com"] (:resource response)))
      (is (= ["https://api.example.com"] (:resource access-data))))))

(deftest handle-token-request-multi-value-resource-test
  (testing "vector resource param produces a vector in the response"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["api:read"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          response        (token-ep/handle-token-request
                           {:grant_type    "client_credentials"
                            :client_id     "test-client"
                            :client_secret "secret123"
                            :scope         "api:read"
                            :resource      ["https://api.example.com" "https://data.example.com"]}
                           nil
                           provider-config
                           client-store
                           code-store
                           token-store
                           claims-provider)
          access-data     (proto/get-access-token token-store (:access_token response))]
      (is (= ["https://api.example.com" "https://data.example.com"] (:resource response)))
      (is (= ["https://api.example.com" "https://data.example.com"] (:resource access-data))))))

(deftest authenticate-client-hashed-secret-test
  (testing "authenticates with correct secret against hashed store"
    (let [secret          "my-secret"
          hashed          (util/hash-client-secret secret)
          client-store    (store/create-client-store
                           [{:client-id          "hashed-client"
                             :client-type        "confidential"
                             :client-secret-hash hashed
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["client_credentials"]
                             :response-types     []
                             :scopes             ["api:read"]}])
          token-store     (store/create-token-store)
          code-store      (store/create-authorization-code-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          response        (token-ep/handle-token-request
                           {:grant_type    "client_credentials"
                            :client_id     "hashed-client"
                            :client_secret secret
                            :scope         "api:read"}
                           nil
                           provider-config client-store code-store token-store claims-provider)]
      (is (= "Bearer" (:token_type response)))
      (is (= "api:read" (:scope response))))))

(deftest authenticate-client-hashed-secret-wrong-test
  (testing "rejects wrong secret against hashed store"
    (let [hashed          (util/hash-client-secret "correct-secret")
          client-store    (store/create-client-store
                           [{:client-id          "hashed-client"
                             :client-type        "confidential"
                             :client-secret-hash hashed
                             :redirect-uris      ["https://app.example.com/callback"]
                             :grant-types        ["client_credentials"]
                             :response-types     []
                             :scopes             ["api:read"]}])
          token-store     (store/create-token-store)
          code-store      (store/create-authorization-code-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})]
      (is (thrown-with-msg? Exception #"Invalid client credentials"
                            (token-ep/handle-token-request
                             {:grant_type    "client_credentials"
                              :client_id     "hashed-client"
                              :client_secret "wrong-secret"
                              :scope         "api:read"}
                             nil
                             provider-config client-store code-store token-store claims-provider))))))

(deftest confidential-client-no-credentials-test
  (testing "rejects confidential client with no stored secret or hash"
    (let [client-store    (store/create-client-store
                           [{:client-id      "misconfigured"
                             :client-type    "confidential"
                             :redirect-uris  []
                             :grant-types    ["client_credentials"]
                             :response-types []
                             :scopes         ["api:read"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})]
      (is (thrown-with-msg? Exception #"Confidential client has no stored credentials"
                            (token-ep/handle-token-request
                             {:grant_type    "client_credentials"
                              :client_id     "misconfigured"
                              :client_secret "any-secret"
                              :scope         "api:read"}
                             nil
                             provider-config client-store code-store token-store claims-provider))))))

(deftest refresh-token-expired-rejection-test
  (testing "rejects an expired refresh token"
    (let [past-instant    (-> (Instant/now) (.minusSeconds 3600))
          fixed-clock     (Clock/fixed past-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {})
          refresh-token   (token/generate-refresh-token)
          past-expiry     (.millis fixed-clock)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] past-expiry nil)
      (is (thrown-with-msg? Exception #"Refresh token expired"
                            (token-ep/handle-refresh-token-grant
                             {:refresh_token refresh-token}
                             (proto/get-client client-store "test-client")
                             provider-config
                             token-store))))))

(deftest refresh-token-valid-before-expiry-test
  (testing "accepts a refresh token that has not yet expired"
    (let [future-instant  (-> (Instant/now) (.plusSeconds 3600))
          future-clock    (Clock/fixed future-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          refresh-token   (token/generate-refresh-token)
          future-expiry   (.millis future-clock)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid" "profile"] future-expiry nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token refresh-token}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)]
        (is (= "Bearer" (:token_type response)))
        (is (= "openid profile" (:scope response)))
        (is (string? (:refresh_token response)))))))

(deftest refresh-token-rotation-revokes-old-token-test
  (testing "old refresh token is revoked and new one has correct metadata"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens true})
          old-refresh     (token/generate-refresh-token)]
      (proto/save-refresh-token token-store old-refresh "user-123" "test-client"
                                ["openid" "profile"] nil nil)
      (let [response    (token-ep/handle-refresh-token-grant
                         {:refresh_token old-refresh}
                         (proto/get-client client-store "test-client")
                         provider-config
                         token-store)
            new-refresh (:refresh_token response)
            old-data    (proto/get-refresh-token token-store old-refresh)
            new-data    (proto/get-refresh-token token-store new-refresh)]
        (is (nil? old-data))
        (is (= "user-123" (:user-id new-data)))
        (is (= "test-client" (:client-id new-data)))
        (is (= ["openid" "profile"] (:scope new-data)))))))

(deftest refresh-token-rotation-disabled-test
  (testing "with rotation disabled, no new refresh token is issued and old remains valid"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:rotate-refresh-tokens false})
          refresh-token   (token/generate-refresh-token)]
      (proto/save-refresh-token token-store refresh-token "user-123" "test-client"
                                ["openid"] nil nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token refresh-token}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)
            old-data (proto/get-refresh-token token-store refresh-token)]
        (is (nil? (:refresh_token response)))
        (is (= "user-123" (:user-id old-data)))))))

(deftest refresh-token-rotation-preserves-expiry-test
  (testing "rotated token gets a fresh expiry based on TTL, not the old expiry"
    (let [now-instant     (Instant/parse "2026-01-01T00:00:00Z")
          fixed-clock     (Clock/fixed now-instant ZoneOffset/UTC)
          client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          token-store     (store/create-token-store)
          provider-config (make-provider-config {:refresh-token-ttl-seconds 86400
                                                 :rotate-refresh-tokens     true
                                                 :clock                     fixed-clock})
          old-refresh     (token/generate-refresh-token)
          old-expiry      (+ (.millis fixed-clock) (* 1000 1800))]
      (proto/save-refresh-token token-store old-refresh "user-123" "test-client"
                                ["openid"] old-expiry nil)
      (let [response (token-ep/handle-refresh-token-grant
                      {:refresh_token old-refresh}
                      (proto/get-client client-store "test-client")
                      provider-config
                      token-store)
            new-data (proto/get-refresh-token token-store (:refresh_token response))
            expected (+ (.millis fixed-clock) (* 1000 86400))]
        (is (= expected (:expiry new-data)))))))

(deftest code-not-consumed-on-validation-failure-test
  (testing "authorization code remains in store after failed exchange"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (is (thrown-with-msg? Exception #"Redirect URI mismatch"
                            (token-ep/handle-authorization-code-grant
                             {:code         code
                              :redirect_uri "https://evil.example.com/callback"}
                             (proto/get-client client-store "test-client")
                             provider-config
                             code-store
                             token-store
                             claims-provider)))
      (is (some? (proto/get-authorization-code code-store code))))))

(deftest code-consumed-on-successful-exchange-test
  (testing "authorization code is deleted from store after successful exchange"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code"]
                             :response-types ["code"]
                             :scopes         ["openid"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid"] nil expiry nil nil nil)
      (token-ep/handle-authorization-code-grant
       {:code         code
        :redirect_uri "https://app.example.com/callback"}
       (proto/get-client client-store "test-client")
       provider-config
       code-store
       token-store
       claims-provider)
      (is (nil? (proto/get-authorization-code code-store code))))))

(deftest authorization-code-grant-with-refresh-token-grant-type-test
  (testing "client with refresh_token grant type receives a refresh token"
    (let [client-store    (store/create-client-store
                           [{:client-id      "test-client"
                             :client-type    "confidential"
                             :client-secret  "secret123"
                             :redirect-uris  ["https://app.example.com/callback"]
                             :grant-types    ["authorization_code" "refresh_token"]
                             :response-types ["code"]
                             :scopes         ["openid" "profile"]}])
          code-store      (store/create-authorization-code-store)
          token-store     (store/create-token-store)
          claims-provider (->TestClaimsProvider)
          provider-config (make-provider-config {:id-token-ttl-seconds 3600})
          code            (token/generate-authorization-code)
          expiry          (+ (System/currentTimeMillis) (* 1000 600))]
      (proto/save-authorization-code code-store code "user-123" "test-client"
                                     "https://app.example.com/callback"
                                     ["openid" "profile"] "nonce123" expiry nil nil nil)
      (let [response     (token-ep/handle-authorization-code-grant
                          {:code         code
                           :redirect_uri "https://app.example.com/callback"}
                          (proto/get-client client-store "test-client")
                          provider-config
                          code-store
                          token-store
                          claims-provider)
            refresh-data (proto/get-refresh-token token-store (:refresh_token response))]
        (is (string? (:refresh_token response)))
        (is (= "user-123" (:user-id refresh-data)))
        (is (= "test-client" (:client-id refresh-data)))))))
